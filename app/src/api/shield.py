import os
import re
import time
import unicodedata
from pathlib import Path
from typing import Optional, Dict, Any
import logging as _logging

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import httpx
import yaml

from llm_guard import scan_prompt, scan_output
from llm_guard.input_scanners import PromptInjection, TokenLimit
from llm_guard.output_scanners import Sensitive

try:
    from llm_guard.output_scanners import Regex as OutputRegex
    HAS_OUTPUT_REGEX = True
except Exception:
    HAS_OUTPUT_REGEX = False

from api.middleware import RequestIdMiddleware, LatencyCSVLogger
from settings import get_settings
from eval.consolidator import log_request

s = get_settings()

# Persist LLM Guard logs to file for post-experiment audit
_LLM_GUARD_LOG_FILE = s.artifacts_dir / "llm_guard.log"
_LLM_GUARD_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

_llm_guard_logger = _logging.getLogger("llm_guard")
_llm_guard_logger.setLevel(_logging.DEBUG)
_fh = _logging.FileHandler(str(_LLM_GUARD_LOG_FILE), encoding="utf-8")
_fh.setFormatter(_logging.Formatter(
    fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))
_llm_guard_logger.addHandler(_fh)

app = FastAPI(title="Shield Proxy API")

app.add_middleware(RequestIdMiddleware)

SCENARIO = os.getenv("SCENARIO", "protected")
DATASET_TAG = os.getenv("DATASET_TAG", s.dataset_tag)

def _resolve_consolidated_csv() -> Path:
    """Return the consolidated CSV path, honouring RUN_KIND isolation.

    - ``RUN_KIND=smoke_test``  → ``artifacts/smoke_test/consolidated_<tag>_<scenario>.csv``
    - ``RUN_KIND=experiment`` (or unset) → ``artifacts/consolidated_<tag>_<scenario>.csv``

    The ``CONSOLIDATED_CSV`` env var can still override the default path for
    experiment runs (backward-compatible with existing tooling).
    """
    _csv_name = f"consolidated_{DATASET_TAG}_{SCENARIO}.csv"
    _run_kind = os.getenv("RUN_KIND", "experiment")
    if _run_kind == "smoke_test":
        return s.artifacts_dir / "smoke_test" / _csv_name
    return Path(os.getenv("CONSOLIDATED_CSV", str(s.artifacts_dir / _csv_name)))

CONSOLIDATED_CSV = _resolve_consolidated_csv()
LATENCY_CSV = str(s.latency_dir / "latency_protected.csv")
app.add_middleware(LatencyCSVLogger, 
    scenario=SCENARIO, 
    domain=DATASET_TAG, 
    csv_path=LATENCY_CSV)

ENABLE_LLM_GUARD = os.getenv("ENABLE_LLM_GUARD", "1") == "1"

RAG_BASE_URL = os.getenv("RAG_BASE_URL", f"http://127.0.0.1:{s.rag_port}")
RAG_GENERATE_URL = f"{RAG_BASE_URL}/generate"
RAG_HEALTH_URL = f"{RAG_BASE_URL}/health"

UPSTREAM_TIMEOUT_S = float(os.getenv("UPSTREAM_TIMEOUT_S", "120"))

# Load LLM Guard configuration from YAML (pre-experiment, no post-hoc bias)
_LLM_GUARD_CONFIG_PATH = s.config_dir / "global" / "llm_guard_config.yaml"

def _load_llm_guard_config() -> dict:
    """Load scanner thresholds from ``llm_guard_config.yaml``, or return ``{}`` if absent."""
    if _LLM_GUARD_CONFIG_PATH.exists():
        with _LLM_GUARD_CONFIG_PATH.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}

_cfg = _load_llm_guard_config()
_input_cfg = _cfg.get("input_scanners", {})
_output_cfg = _cfg.get("output_scanners", {})

class Query(BaseModel):
    """Request body for the Shield ``/generate`` endpoint."""

    prompt: str

_CONTROL_TOKEN_RE = re.compile(r"<\|[a-zA-Z0-9_]+\|>")
 
 
def _sanitize_control_chars(text: str) -> str:
    """
    C2 — Remove control characters and special tokens from prompt input.
 
    Covers:
      - Model special tokens: <|endoftext|>, <|im_start|>, <|fim_prefix|>, etc.
      - Null bytes and C0/C1 Unicode control characters (except \\n, \\t, \\r)
    """
    # Special tokens used by GPT, Llama, and similar tokenizers
    text = _CONTROL_TOKEN_RE.sub("", text)
    # Null bytes
    text = text.replace("\x00", "")
    # Unicode control characters (category Cc), preserving whitespace
    text = "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Cc" or ch in ("\n", "\t", "\r")
    )
    return text.strip()

def guard_input(user_prompt: str) -> tuple[Optional[str], Optional[str], Optional[float]]:
    """Validate and sanitize the input prompt using LLM Guard input scanners.

    Applies controls in order: C2 (control-character sanitization), C1
    (TokenLimit), and C3 (PromptInjection).  Scanners are skipped when
    ``ENABLE_LLM_GUARD`` is False.

    Args:
        user_prompt: Raw user-supplied prompt string.

    Returns:
        A 3-tuple ``(sanitized_prompt, scanner_name, score)``:
          - On pass: ``(sanitized_text, None, last_score)``
          - On block: ``(None, blocking_scanner_name, score)``
    """
    p = user_prompt.strip()
    if not ENABLE_LLM_GUARD:
        return p, None, None

    p = _sanitize_control_chars(p)

    pi_cfg = _input_cfg.get("prompt_injection", {})
    tl_cfg = _input_cfg.get("token_limit", {})

    scanners = []

    if tl_cfg.get("enabled", True):
        scanners.append(
            TokenLimit(
                limit=tl_cfg.get("limit", 512),
                encoding_name=tl_cfg.get("encoding_name", "cl100k_base"),
            )
        )

    if pi_cfg.get("enabled", True):
        scanners.append(
            PromptInjection(
                threshold=pi_cfg.get("threshold", 0.92),
                use_onnx=pi_cfg.get("use_onnx", False),
            )
        )

    last_score = None

    for scanner in scanners:
        sanitized, is_valid_dict, scores = scan_prompt([scanner], p)
        if isinstance(scores, dict):
            last_score = next(iter(scores.values()), None)
        if not all(is_valid_dict.values()):
            _llm_guard_logger.warning(
                "INPUT BLOCKED | scanner=%s | score=%s | prompt_preview=%.120s",
                scanner.__class__.__name__, last_score, p,
            )
            return None, scanner.__class__.__name__, last_score
        p = sanitized
    return p, None, last_score


def guard_output(prompt: str, text: str) -> tuple[str, Optional[str], Optional[float]]:
    """
    Validate the model output using two complementary scanners:
      - Sensitive   → C20 (semantic, score-based; participates in sensitivity analysis)
      - OutputRegex → C19 (deterministic, binary; catches structured PII and
                           [CONFIDENTIAL] marker leaking into responses)
 
    The two scanners are evaluated in sequence. Sensitive runs first because it
    covers cases where PII is paraphrased and lacks a recognizable structure;
    OutputRegex acts as a deterministic safety net for structured PII that may
    fall below the Sensitive threshold.
 
    Returns (sanitized_output, None, score) if allowed.
    Returns (blocked_message, scanner_name, score) if blocked.
    """
    if not ENABLE_LLM_GUARD:
        return text, None, None

    text = _sanitize_control_chars(text)

    sens_cfg = _output_cfg.get("sensitive", {})
    rx_cfg = _output_cfg.get("regex", {})

    scanners = []

    # C20 — semantic scanner (continuous score, participates in sensitivity analysis)
    if sens_cfg.get("enabled", True):
        scanners.append(
            Sensitive(
                threshold=sens_cfg.get("threshold", 0.5),
                redact=sens_cfg.get("redact", False),
                use_onnx=sens_cfg.get("use_onnx", False),
            )
        )
 
    # C19 — deterministic regex scanner (binary match, no continuous score)
    if HAS_OUTPUT_REGEX and rx_cfg.get("enabled", True):
        scanners.append(
            OutputRegex(
                patterns=rx_cfg.get("patterns", []),
                is_blocked=rx_cfg.get("is_blocked", True),
                match_type=rx_cfg.get("match_type", "search"),
            )
        )
 
    p_out      = text
    last_score = None
 
    for scanner in scanners:
        try:
            sanitized, is_valid_dict, scores = scan_output([scanner], prompt, p_out)
            if isinstance(scores, dict):
                last_score = next(iter(scores.values()), None)
            if not all(is_valid_dict.values()):
                _llm_guard_logger.warning(
                    "OUTPUT BLOCKED | scanner=%s | score=%s | prompt_preview=%.120s",
                    scanner.__class__.__name__, last_score, prompt,
                )
                return (
                    f"Output blocked by {scanner.__class__.__name__}.",
                    scanner.__class__.__name__,
                    last_score,
                )
            p_out = sanitized
        except Exception as exc:
            _llm_guard_logger.error(
                "Output scanner error | scanner=%s | error=%s",
                scanner.__class__.__name__, exc,
            )
            continue
 
    return p_out, None, last_score


def _extract_forward_headers(req: Request) -> Dict[str, str]:
    """Build headers to forward to the upstream RAG, preserving the Garak probe tag."""
    h: Dict[str, str] = {}
    rid = req.headers.get("x-request-id")
    if rid:
        h["x-request-id"] = rid

    garak_tag = req.headers.get("x-garak-tag")
    if garak_tag:
        h["x-garak-tag"] = garak_tag

    h["x-forwarded-by"] = "shield"
    return h


@app.post("/generate")
async def generate(query: Query, request: Request):
    """Proxy a prompt through LLM Guard, then forward to the upstream RAG.

    Pipeline:
      1. ``guard_input`` — C1/C2/C3 input scanning.
      2. Forward sanitized prompt to RAG with ``x-forwarded-by: shield`` header.
      3. ``guard_output`` — C19/C20 output scanning.

    All outcomes (blocked or passed) are logged to the consolidated CSV.

    Returns:
        A JSON object ``{"response": <text>}``; blocked responses contain the
        scanner's block message.

    Raises:
        HTTPException: 502 if the upstream RAG is unreachable or returns an error.
    """
    start = time.perf_counter()

    garak_tag = request.headers.get("X-Garak-Tag", "")
    prompt_type = "adversarial" if garak_tag else "legitimate"

    safe_prompt, input_scanner, input_score = guard_input(query.prompt)
    if safe_prompt is None:
        latency_ms = (time.perf_counter() - start) * 1000.0
        out = f"Blocked by {input_scanner}: prompt injection or sensitive pattern detected."
        request.state.response_len = len(out.encode("utf-8"))

        log_request(
            CONSOLIDATED_CSV,
            scenario=SCENARIO,
            domain=DATASET_TAG,
            prompt=query.prompt,
            response=out,
            latency_ms=latency_ms,
            was_blocked=True,
            scanner_triggered=input_scanner,
            block_reason=f"input_{input_scanner.lower()}",
            garak_tag=garak_tag,
            prompt_type=prompt_type,
            input_scanner_score=input_score,
            output_scanner_score=None,
        )
        return {"response": out}

    payload = {"prompt": safe_prompt}
    headers = _extract_forward_headers(request)

    try:
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S) as client:
            resp = await client.post(RAG_GENERATE_URL, json=payload, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream RAG unreachable: {e}")

    if resp.status_code < 200 or resp.status_code >= 300:
        raise HTTPException(
            status_code=502,
            detail=f"Upstream RAG error: {resp.status_code} body={resp.text[:500]}",
        )

    data = resp.json()
    out = str(data.get("response", ""))

    out_guarded, output_scanner, output_score = guard_output(query.prompt, out)
    latency_ms = (time.perf_counter() - start) * 1000.0

    was_blocked = output_scanner is not None
    scanner_triggered = output_scanner if was_blocked else None

    request.state.response_len = len(out_guarded.encode("utf-8"))

    log_request(
        CONSOLIDATED_CSV,
        scenario=SCENARIO,
        domain=DATASET_TAG,
        prompt=query.prompt,
        response=out_guarded,
        latency_ms=latency_ms,
        was_blocked=was_blocked,
        scanner_triggered=scanner_triggered,
        block_reason=f"output_{output_scanner.lower()}" if output_scanner is not None else None,
        garak_tag=garak_tag,
        prompt_type=prompt_type,
        input_scanner_score=input_score,
        output_scanner_score=output_score,
    )

    return {"response": out_guarded}


@app.get("/health")
async def health():
    """Return Shield service status and upstream RAG reachability."""
    upstream_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(RAG_HEALTH_URL)
            upstream_ok = (200 <= r.status_code < 300)
    except Exception:
        upstream_ok = False

    return {
        "status": "ok",
        "mode": "proxy",
        "enable_llm_guard": ENABLE_LLM_GUARD,
        "upstream_rag": RAG_BASE_URL,
        "upstream_ok": upstream_ok,
    }
