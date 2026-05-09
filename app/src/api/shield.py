import os
import time
from pathlib import Path
from typing import Optional, Dict, Any
import logging as _logging

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import httpx
import yaml

from llm_guard import scan_prompt, scan_output
from llm_guard.input_scanners import PromptInjection, Regex as InputRegex, TokenLimit

try:
    from llm_guard.output_scanners import Sensitive
    HAS_SENSITIVE = True
except Exception:
    HAS_SENSITIVE = False

from api.middleware import RequestIdMiddleware, LatencyCSVLogger
from settings import get_settings
from eval.consolidator import log_request

# Persist LLM Guard logs to file for post-experiment audit
_LLM_GUARD_LOG_FILE = Path(os.getenv(
    "LLM_GUARD_LOG_FILE",
    "/root/proyecto_tesis/artifacts/llm_guard.log"
))
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

s = get_settings()

app.add_middleware(RequestIdMiddleware)

SCENARIO = os.getenv("SCENARIO", "protected")
DATASET_TAG = os.getenv("DATASET_TAG", s.dataset_tag)

CONSOLIDATED_CSV = Path(os.getenv(
    "CONSOLIDATED_CSV",
    str(s.artifacts_dir / f"consolidated_{DATASET_TAG}_{SCENARIO}.csv")
))
LATENCY_CSV = os.getenv("LATENCY_CSV", "/root/proyecto_tesis/artifacts/latency/latency_protected.csv")
app.add_middleware(LatencyCSVLogger, scenario=SCENARIO, csv_path=LATENCY_CSV)

ENABLE_LLM_GUARD = os.getenv("ENABLE_LLM_GUARD", "1") == "1"
ENABLE_OUTPUT_GUARD = os.getenv("ENABLE_OUTPUT_GUARD", "0") == "1"

RAG_BASE_URL = os.getenv("RAG_BASE_URL", f"http://127.0.0.1:{s.rag_port}")
RAG_GENERATE_URL = f"{RAG_BASE_URL}/generate"
RAG_HEALTH_URL = f"{RAG_BASE_URL}/health"

UPSTREAM_TIMEOUT_S = float(os.getenv("UPSTREAM_TIMEOUT_S", "120"))

# Load LLM Guard configuration from YAML (pre-experiment, no post-hoc bias)
_LLM_GUARD_CONFIG_PATH = Path(os.getenv(
    "LLM_GUARD_CONFIG_PATH",
    str(Path("/root/proyecto_tesis/app/config/llm_guard_config.yaml"))
))

def _load_llm_guard_config() -> dict:
    if _LLM_GUARD_CONFIG_PATH.exists():
        with _LLM_GUARD_CONFIG_PATH.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}

_cfg = _load_llm_guard_config()
_input_cfg = _cfg.get("input_scanners", {})
_output_cfg = _cfg.get("output_scanners", {})

class Query(BaseModel):
    prompt: str

def guard_input(user_prompt: str) -> tuple[Optional[str], Optional[str], Optional[float]]:
    """
    Validate and sanitize the input prompt.
    Returns (sanitized_prompt, None) if allowed.
    Returns (None, scanner_name) if blocked.
    Controls: C2/C3 (PromptInjection), C1 (TokenLimit), C19 (Regex)
    """
    p = user_prompt.strip()
    if not ENABLE_LLM_GUARD:
        return p, None, None

    pi_cfg = _input_cfg.get("prompt_injection", {})
    rx_cfg = _input_cfg.get("regex", {})
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

    if rx_cfg.get("enabled", True):
        scanners.append(
            InputRegex(
                patterns=rx_cfg.get("patterns", ["\\[CONFIDENTIAL\\]"]),
                is_blocked=rx_cfg.get("is_blocked", True),
                match_type=rx_cfg.get("match_type", "search"),
            )
        )

    last_score = None

    for scanner in scanners:
        sanitized, is_valid_dict, scores = scan_prompt([scanner], p)
        if isinstance(scores, dict):
            last_score = next(iter(scores.values()), None)
        if not all(is_valid_dict.values()):
            return None, scanner.__class__.__name__
        p = sanitized

    return p, None, last_score


def guard_output(prompt: str, text: str) -> tuple[str, Optional[str], Optional[float]]:
    """
    Validate and sanitize the model output.
    Returns (sanitized_output, None) if allowed.
    Returns (blocked_message, scanner_name) if blocked.
    Controls: C20 (Sensitive)
    """
    if not ENABLE_LLM_GUARD:
        return text, None, None

    if not HAS_SENSITIVE:
        return text, None, None

    sens_cfg = _output_cfg.get("sensitive", {})

    if not sens_cfg.get("enabled", True):
        return text, None

    scanners = [
        Sensitive(
            threshold=sens_cfg.get("threshold", 0.5),
            redact=sens_cfg.get("redact", False),
            use_onnx=sens_cfg.get("use_onnx", False),
        )
    ]

    p_out = text
    last_score = None
    for scanner in scanners:
        try:
            sanitized, is_valid_dict, scores = scan_output([scanner], prompt, p_out)
            if isinstance(scores, dict):
                last_score = next(iter(scores.values()), None)
            if not all(is_valid_dict.values()):
                return f"Output blocked by {scanner.__class__.__name__}.", scanner.__class__.__name__
            p_out = sanitized
        except Exception:
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
    start = time.perf_counter()

    garak_tag = request.headers.get("X-Garak-Tag", "")
    prompt_type = "adversarial" if garak_tag else "legitimate"

    # Input guard
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
            garak_tag=garak_tag,
            prompt_type=prompt_type,
            input_scanner_score=input_score,
            output_scanner_score=None,
        )
        return {"response": out}

    # Forward to RAG
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

    # Output guard
    out_guarded, output_scanner, output_score = guard_output(query.prompt, out)
    latency_ms = (time.perf_counter() - start) * 1000.0

    was_blocked = out_guarded != out
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
        garak_tag=garak_tag,
        prompt_type=prompt_type,
        input_scanner_score=input_score,
        output_scanner_score=output_score,
    )

    return {"response": out_guarded}


@app.get("/health")
async def health():
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
