import json
import os
import re
import string
from pathlib import Path
import time
import hashlib

import chromadb
import ollama
from fastapi import FastAPI, Request
from pydantic import BaseModel
import logging
from eval.consolidator import log_request

from api.middleware import RequestIdMiddleware, LatencyCSVLogger
from settings import get_settings

app = FastAPI(title="RAG API")

s = get_settings()
logger = logging.getLogger("rag")

DATASET_TAG = os.getenv("DATASET_TAG", s.dataset_tag)
CONFIG_RAG_PATH = s.get_rag_config_path(DATASET_TAG)
CHROMA_PATH = str(s.chroma_db_path)
OLLAMA_HOST_ENV = os.getenv("OLLAMA_HOST")
SCENARIO = os.getenv("SCENARIO", "unprotected")
LATENCY_CSV = str(s.latency_dir / "latency_unprotected.csv")

def _resolve_consolidated_csv() -> Path:
    """Return the base (non-smoke-test) consolidated CSV path.

    RUN_KIND-based smoke_test isolation is applied per-request by
    ``consolidator.log_request()``, driven by the ``X-Run-Kind`` header on
    each incoming request — not here. This process is a long-lived container
    shared across many runs, so any RUN_KIND baked in at import time would go
    stale as soon as a different run_kind is used without restarting it.

    The ``CONSOLIDATED_CSV`` env var can still override the default path.
    """
    _csv_name = f"consolidated_{DATASET_TAG}_{SCENARIO}.csv"
    return Path(os.getenv("CONSOLIDATED_CSV", str(s.artifacts_dir / _csv_name)))

CONSOLIDATED_CSV = _resolve_consolidated_csv()

LATENCY_DIRECT = os.getenv("LATENCY_CSV_DIRECT", str(s.artifacts_dir / "latency" / "latency_unprotected_direct.csv"))
LATENCY_VIA_SHIELD = os.getenv("LATENCY_CSV_VIA_SHIELD", str(s.artifacts_dir / "latency" / "latency_unprotected_via_shield.csv"))

# Middleware must be registered after all module-level variables are defined.
app.add_middleware(RequestIdMiddleware)

# Track direct (non-Shield) requests to /generate for the unprotected scenario.
app.add_middleware(
    LatencyCSVLogger,
    scenario="unprotected",
    domain=DATASET_TAG,
    csv_path=LATENCY_DIRECT,
    skip_if_header=("x-forwarded-by", "shield"),
)

# Track requests proxied through Shield to measure LAS latency overhead.
app.add_middleware(
    LatencyCSVLogger,
    scenario="unprotected_via_shield",
    domain=DATASET_TAG,
    csv_path=LATENCY_VIA_SHIELD,
    only_if_header=("x-forwarded-by", "shield"),
)

if not CONFIG_RAG_PATH.exists():
    raise FileNotFoundError(f"RAG config not found: {CONFIG_RAG_PATH}")

config = json.loads(CONFIG_RAG_PATH.read_text(encoding="utf-8"))

# Environment variable takes precedence over the Ollama host set in the config JSON.
if OLLAMA_HOST_ENV:
    config["ollama_host"] = OLLAMA_HOST_ENV

COLLECTION_NAME = config.get("collection_name")
SYSTEM_ROLE = config.get("system_role", "")
RESTRICTIONS = config.get("restrictions", "")
MODEL_NAME = config.get("model_name", "llama3:8b")
OLLAMA_HOST = config.get("ollama_host", "http://127.0.0.1:11434")

chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH))
collection = chroma_client.get_or_create_collection(name=COLLECTION_NAME)

client = ollama.Client(host=OLLAMA_HOST)

SYSTEM_PROMPT_HASH = hashlib.sha256(
    (SYSTEM_ROLE + RESTRICTIONS).encode("utf-8")
).hexdigest()

DOMAIN_DISTANCE_THRESHOLD = float(os.getenv("DOMAIN_DISTANCE_THRESHOLD", "1.0"))

# ---------------------------------------------------------------------------
# C11 — Semantic query coherence validation
# Rejects queries whose minimum distance to any corpus fragment exceeds the
# configured threshold, indicating no semantic relationship with the corpus.
# Distinct from C4: C4 validates domain membership; C11 validates minimum
# semantic coherence before retrieval is attempted.
# Fails open: if ChromaDB is unavailable, the query is allowed through.
# ---------------------------------------------------------------------------
QUERY_COHERENCE_THRESHOLD = float(os.getenv("QUERY_COHERENCE_THRESHOLD", "1.5"))

# ---------------------------------------------------------------------------
# C12 — Corpus reconnaissance detection
# Detects queries designed for systematic enumeration of the vector store.
# Two complementary strategies:
#   Lexical  — explicit patterns signaling bulk retrieval intent.
#   Structural — excessive length or term repetition suggesting enumeration.
# ---------------------------------------------------------------------------
_C12_RECON_PATTERNS = re.compile(
    r"\b(list all|show all|dump all|retrieve all|get all|extract all"
    r"|show every|list every|enumerate all|enumerate every"
    r"|all documents|all contents|all records|all data|all files"
    r"|full database|entire corpus|entire database|everything in the"
    r"|what documents|which documents|how many documents"
    r"|index of|table of contents of the database"
    r"|reveal (your|the) (corpus|index|database|documents)"
    r"|what is indexed|what have you indexed)\b",
    re.IGNORECASE,
)
_C12_MAX_TOKENS = 80        # queries above this token count are suspicious
_C12_REPEAT_RATIO = 0.6     # ratio of repeated tokens above this is suspicious

# ---------------------------------------------------------------------------
# C17 — Context-grounded response validation
# Measures token overlap between the model response and the retrieved context.
# Responses whose grounding ratio falls below the threshold are blocked.
# Default threshold (0.05) is intentionally set below both calibrated domain
# values so the control fails open when C17_GROUNDING_THRESHOLD is not set.
# ---------------------------------------------------------------------------
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
    "into", "through", "during", "before", "after", "above", "below",
    "and", "but", "or", "nor", "so", "yet", "both", "either", "neither",
    "not", "no", "if", "then", "that", "this", "these", "those", "it",
    "its", "i", "you", "he", "she", "we", "they", "what", "which", "who",
})
_C17_GROUNDING_THRESHOLD = float(os.getenv("C17_GROUNDING_THRESHOLD", "0.05"))

# ---------------------------------------------------------------------------
# C8 — Sensitivity-based vector store partitioning
# SENSITIVITY_LEVEL defines the ceiling allowed for this session.
# The retrieval filter includes only chunks at or below the configured level.
# Mapping: low={low}, medium={low, medium}, high={low, medium, high}
# ---------------------------------------------------------------------------
_SENSITIVITY_CEILING: dict = {
    "low":    ["low"],
    "medium": ["low", "medium"],
    "high":   ["low", "medium", "high"],
}
SENSITIVITY_LEVEL = os.getenv("SENSITIVITY_LEVEL", "high").lower()
ALLOWED_SENSITIVITY = _SENSITIVITY_CEILING.get(SENSITIVITY_LEVEL, ["low", "medium", "high"])

# ---------------------------------------------------------------------------
# C9 — Corpus integrity baseline (computed once at startup, held in memory)
# Each document in the collection is hashed (SHA-256) and stored by its ID.
# Before any fragment is injected into the LLM context, its hash is re-checked
# against this baseline.  A mismatch triggers a hard block.
# ---------------------------------------------------------------------------
def _build_corpus_hashes() -> dict:
    """
    Fetch every document stored in ChromaDB and compute its SHA-256 hash.
    Returns a mapping of {doc_id: hex_digest}.
    Called once at module load time; result is stored in CORPUS_HASHES.
    """
    hashes: dict = {}
    try:
        total = collection.count()
        if total == 0:
            logger.warning("C9: collection is empty at startup — no hashes computed")
            return hashes
        # Retrieve all documents in a single call (no query needed).
        result = collection.get(include=["documents"])
        ids = result.get("ids", [])
        docs = result.get("documents", [])
        for doc_id, text in zip(ids, docs):
            hashes[doc_id] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        logger.info("C9: corpus baseline built — %d document hashes stored", len(hashes))
    except Exception as e:
        logger.exception("C9: failed to build corpus hashes at startup", exc_info=e)
    return hashes
 
CORPUS_HASHES: dict = _build_corpus_hashes()

class Query(BaseModel):
    """Request body for the ``/generate`` endpoint."""

    prompt: str

def retrieve_context(query: str, is_protected: bool, k: int = 3) -> tuple:
    """
    Retrieve the top-k fragments from ChromaDB for the given query.

    Only fragments whose sensitivity level is within ALLOWED_SENSITIVITY are
    eligible for retrieval, enforcing vector store partitioning at query time.
    Document metadata is intentionally excluded from the include list. Passing
    only ["documents", "ids"] ensures that source paths, page numbers, chunk
    indices, and any other metadata fields stored in ChromaDB are never
    injected into the LLM context or exposed to the caller. The fragment IDs
    are used internally for C9 integrity verification only and are never
    included in the prompt sent to the model.

    Returns:
        context_str  — fragments joined for prompt injection.
        fragments    — list of (doc_id, text) pairs, used by C9 integrity check.

    LLM-Sec Control C8: Restricts retrieval to fragments whose sensitivity metadata is within ALLOWED_SENSITIVITY for the active scenario
    LLM-Sec Control C10: Bounds the number of retrieved fragments via the n_results (k) parameter passed to ChromaDB
    LLM-Sec Control C13: Caps the total context volume injected into the prompt by limiting retrieval to k fragments
    LLM-Sec Control C14: Excludes document metadata from retrieval, so only fragment text/IDs reach the LLM context
    """
    try:
        where_filter = {"sensitivity": {"$in": ALLOWED_SENSITIVITY}} if is_protected else None
        results = collection.query(
            query_texts=[query],
            n_results=k,
            include=["documents"],
            where=where_filter,
        )
        docs = results.get("documents", [[]])[0] or []
        ids  = results.get("ids",       [[]])[0] or []
        fragments = list(zip(ids, docs))
        return "\n\n".join(docs), fragments
    except Exception as e:
        logger.exception("Chroma query failed", exc_info=e)
        return "", []

def validate_system_prompt_integrity() -> bool:
    """
    Compares current hash against the hash computed at startup.

    LLM-Sec Control C32: Verifies the system prompt and restrictions have not been modified since startup (SHA-256 hash check)
    """
    current_hash = hashlib.sha256(
        (SYSTEM_ROLE + RESTRICTIONS).encode("utf-8")
    ).hexdigest()
    return current_hash == SYSTEM_PROMPT_HASH

def is_on_domain(query: str) -> bool:
    """
    Returns False if the minimum distance to the corpus exceeds the configured threshold.
    Fails open: if ChromaDB is unavailable, the prompt is allowed through.

    LLM-Sec Control C4: Blocks queries whose minimum semantic distance to the corpus exceeds DOMAIN_DISTANCE_THRESHOLD (out-of-domain rejection)
    """
    try:
        results = collection.query(
            query_texts=[query],
            n_results=1,
            include=["distances"],
        )
        distance = results["distances"][0][0]
        return distance <= DOMAIN_DISTANCE_THRESHOLD
    except Exception as e:
        logger.exception("Domain validation failed", exc_info=e)
        return True  # fail-open: do not block on error

def is_coherent_query(query: str) -> bool:
    """
    Returns False if the minimum distance to any corpus fragment exceeds
    QUERY_COHERENCE_THRESHOLD, indicating a structurally incoherent or
    adversarially encoded query.
    Fails open: if ChromaDB is unavailable, the query is allowed through.

    LLM-Sec Control C11: Blocks queries whose minimum semantic distance to the corpus exceeds QUERY_COHERENCE_THRESHOLD (incoherent/encoded query rejection)
    """
    try:
        results = collection.query(
            query_texts=[query],
            n_results=1,
            include=["distances"],
        )
        distance = results["distances"][0][0]
        return distance <= QUERY_COHERENCE_THRESHOLD
    except Exception as e:
        logger.exception("Coherence validation failed", exc_info=e)
        return True 

def is_safe_from_reconnaissance(query: str) -> bool:
    """
    Returns False if the query matches either detection strategy:
      Lexical:    explicit bulk-retrieval or enumeration patterns.
      Structural: excessive length (> _C12_MAX_TOKENS tokens) combined with
                  high term repetition (repeated-token ratio > _C12_REPEAT_RATIO),
                  which is characteristic of enumeration-by-exhaustion attempts.

    Fails closed on lexical matches (deterministic).
    Structural check only triggers when BOTH conditions are met simultaneously
    to avoid false positives on legitimate long queries.

    LLM-Sec Control C12: Detects and blocks queries indicative of systematic corpus reconnaissance/enumeration attempts
    """
    # Lexical check — deterministic, fail closed.
    if _C12_RECON_PATTERNS.search(query):
        logger.warning("C12: lexical reconnaissance pattern detected")
        return False

    # Structural check — requires both conditions simultaneously.
    tokens = query.lower().split()
    if len(tokens) > _C12_MAX_TOKENS:
        unique = set(tokens)
        repeat_ratio = 1.0 - (len(unique) / len(tokens))
        if repeat_ratio > _C12_REPEAT_RATIO:
            logger.warning(
                "C12: structural reconnaissance detected — tokens=%d repeat_ratio=%.2f",
                len(tokens), repeat_ratio,
            )
            return False

    return True

def is_grounded_response(response: str, context: str) -> tuple:
    """
    Computes the ratio of significant response tokens that also appear in the
    context. Significant tokens are non-stop-word, alphabetic tokens of at
    least 4 characters.

    Returns:
        (True, ratio)   — response is sufficiently grounded.
        (False, ratio)  — response grounding ratio is below threshold.

    Edge cases:
        - Empty response: treated as grounded (nothing to validate).
        - No significant tokens in response: treated as grounded (e.g. short
          acknowledgment responses).
        - Empty context: treated as not grounded (fail closed).

    LLM-Sec Control C17: Blocks responses whose token overlap with the retrieved context falls below C17_GROUNDING_THRESHOLD
    """
    if not response.strip():
        return True, 1.0

    if not context.strip():
        logger.warning("C17: empty context — cannot validate grounding, blocking response")
        return False, 0.0

    def _tokenize(text: str) -> set:
        translator = str.maketrans("", "", string.punctuation)
        tokens = text.lower().translate(translator).split()
        return {t for t in tokens if len(t) >= 4 and t not in _STOP_WORDS}

    response_tokens = _tokenize(response)
    if not response_tokens:
        return True, 1.0

    context_tokens = _tokenize(context)
    overlap = response_tokens & context_tokens
    ratio = len(overlap) / len(response_tokens)

    if ratio < _C17_GROUNDING_THRESHOLD:
        logger.warning(
            "C17: response grounding too low — ratio=%.3f threshold=%.3f",
            ratio, _C17_GROUNDING_THRESHOLD,
        )
        return False, ratio

    return True, ratio

def validate_corpus_integrity(fragments: list) -> tuple:
    """
    For each (doc_id, text) pair returned by ChromaDB, recomputes the SHA-256
    hash and compares it against the baseline stored in CORPUS_HASHES.

    Returns:
        (True, None)           — all fragments pass.
        (False, tampered_id)   — first doc_id whose hash does not match.

    Behavior on unknown IDs: a fragment whose ID was not present at startup
    is treated as a tampered document (fail-closed).

    LLM-Sec Control C9: Verifies retrieved fragment hashes against the CORPUS_HASHES baseline before LLM context injection
    """
    for doc_id, text in fragments:
        expected = CORPUS_HASHES.get(doc_id)
        if expected is None:
            logger.warning("C9: unknown doc_id '%s' — not in baseline, treating as tampered", doc_id)
            return False, doc_id
        actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if actual != expected:
            logger.warning("C9: integrity mismatch for doc_id '%s'", doc_id)
            return False, doc_id
    return True, None

def _blocked_response(
    request: Request,
    query: Query,
    start: float,
    garak_tag: str,
    prompt_type: str,
    message: str,
    block_reason: str,
    run_id: str,
    run_kind: str,
    log: bool = True,
    grounding_ratio: float | None = None,
) -> dict:
    """Build a blocked-response dict and optionally log it to the consolidated CSV.

    Args:
        request: The incoming FastAPI request (used to set ``response_len``).
        query: The original query containing the prompt text.
        start: ``time.perf_counter()`` value at request start, for latency calculation.
        garak_tag: Value of the ``X-Garak-Tag`` header.
        prompt_type: ``"adversarial"`` or ``"legitimate"``.
        message: Human-readable block message returned to the caller.
        block_reason: Short code identifying the control that triggered the block.
        run_id: Value of the ``X-Run-Id`` header (see :func:`generate`).
        run_kind: Value of the ``X-Run-Kind`` header (see :func:`generate`).
        log: When False, skips writing to the consolidated CSV (used to avoid
            double-logging requests forwarded through Shield).
        grounding_ratio: C17 grounding ratio of the response, if computed.

    Returns:
        A ``{"response": message}`` dict ready to be returned by the endpoint.
    """
    latency_ms = (time.perf_counter() - start) * 1000.0
    request.state.response_len = len(message.encode("utf-8"))
    if log:
        log_request(
            CONSOLIDATED_CSV,
            scenario=SCENARIO,
            domain=DATASET_TAG,
            prompt=query.prompt,
            response=message,
            latency_ms=latency_ms,
            was_blocked=True,
            garak_tag=garak_tag,
            prompt_type=prompt_type,
            block_reason=block_reason,
            grounding_ratio=grounding_ratio,
            response_has_system_prompt=0,
            injection_followed=0,
            run_id=run_id,
            run_kind=run_kind,
        )
    return {
        "response": message,
        "blocked_by_rag": True,
        "block_reason": block_reason,
        "grounding_ratio": grounding_ratio,
    }


@app.post("/generate")
async def generate(query: Query, request: Request):
    """Answer a user query using RAG and apply defence controls when running as protected.

    When ``is_protected`` is True (derived per-request from the
    ``x-scenario: protected`` header set by Shield; absent when Garak hits
    this service directly in Scenario A), the following controls gate the pipeline:
    C32 (system-prompt integrity), C4 (domain validation), C11 (coherence),
    C12 (reconnaissance detection), C9 (corpus integrity), C17 (response
    grounding). Requests forwarded by Shield (``x-forwarded-by: shield``) are
    excluded from consolidated-CSV logging to prevent double-counting.

    Returns:
        A JSON object ``{"response": <text>}``, blocked responses included.

    LLM-Sec Control C5: Only the model's generated text is extracted/returned to the client; the system prompt (SYSTEM_ROLE/RESTRICTIONS) is never included in the response
    LLM-Sec Control C6: Structures the prompt with explicit Context:/Question: delimiters, separating retrieved content from the user query
    LLM-Sec Control C15: Injects externally-configured system role and restriction instructions (SYSTEM_ROLE/RESTRICTIONS) into every prompt
    """
    start = time.perf_counter()

    garak_tag = request.headers.get("X-Garak-Tag", "")
    prompt_type = "adversarial" if garak_tag else "legitimate"
    forwarded_by_shield = request.headers.get("x-forwarded-by", "") == "shield"
    is_protected = request.headers.get("x-scenario", "") == "protected"
    # RUN_ID/RUN_KIND live in the garak_runner/legitimate-orchestrator
    # process, not this container's environment — they must arrive per
    # request via header (rag.py's own os.getenv would always read empty).
    run_id = request.headers.get("X-Run-Id", "")
    run_kind = request.headers.get("X-Run-Kind", "experiment")

    # Pre-retrieval checks: C32 and C4 act on the prompt before the vector store is touched.
    if is_protected:
        if not validate_system_prompt_integrity():
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="System prompt integrity check failed.",
                block_reason="system_prompt_integrity_failed",
                run_id=run_id, run_kind=run_kind,
                log=not forwarded_by_shield,
            )
        if not is_on_domain(query.prompt):
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Query is outside the authorized domain.",
                block_reason="domain_validation_failed",
                run_id=run_id, run_kind=run_kind,
                log=not forwarded_by_shield,
            )
        if not is_coherent_query(query.prompt):
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Query does not meet minimum semantic coherence requirements.",
                block_reason="query_coherence_failed",
                run_id=run_id, run_kind=run_kind,
                log=not forwarded_by_shield,
            )
        if not is_safe_from_reconnaissance(query.prompt):
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Query flagged as potential corpus reconnaissance attempt.",
                block_reason="corpus_reconnaissance_detected",
                run_id=run_id, run_kind=run_kind,
                log=not forwarded_by_shield,
            )

    context, fragments = retrieve_context(query.prompt, is_protected, k=3)
    logger.info(
        "DEBUG-C17 retrieve_context: is_protected=%s fragments_count=%d context[:200]=%r",
        is_protected, len(fragments), context[:200],
    )

    # Post-retrieval check: C9 validates fragment integrity before context injection.
    if is_protected:
        integrity_ok, _ = validate_corpus_integrity(fragments)
        if not integrity_ok:
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Corpus integrity check failed.",
                block_reason="corpus_integrity_failed",
                run_id=run_id, run_kind=run_kind,
                log=not forwarded_by_shield,
            )

    prompt = f"""{SYSTEM_ROLE}

{RESTRICTIONS}

Context:
{context}

Question:
{query.prompt}""".strip()

    response = client.generate(model=MODEL_NAME, prompt=prompt)
    out = response.get("response", "")

    grounded, grounding_ratio = is_grounded_response(out, context)
    logger.info(
        "DEBUG-C17 is_grounded_response: ratio=%.4f grounded=%s out[:200]=%r",
        grounding_ratio, grounded, out[:200],
    )
    if is_protected and not grounded:
        return _blocked_response(
            request, query, start, garak_tag, prompt_type,
            message="Response could not be grounded in the retrieved context.",
            block_reason="response_not_grounded",
            run_id=run_id, run_kind=run_kind,
            log=not forwarded_by_shield,
            grounding_ratio=grounding_ratio,
        )

    latency_ms = (time.perf_counter() - start) * 1000.0

    request.state.response_len = len(out.encode("utf-8"))

    if not forwarded_by_shield:
        log_request(
            CONSOLIDATED_CSV,
            scenario=SCENARIO,
            domain=DATASET_TAG,
            prompt=query.prompt,
            response=out,
            latency_ms=latency_ms,
            was_blocked=False,
            garak_tag=garak_tag,
            prompt_type=prompt_type,
            grounding_ratio=grounding_ratio,
            response_has_system_prompt=0,
            injection_followed=0,
            run_id=run_id,
            run_kind=run_kind,
        )

    return {"response": out, "blocked_by_rag": False, "grounding_ratio": grounding_ratio}


@app.get("/health")
def health():
    """Return service status and active configuration parameters."""
    return {
        "status": "ok",
        "scenario": SCENARIO,
        "dataset_tag": DATASET_TAG,
        "collection_name": COLLECTION_NAME,
        "chroma_path": str(CHROMA_PATH),
        "ollama_host": OLLAMA_HOST,
        "model_name": MODEL_NAME,
        "docs_in_db": collection.count(),
        "latency_csv": str(LATENCY_CSV),
        "corpus_hashes_loaded": len(CORPUS_HASHES),
        "allowed_sensitivity": ALLOWED_SENSITIVITY,
        "coherence_threshold": QUERY_COHERENCE_THRESHOLD,
        "c12_recon_max_tokens": _C12_MAX_TOKENS,
        "c12_recon_repeat_ratio": _C12_REPEAT_RATIO,
        "c17_grounding_threshold": _C17_GROUNDING_THRESHOLD,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", str(s.rag_port))))
