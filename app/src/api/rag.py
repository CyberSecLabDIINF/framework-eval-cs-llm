import json
import os
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
IS_PROTECTED = SCENARIO == "protected"
LATENCY_CSV = str(s.latency_dir / "latency_unprotected.csv")

CONSOLIDATED_CSV = Path(os.getenv(
    "CONSOLIDATED_CSV",
    str(s.artifacts_dir / f"consolidated_{DATASET_TAG}_{SCENARIO}.csv")
))

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
    prompt: str

def retrieve_context(query: str, k: int = 3) -> tuple:
    """
    Retrieve the top-k fragments from ChromaDB for the given query.
 
    C8 — Only fragments whose sensitivity level is within ALLOWED_SENSITIVITY
    are eligible for retrieval, enforcing vector store partitioning at query time.
 
    Returns:
        context_str  — fragments joined for prompt injection.
        fragments    — list of (doc_id, text) pairs, used by C9 integrity check.
    """
    try:
        where_filter = {"sensitivity": {"$in": ALLOWED_SENSITIVITY}} if IS_PROTECTED else None
        results = collection.query(
            query_texts=[query],
            n_results=k,
            include=["documents", "ids"],
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
    C32 — Verify that the system prompt has not been modified.
    Compares current hash against the hash computed at startup.
    """
    current_hash = hashlib.sha256(
        (SYSTEM_ROLE + RESTRICTIONS).encode("utf-8")
    ).hexdigest()
    return current_hash == SYSTEM_PROMPT_HASH

def is_on_domain(query: str) -> bool:
    """
    C4 — Validate semantic relevance of the prompt against the authorized domain.
    Returns False if the minimum distance to the corpus exceeds the configured threshold.
    Fails open: if ChromaDB is unavailable, the prompt is allowed through.
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

def validate_corpus_integrity(fragments: list) -> tuple:
    """
    C9 — Validate integrity of retrieved fragments before LLM context injection.
 
    For each (doc_id, text) pair returned by ChromaDB, recomputes the SHA-256
    hash and compares it against the baseline stored in CORPUS_HASHES.
 
    Returns:
        (True, None)           — all fragments pass.
        (False, tampered_id)   — first doc_id whose hash does not match.
 
    Behavior on unknown IDs: a fragment whose ID was not present at startup
    is treated as a tampered document (fail-closed).
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
    log: bool = True,
) -> dict:
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
        )
    return {"response": message}


@app.post("/generate")
async def generate(query: Query, request: Request):
    start = time.perf_counter()

    garak_tag = request.headers.get("X-Garak-Tag", "")
    prompt_type = "adversarial" if garak_tag else "legitimate"
    forwarded_by_shield = request.headers.get("x-forwarded-by", "") == "shield"

    # Pre-retrieval checks: C32 and C4 act on the prompt before the vector store is touched.
    if IS_PROTECTED:
        if not validate_system_prompt_integrity():
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="System prompt integrity check failed.",
                block_reason="system_prompt_integrity_failed",
            )
        if not is_on_domain(query.prompt):
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Query is outside the authorized domain.",
                block_reason="domain_validation_failed",
                log=not forwarded_by_shield,
            )

    context, fragments = retrieve_context(query.prompt, k=3)

    # Post-retrieval check: C9 validates fragment integrity before context injection.
    if IS_PROTECTED:
        integrity_ok, _ = validate_corpus_integrity(fragments)
        if not integrity_ok:
            return _blocked_response(
                request, query, start, garak_tag, prompt_type,
                message="Corpus integrity check failed.",
                block_reason="corpus_integrity_failed",
            )

    prompt = f"""{SYSTEM_ROLE}

{RESTRICTIONS}

Context:
{context}

Question:
{query.prompt}""".strip()

    response = client.generate(model=MODEL_NAME, prompt=prompt)
    out = response.get("response", "")
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
        )

    return {"response": out}


@app.get("/health")
def health():
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
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", str(s.rag_port))))
