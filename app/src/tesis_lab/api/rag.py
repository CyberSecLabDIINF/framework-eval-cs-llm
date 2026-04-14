import json
import os
from pathlib import Path
import time

import chromadb
import ollama
from fastapi import FastAPI, Request
from pydantic import BaseModel
import logging
from tesis_lab.eval.consolidator import log_request

from tesis_lab.api.middleware import RequestIdMiddleware, LatencyCSVLogger
from tesis_lab.settings import get_settings

app = FastAPI(title="RAG API")

s = get_settings()
logger = logging.getLogger("rag")

DATASET_TAG = os.getenv("DATASET_TAG", s.dataset_tag)
CONFIG_RAG_PATH = Path(os.getenv("RAG_CONFIG_PATH", str(s.get_rag_config_path(DATASET_TAG)))).resolve()
CHROMA_PATH = Path(os.getenv("CHROMA_PATH", str(s.project_root / "chroma_db"))).resolve()
OLLAMA_HOST_ENV = os.getenv("OLLAMA_HOST")
SCENARIO = os.getenv("SCENARIO", "unprotected")
LATENCY_CSV = os.getenv(
    "LATENCY_CSV",
    str(s.reports_dir / "latency" / "latency.csv"),  # legacy compatible
)

CONSOLIDATED_CSV = Path(os.getenv(
    "CONSOLIDATED_CSV",
    str(s.artifacts_dir / "consolidated_{DATASET_TAG}_{SCENARIO}.csv")
))

LATENCY_DIRECT = os.getenv("LATENCY_CSV_DIRECT", str(s.artifacts_dir / "latency" / "latency_unprotected_direct.csv"))
LATENCY_VIA_SHIELD = os.getenv("LATENCY_CSV_VIA_SHIELD", str(s.artifacts_dir / "latency" / "latency_unprotected_via_shield.csv"))

# Middleware must be registered after all module-level variables are defined.
app.add_middleware(RequestIdMiddleware)

# Track direct (non-Shield) requests to /generate for the unprotected scenario.
app.add_middleware(
    LatencyCSVLogger,
    scenario="unprotected",
    csv_path=LATENCY_DIRECT,
    skip_if_header=("x-forwarded-by", "shield"),
)

# Track requests proxied through Shield to measure LAS latency overhead.
app.add_middleware(
    LatencyCSVLogger,
    scenario="unprotected_via_shield",
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


class Query(BaseModel):
    prompt: str


def retrieve_context(query: str, k: int = 3) -> str:
    try:
        results = collection.query(query_texts=[query], n_results=k)
        docs = results.get("documents", [[]])[0] or []
        return "\n\n".join(docs)
    except Exception as e:
        logger.exception("Chroma query failed", exc_info=e)
        return ""



@app.post("/generate")
async def generate(query: Query, request: Request):
    start = time.perf_counter()
    context = retrieve_context(query.prompt, k=3)

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

    garak_tag = request.headers.get("X-Garak-Tag", "")
    prompt_type = "adversarial" if garak_tag else "legitimate"

    forwarded_by_shield = request.headers.get("x-forwarded-by", "") == "shield"

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
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", str(s.rag_port))))
