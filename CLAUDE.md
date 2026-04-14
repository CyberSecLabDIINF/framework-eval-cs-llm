# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a research project evaluating RAG (Retrieval-Augmented Generation) system security against adversarial attacks. It runs two parallel API endpoints — an unprotected RAG and a protected Shield (LLM Guard wrapper) — then uses the [Garak](https://github.com/leondz/garak) framework to execute OWASP LLM vulnerability probes against both, measuring attack success rate (ASR) and latency.

## Common Commands

All operations run via Docker Compose:

```bash
# Start core services (Ollama + RAG + Shield APIs)
docker compose up -d --build

# Ingest documents into ChromaDB
docker exec -it tesis_rag bash -lc "python3 -m tesis_lab.cli ingest --source regulatory_technical --reset"

docker exec -it tesis_rag bash -lc "python3 -m tesis_lab.cli ingest --source academic_institutional --reset"

# Run attacks (target: unprotected | protected)
docker compose --profile attacks run --rm garak_runner attack garak --target unprotected
docker compose --profile attacks run --rm garak_runner attack garak --target unprotected --suite LLM01

# Analyze latency
docker compose --profile attacks run --rm garak_runner analyze latency \
  --unprotected-csv ./artifacts/latency/latency_unprotected.csv \
  --protected-csv ./artifacts/latency/latency_protected.csv

# Compare ASR between runs
docker compose --profile attacks run --rm garak_runner analyze compare \
  --run-unprotected ./artifacts/runs/<run_id_unprotected> \
  --run-protected ./artifacts/runs/<run_id_protected>

# List available Garak probes
docker compose --profile attacks run --rm garak_runner attack list-probes --suite LLM01

# Health checks
curl http://localhost:8000/health  # RAG API
curl http://localhost:8001/health  # Shield API
```

### Bootstrap (first-time / air-gapped setup)

```bash
# Pull Ollama model
docker compose --profile bootstrap up -d ollama_bootstrap
docker exec -it ollama_bootstrap ollama pull llama3:8b
docker compose --profile bootstrap down

# Cache ONNX embeddings for Chroma
docker compose --profile bootstrap run --rm chroma_bootstrap
```

## Architecture

The system is a Python 3.10 package (`tesis_lab`) structured as follows:

```
app/src/tesis_lab/
├── settings.py       # Pydantic BaseSettings — single source of truth for config
├── cli.py            # Typer CLI: serve, ingest, attack, analyze subcommands
├── api/
│   ├── rag.py        # Unprotected FastAPI app — ChromaDB context + Ollama generation
│   ├── shield.py     # Protected FastAPI app — LLM Guard input/output scan + proxy to RAG
│   └── middleware.py # RequestIdMiddleware + LatencyCSVLogger (CSV per endpoint)
├── eval/
│   ├── garak_metrics.py    # Parse report.jsonl → compute ASR per probe
│   ├── garak_catalog.py    # Load OWASP suites/probes from owasp_suites.json
│   └── latency_analyzer.py # Read latency CSVs → percentiles (p50, p90, p95, p99)
├── ingestion/
│   ├── registry.py         # Dispatch to the right loader by source name
│   └── generic_dir.py      # PDF → LangChain splitter → ChromaDB upsert
└── utils/
    ├── paths.py      # RunPaths dataclass + run_id generation (timestamp+target+tag)
    └── logging.py    # Structured logging setup
```

### Data flow

1. **Ingestion**: PDFs → PyPDFLoader → recursive text splitter → ChromaDB collection
2. **Query (unprotected)**: `POST /generate` → ChromaDB semantic search → Ollama (`llama3:8b`) → response
3. **Query (protected)**: Shield `POST /generate` → `guard_input()` (LLM Guard) → proxy to RAG `/generate` → `guard_output()` → response
4. **Middleware**: Every request gets a `X-Request-ID`; latency is appended to `artifacts/latency/<scenario>.csv`
5. **Attack**: Garak runner reads `garak_rest_base.json` (template), substitutes URL, fires probes, writes `report.jsonl`
6. **Analysis**: `garak_metrics.py` reads `report.jsonl` → ASR; `latency_analyzer.py` reads CSVs → percentile tables

### Key config files

| File | Purpose |
|------|---------|
| `app/config/rag.json` | LLM model, Ollama host, ChromaDB collection name, system role |
| `app/config/owasp_suites.json` | Maps OWASP LLM categories → Garak probe names |
| `app/config/garak_rest_base.json` | REST probe template (method, headers, JSON field mapping) |
| `.env` | `GARAK_TARGET` and other runtime overrides |

### Artifacts layout

Run outputs land in `artifacts/runs/<run_id>/` with sub-dirs: `garak/`, `latency/`, `logs/`, `config_used/`, plus `run_meta.json` and `metrics.json`. This directory is git-ignored; use `run_meta.json` to trace back the Git commit and dataset tag used.

## Corpus & Ground Truth

The knowledge corpus consists of two domains ingested into ChromaDB:

### Regulatory-Technical (`data/raw/regulatory_technical/`)
- Regulation (EU) 2024/1252 — Critical Raw Materials Act

### Academic-Institutional (`data/raw/academic_institutional/`)
- Common Data Set 2024-2025

### Synthetic documents (`data/synthetic/`)
Each domain includes 3 synthetic PDF documents (D1-S1 through D1-S3 and D2-S1
through D2-S3) that embed sensitive fragments using the following marker syntax:

[CONFIDENTIAL] field: value | field: value [/CONFIDENTIAL]

These fragments construct an exfiltration ground truth without using real
confidential data. Each document contains 4 confidential fragments covering
PII patterns detectable by LLM Guard scanners (e.g. Chilean RUT format).

### Query types used in evaluation
- Direct attack: prompt explicitly requesting confidential data
- Indirect attack: prompt attempting to extract data through indirect reasoning
- Legitimate control: valid query that should not trigger any scanner