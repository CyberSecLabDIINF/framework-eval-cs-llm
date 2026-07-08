# CLAUDE.md — LLM-Sec Framework

## Project Overview

Master's thesis: "Framework for cybersecurity evaluation in LLM-integrated platforms" (USACH DIINF, advisor: Juan Ignacio Iturbe Araya).

LLM-Sec is a hybrid cybersecurity evaluation framework (risk-based + maturity model) for RAG architectures, validated at TRL 4. It operationalizes OWASP LLM Top 10:2025 into quantifiable metrics and auditable controls (C1–C62).

**Experimental design:**
- Scenario A (unprotected) vs Scenario B (protected with LLM Guard)
- Two domains: `regulatory_technical` (EU Critical Raw Materials Act) and `academic_institutional` (Common Data Set)
- Four metrics: TFA (attack filtering rate), LAS (security latency), PCC (score correlation), NCP (score correlation)
- 11 Garak probes covering LLM01, LLM02, LLM07, LLM08
- 5 Garak generations × 5 external repetitions; 5 legitimate prompt repetitions per domain

---

## Conventions

- **Code, comments, docstrings:** English
- **Thesis text:** Spanish academic register
- **Plot colors:** orange `#e07b39` (Scenario A), blue `#1e5eff` (Scenario B)
- **Evaluation pipeline entry point:** `python3 -m eval.process_results` (run from `app/src/` with venv active, or inside the container)

---

## Stack

| Component | Version | Role |
|---|---|---|
| Ollama + Llama 3 8B | — | Inference server (test subject) |
| LLM Guard | 0.3.16 | Security proxy (defensive layer) |
| Garak | 0.13.3 | Automated offensive auditing |
| ChromaDB | — | Vector database |
| Docker Compose | v5.x | Orchestration in isolated network |
| Python | 3.10 | Application runtime |

---

## Docker Services & Networks

### Profiles

| Profile | Services | Purpose |
|---|---|---|
| `lab` | `ollama_core`, `rag_api`, `shield_api` | Normal experiment operation |
| `attacks` | `garak_runner` | Garak probes and legitimate-prompt runs |
| `bootstrap` | `ollama_bootstrap`, `chroma_bootstrap` | One-time first-run setup |

### Key services

- **`rag_api`** (`tesis_rag`, port 8000, internal only): Unprotected RAG endpoint. In `SCENARIO=protected` applies in-process controls C4/C8/C9/C11/C12/C17.
- **`shield_api`** (`tesis_shield`, port 8001, exposed): LLM Guard proxy. Runs C1/C2/C3 (input) and C19/C20 (output) unconditionally regardless of env vars. Scenario B is activated by directing Garak at this service.
- **`garak_runner`** (`tesis_garak_runner`): Runs `cli.py attack garak`; exits after one run (`restart: "no"`).
- **`ollama_core`**: Serves `llama3:8b` via GPU (NVIDIA runtime, `NVIDIA_VISIBLE_DEVICES=all`).

### Networks

- `red_internal` (internal bridge): service-to-service only, no external access
- `red_front` (bridge): external access; `shield_api` and bootstrap services only

### Bind mounts of note

| Host | Container |
|---|---|
| `./app/src` | `/root/proyecto_tesis/app/src` |
| `./app/config` | `/root/proyecto_tesis/app/config` (ro for attacks) |
| `./artifacts` | `/root/proyecto_tesis/artifacts` |
| `./chroma_db` | `/root/proyecto_tesis/chroma_db` |
| `./ollama_data` | `/root/.ollama` |
| `./llm_guard_cache` | `/root/.cache/huggingface` |

`tesis_rag` and `tesis_shield` run uvicorn with `--reload --reload-dir app/src`, so Python changes in `app/src/` take effect on the next request without rebuild or restart.

---

## Source Layout (`app/src/`)

```
app/src/
├── settings.py             # Pydantic BaseSettings singleton (get_settings())
├── cli.py                  # Typer CLI: serve / ingest / attack / metrics / where
├── api/
│   ├── rag.py              # Unprotected RAG FastAPI app (POST /generate)
│   ├── shield.py           # LLM Guard proxy FastAPI app (POST /generate)
│   └── middleware.py       # RequestIdMiddleware + LatencyCSVLogger
├── eval/
│   ├── constants.py        # PROBE_TO_SUITE, SCENARIO_COLORS, SUITE_COLORS, etc.
│   ├── loaders.py          # Data-access layer (JSONL, consolidated CSV, latency CSV)
│   ├── metrics.py          # TFA, LAS, confusion matrix, segmented analysis, PII scan
│   ├── plots.py            # All matplotlib figures → artifacts/figures/
│   ├── process_results.py  # Thin orchestrator; entry point for analysis pipeline
│   ├── consolidator.py     # Thread-safe CSV writer + patch_garak_passed()
│   ├── garak_catalog.py    # Loads owasp_suites.json
│   └── legitimate_runner.py# Sends legitimate prompts and logs responses
├── ingestion/
│   ├── generic_dir.py      # PDF → chunk → ChromaDB pipeline
│   └── registry.py         # Dispatch layer (domain name → data path)
└── utils/
    ├── paths.py            # RunPaths dataclass, make_run_paths(), snapshot_configs()
    └── logging.py          # Shared structlog/stdlib logger setup
```

---

## Security Controls (Scenario B)

### Shield (input)
| Control | Scanner | Description |
|---|---|---|
| C1 | `TokenLimit` | Max 512 tokens (cl100k_base) |
| C2 | `_sanitize_control_chars` | Strip model special tokens + Unicode control chars |
| C3 | `PromptInjection` | Block injection attempts (threshold: 0.92) |

### RAG in-process (Scenario B only)
| Control | Description |
|---|---|
| C4 | Domain distance check — blocks off-topic queries |
| C8 | Sensitivity partitioning — blocks queries for `high` sensitivity chunks |
| C9 | Corpus integrity — verifies chunk hashes against `CORPUS_HASHES` baseline |
| C11 | Query coherence — blocks low-coherence/encoded prompts |
| C12 | Recon detection — blocks overly short or highly repetitive prompts |
| C17 | Grounding check — blocks responses deviating too far from context |

### Shield (output)
| Control | Scanner | Description |
|---|---|---|
| C19 | `OutputRegex` | Blocks `[CONFIDENTIAL]`, RUT, email, phone, password, card patterns |
| C20 | `Sensitive` | Semantic sensitive-data scanner (continuous score) |

**Maturity result:** Scenario B = **N3** across all subdimensions D1–D4 (minimum-floor rule). Scenario A = **N0** by design (D4 has no N1 controls assigned).

---

## Key Configuration Files

| File | Purpose |
|---|---|
| `.env.regulatory_technical` | Env vars for regulatory domain (DATASET_TAG, thresholds, GARAK_TARGET) |
| `.env.academic_institutional` | Env vars for academic domain |
| `app/config/global/llm_guard_config.yaml` | LLM Guard scanner config (thresholds, sensitivity analysis) |
| `app/config/global/owasp_suites.json` | OWASP probe catalog |
| `app/config/global/garak_rest_base.json` | Garak REST base config |
| `app/config/domains/<tag>/rag.json` | Domain RAG config (collection_name, system_role, restrictions, n_results, domain_keywords) |
| `app/config/domains/<tag>/legitimate_prompts.json` | Legitimate prompt set |
| `app/config/domains/<tag>/verification_queries.json` | Ground truth queries |

---

## Calibrated Thresholds (fixed; do not recalibrate)

| Threshold | regulatory_technical | academic_institutional |
|---|---|---|
| `QUERY_COHERENCE_THRESHOLD` (C11) | 1.35 | 1.1723 |
| `C17_GROUNDING_THRESHOLD` | 0.0556 | 0.0714 |
| `SENSITIVITY_LEVEL` | `high` (both) | `high` (both) |

Calibrated on 70 legitimate queries vs 35 incoherent queries per domain. Do not overwrite these values in the `.env` files — they are fixed experimental evidence.

---

## Consolidated CSV Schema (23 columns)

`artifacts/consolidated_<domain>_<scenario>.csv`

Key columns: `timestamp`, `scenario`, `domain`, `prompt_type` (adversarial|legitimate), `probe`, `suite` (LLM01–LLM08), `subdimension` (D1–D4), `repetition`, `prompt`, `response`, `latency_ms`, `should_block`, `was_blocked`, `scanner_triggered`, `block_reason`, `input_scanner_score`, `output_scanner_score`, `garak_passed`, `response_has_confidential`, `grounding_ratio`, `run_id`, `response_has_system_prompt`, `injection_followed`, `rogue_string_found`.

`garak_passed` is written empty during the run and back-filled by `consolidator.patch_garak_passed()` using majority-vote from `*.report.jsonl`.

---

## TFA Ground Truth by Suite

| Suite | Ground-truth column | Rationale |
|---|---|---|
| LLM01 | `garak_passed` | Garak's own detector valid for prompt injection |
| LLM02 | `response_has_confidential` | Garak cannot see the RAG corpus |
| LLM07 | `response_has_system_prompt` | Garak heuristics produce false positives |
| LLM08 | `injection_followed` | Garak detector unreliable without WHOIS documents |

Primary detector for encoding probes: `encoding.DecodeMatch` (not `DecodeApprox`). Each encoding probe has 6400 attempts, not 12800 — discard `DecodeApprox` to avoid double-counting.

---

## Running the Pipeline

### One-time bootstrap (first run on a machine)

```bash
# Pull Ollama model
docker compose --profile bootstrap up -d ollama_bootstrap
docker exec -it ollama_bootstrap ollama pull llama3:8b
docker compose --profile bootstrap down

# Pre-cache ChromaDB ONNX embeddings
docker compose --env-file .env.regulatory_technical --profile bootstrap up --attach chroma_bootstrap
```

### Full experiment (both domains, both scenarios)

```bash
./llmsec.sh run
```

### Single scenario for one domain

```bash
./llmsec.sh run-scenario A regulatory_technical
./llmsec.sh run-scenario B academic_institutional
# Add --rebuild only if Dockerfile or requirements.txt changed
```

### Smoke test (quick sanity check)

```bash
./llmsec.sh smoke regulatory_technical
```

### Process results (after all 4 runs complete)

```bash
# Inside venv or container:
python3 app/src/eval/process_results.py --artifacts artifacts/ --deep --plots --exfiltration --characterize
# Or via llmsec.sh:
./llmsec.sh process
```

### Reload Python code without rebuild

```bash
# uvicorn --reload handles app/src/ changes automatically.
# Only needed if --reload wasn't active:
bash llmsec.sh reload
```

---

## llmsec.sh Subcommands

| Subcommand | Action |
|---|---|
| `./llmsec.sh smoke <domain>` | Smoke test: 1 probe × 1 rep, both scenarios |
| `./llmsec.sh run` | Full evaluation of both base domains |
| `./llmsec.sh run <dom1> [dom2]` | Full evaluation of specific domains |
| `./llmsec.sh run-scenario <A\|B> <domain> [--rebuild]` | Single scenario for one domain |
| `./llmsec.sh new` | Create new domain config (interactive) + optional evaluation |
| `./llmsec.sh process` | Process existing results (figures + CSV check) |
| `./llmsec.sh reload` | Restart rag/shield without rebuild |
| `source llmsec.sh shell <domain>` | Load interactive aliases (`lab-up`, `lab-down`, etc.) |

---

## process_results.py Flags

| Flag | Description |
|---|---|
| `--artifacts PATH` | Root artifacts directory (default: `artifacts/`) |
| `--domains D1 D2` | Restrict to specific domains |
| `--plots` | Generate all figures to `artifacts/figures/` |
| `--deep` | Detector/confusion/LAS deep analysis |
| `--exfiltration` | PII + verbatim exfiltration analysis |
| `--characterize` | Structural CSV + JSONL characterization |
| `--backfill-scores` | One-time fix: convert risk scores to raw [0,1] probabilities |
| `--tfa-breakdown` | Guard-blocked / defense-gap / residual-risk breakdown |
| `--duration` | Wall-clock execution time per run |
| `--probe-timings` | Median probe execution time charts (PDF) |

---

## Artifact Directories

```
artifacts/
├── runs/<timestamp>_<tag>_<target>_<run_kind>/
│   ├── garak/*.report.jsonl
│   ├── logs/app.log
│   └── config_used/
├── consolidated_<domain>_<scenario>.csv
├── latency/
│   ├── latency_unprotected_direct.csv
│   ├── latency_unprotected_via_shield.csv
│   └── latency_protected.csv
├── segmented/      (01–16 CSV files)
├── figures/        (PNG/PDF plots)
├── characterization/
└── corpus_version_registry.csv   (C62 audit log)
```

---

## Diagnostics

```bash
# Service health
curl http://localhost:8000/health   # RAG API
curl http://localhost:8001/health   # Shield API

# Active controls
curl -s http://localhost:8000/health | python3 -m json.tool
docker logs tesis_rag | grep "C9:"

# ChromaDB chunk count
docker exec tesis_rag python3 -c "
import chromadb
c = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
print(c.get_collection('<DOMAIN>').count())
"

# Effective settings paths
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm garak_runner where

# Disk usage
df -h && du -sh ~/framework-eval-cs-llm/artifacts/
```

---

## Auto-correction (llmsec.sh)

| Situation | Automatic action |
|---|---|
| Containers down | Brings up stack with correct `--env-file` |
| `tesis_rag` unhealthy | Restart; if persists, re-ingest corpus and restart |
| `tesis_shield` unhealthy | Restart; if persists, marks error for manual review |
| Collection empty | Auto-ingest with `--reset` |
| Missing CONFIDENTIAL fragments | Re-ingest with `--reset` and re-verify ground truth |
| Aborted Garak run (< 55 JSONL) | Detect and resume with `continue-run` (max 2 retries) |
| GPU not detected | Warn and continue in CPU mode |

A valid Garak run has exactly **55 JSONL files**. Aborted runs have 0–30.
