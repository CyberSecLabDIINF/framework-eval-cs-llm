# Architecture Reference

This document describes each module in `app/src/`, the Docker Compose services, and how they interact. It reflects the state of the codebase as of the last update.

---

## Table of Contents

1. [settings.py](#1-settingspy)
2. [cli.py](#2-clipy)
3. [api/rag.py](#3-apiragpy)
4. [api/shield.py](#4-apishieldpy)
5. [api/middleware.py](#5-apimiddlewarepy)
6. [eval/consolidator.py](#6-evalconsolidatorpy)
7. [eval/process_results.py](#7-evalprocess_resultspy)
8. [eval/garak_catalog.py](#8-evalgarak_catalogpy)
9. [eval/legitimate_runner.py](#9-evallegitimate_runnerpy)
10. [ingestion/generic_dir.py](#10-ingestiongeneric_dirpy)
11. [ingestion/registry.py](#11-ingestionregistrypy)
12. [utils/paths.py](#12-utilspathspy)
13. [utils/logging.py](#13-utilsloggingpy)
14. [docker-compose.yml](#14-docker-composeyml)

---

## 1. `settings.py`

**Purpose.** Single source of truth for all runtime configuration. Extends Pydantic `BaseSettings` to load values from environment variables (highest priority) and an optional `.env` file. All path-derived fields (`app_dir`, `data_dir`, `artifacts_dir`, `runs_dir`, `latency_dir`, `config_dir`, etc.) and all endpoint URLs (`rag_url`, `shield_url`, `*_generate_url`, `*_health_url`) are computed in `model_post_init` from a single `project_root`. The singleton `get_settings()` (cached via `lru_cache`) also calls `ensure_dirs()` on first access, so artifact directories always exist before any other module runs.

**Key classes / functions.**

| Name | Description |
|---|---|
| `Settings` | Pydantic `BaseSettings` with all config fields and derived paths. |
| `Settings.model_post_init()` | Derives all path and URL fields from `project_root`, `rag_port`, `shield_port`. |
| `Settings.ensure_dirs()` | Creates `artifacts_dir`, `runs_dir`, `data_dir`, `latency_dir` if absent. |
| `Settings.get_rag_config_path(tag)` | Returns `config/domains/<tag>/rag.json`. |
| `Settings.get_legitimate_prompts_path(tag)` | Returns `config/domains/<tag>/legitimate_prompts.json`. |
| `Settings.get_verification_queries_path(tag)` | Returns `config/domains/<tag>/verification_queries.json`. |
| `Settings.target_generate_url(target)` | Returns the correct `/generate` URL for `"unprotected"` or `"protected"`. |
| `Settings.target_health_url(target)` | Returns the correct `/health` URL for the active scenario. |
| `get_settings()` | `@lru_cache(maxsize=1)` factory; returns the shared singleton `Settings`. |

**Environment variables read.** All fields map directly from env vars (Pydantic convention: upper-cased field name). Notable ones: `PROJECT_ROOT`, `APP_DIR`, `DATA_DIR`, `ARTIFACTS_DIR`, `CONFIG_DIR`, `RUNS_DIR`, `GARAK_RUNS_DIR`, `CHROMA_DB_PATH`, `RAG_PORT`, `SHIELD_PORT`, `RAG_BASE_URL`, `SHIELD_BASE_URL`, `TARGET`, `DATASET_TAG`.

**Files read/written.** Reads `.env` (optional). Writes nothing directly; `ensure_dirs()` creates directories.

**Dependencies.** No internal module dependencies.

---

## 2. `cli.py`

**Purpose.** Typer CLI that groups all experiment operations under one entry point (`python3 -m cli`). Subcommand groups: `serve` (start API servers), `ingest` (PDF ingestion and verification), `attack` (Garak probes and legitimate-prompt runs), `metrics` (TFA/LAS computation), and `where` (path debugging). The `attack garak` and `attack legitimate` commands set `RUN_ID` as an environment variable so that `consolidator.py` can tag every CSV row with the correct run identifier in real time.

**Key functions.**

| Name | Description |
|---|---|
| `serve_rag()` / `serve_shield()` | Launch uvicorn for `api.rag:app` or `api.shield:app`. |
| `run_garak()` | Build Garak config, invoke Garak subprocess, call `patch_garak_passed()`, log `run_meta.json`. Sets `os.environ["RUN_ID"]`. |
| `continue_run()` | Resume an interrupted Garak run from an existing run directory. |
| `run_legitimate()` | Send legitimate prompts via `legitimate_runner`; sets `os.environ["RUN_ID"]`. |
| `ingest_source()` | Dispatch to `ingestion.registry.run_source()`. |
| `verify_ingest()` | Run verification queries against ChromaDB. |
| `patch_garak()` | Call `consolidator.patch_garak_passed()` on an existing CSV/garak-dir pair. |
| `process_metrics()` | Invoke `eval.process_results` for TFA, LAS, deep analysis, and optional plots. |
| `where()` | Print all effective `Settings` paths for debugging. |
| `_check_health()` | Poll a health endpoint with retries before starting an experiment. |
| `_run_subprocess()` | Wrapper around `subprocess.run` with environment injection and logging. |
| `snapshot_configs()` | Delegates to `utils.paths.snapshot_configs`; copies config files + writes `run_meta.json`. |

**Environment variables read.** Reads all `Settings` fields. Also reads/writes `RUN_ID`, `RUN_KIND`, `REST_API_KEY`, `GARAK_TARGET`.

**Files read/written.**
- Reads: `owasp_suites.json`, `garak_rest_base.json`, `config/domains/<tag>/rag.json`, `legitimate_prompts.json`
- Writes: `artifacts/runs/<run_id>/run_meta.json`, `artifacts/runs/<run_id>/garak/*.report.jsonl` (via Garak subprocess), `artifacts/consolidated_<tag>_<scenario>.csv` (via consolidator)

**Dependencies.** `settings`, `utils.paths`, `ingestion.registry`, `eval.consolidator`, `eval.legitimate_runner`, `eval.process_results`, `eval.garak_catalog`.

---

## 3. `api/rag.py`

**Purpose.** FastAPI application serving the unprotected RAG endpoint (`POST /generate`). Retrieves semantically relevant context from ChromaDB, constructs a prompt, and queries Ollama (`llama3:8b`). When `IS_PROTECTED=True` (i.e. `SCENARIO=protected`), also applies six in-process defence controls (C4, C8, C9, C11, C12, C17) before returning a response. These controls are bypassed when the request was already filtered by Shield (`x-forwarded-by: shield` header), preventing double-logging.

**Key functions / classes.**

| Name | Description |
|---|---|
| `Query` | Pydantic model: `prompt: str`. Request body for `/generate`. |
| `_blocked_response()` | Logs a blocked request via `log_request()` and returns `{"response": message}`. |
| `generate()` | Main endpoint. Applies controls C4/C8/C9/C11/C12/C17 (when `IS_PROTECTED`), retrieves ChromaDB context, calls Ollama, logs to consolidated CSV. |
| `health()` | Returns service status and ChromaDB collection count. |

**Controls applied (when `IS_PROTECTED=True`).**

| Control | Description |
|---|---|
| C4 | Domain distance check — blocks off-topic queries. |
| C8 | Sensitivity partitioning — blocks queries for `high` sensitivity chunks. |
| C9 | Corpus integrity — blocks prompts whose hash is not in `CORPUS_HASHES`. |
| C11 | Query coherence — blocks low-coherence prompts. |
| C12 | Recon detection — blocks overly short or highly repetitive prompts. |
| C17 | Grounding check — blocks responses whose content deviates too far from context. |

**Environment variables read.** `SCENARIO`, `DATASET_TAG`, `CONSOLIDATED_CSV`, `RUN_KIND`, `OLLAMA_HOST`, `LATENCY_CSV_DIRECT`, `LATENCY_CSV_VIA_SHIELD`, `DOMAIN_DISTANCE_THRESHOLD`, `QUERY_COHERENCE_THRESHOLD`, `C17_GROUNDING_THRESHOLD`, `SENSITIVITY_LEVEL`, `CHROMA_PATH`, plus all `Settings` fields via `get_settings()`.

**Files read/written.**
- Reads: `config/domains/<tag>/rag.json`, ChromaDB collection at `CHROMA_PATH`.
- Writes: `artifacts/latency/latency_unprotected_direct.csv`, `artifacts/latency/latency_unprotected_via_shield.csv`, `artifacts/consolidated_<tag>_<scenario>.csv`.

**Dependencies.** `settings`, `api.middleware`, `eval.consolidator`.

---

## 4. `api/shield.py`

**Purpose.** FastAPI proxy that wraps the RAG with LLM Guard input and output scanning. Every `/generate` request passes through `guard_input()` (controls C1/C2/C3) before being forwarded to the upstream RAG, then the RAG response passes through `guard_output()` (controls C19/C20) before being returned to the caller. All outcomes — blocked or passed — are written to the consolidated CSV via `consolidator.log_request()`.

**Key functions / classes.**

| Name | Description |
|---|---|
| `Query` | Pydantic model: `prompt: str`. |
| `_sanitize_control_chars()` | C2 — strips model special tokens (`<\|…\|>`) and Unicode control characters. |
| `guard_input()` | Applies C2 (sanitize), C1 (TokenLimit), C3 (PromptInjection) in sequence. Returns `(sanitized, None, score)` on pass or `(None, scanner_name, score)` on block. |
| `guard_output()` | Applies C20 (Sensitive, semantic) then C19 (OutputRegex, deterministic). Returns `(text, None, score)` on pass or `(blocked_msg, scanner_name, score)` on block. |
| `generate()` | Orchestrates guard_input → proxy to RAG → guard_output → log_request. |
| `health()` | Returns Shield status and upstream RAG reachability. |
| `_load_llm_guard_config()` | Reads `llm_guard_config.yaml`; returns `{}` if absent. |

**Scanner controls.**

| Control | Scanner | Phase |
|---|---|---|
| C1 | `TokenLimit` | Input |
| C2 | `_sanitize_control_chars` | Input (pre-scan) |
| C3 | `PromptInjection` | Input |
| C19 | `OutputRegex` | Output |
| C20 | `Sensitive` | Output |

**Environment variables read.** `SCENARIO`, `DATASET_TAG`, `CONSOLIDATED_CSV`, `RUN_KIND`, `ENABLE_LLM_GUARD`, `RAG_BASE_URL`, `UPSTREAM_TIMEOUT_S`, plus all `Settings` fields.

**Files read/written.**
- Reads: `app/config/global/llm_guard_config.yaml`.
- Writes: `artifacts/latency/latency_protected.csv`, `artifacts/consolidated_<tag>_protected.csv`, `artifacts/llm_guard.log`.

**Dependencies.** `settings`, `api.middleware`, `eval.consolidator`, `llm_guard`.

---

## 5. `api/middleware.py`

**Purpose.** Two ASGI middlewares used by both RAG and Shield applications. `RequestIdMiddleware` injects a `X-Request-ID` UUID into every request/response for traceability. `LatencyCSVLogger` records per-request latency, endpoint, and metadata to a CSV file; it supports header-based routing so the same service can write to two different CSVs depending on whether the request originated from Shield (`x-forwarded-by: shield`) or directly from a client.

**Key classes.**

| Name | Description |
|---|---|
| `RequestIdMiddleware` | Injects UUID `X-Request-ID` header on every request/response. |
| `LatencyCSVLogger` | Appends one CSV row per request with: timestamp, scenario, domain, method, endpoint, status_code, latency_ms, request_id, suite_probe, prompt_tokens, response_tokens. |
| `LatencyCSVLogger.__init__()` | Accepts `only_if_header` / `skip_if_header` filters to route direct vs. via-shield traffic. |
| `LatencyCSVLogger.dispatch()` | Measures wall-clock latency, enforces header filters, appends to CSV. |

**Environment variables read.** None directly; values injected via constructor arguments by `rag.py` and `shield.py`.

**Files read/written.** Appends to whichever CSV path is passed in `csv_path`.

**Dependencies.** Standard library only (`csv`, `uuid`, `time`). No internal module imports.

---

## 6. `eval/consolidator.py`

**Purpose.** Thread-safe CSV writer providing the single append path (`log_request`) for all `/generate` responses — both from `rag.py` and `shield.py`. Also provides `patch_garak_passed()`, which back-fills the `garak_passed` column by parsing Garak's `*.report.jsonl` after an attack run completes. The consolidated CSV is the primary input for all downstream analysis.

**CSV schema (`COLUMNS`).**

```
timestamp, scenario, domain, prompt_type, probe, suite, subdimension, repetition,
prompt, response, latency_ms, should_block, was_blocked, scanner_triggered,
block_reason, input_scanner_score, output_scanner_score, garak_passed,
response_has_confidential, run_id
```

**Key functions.**

| Name | Description |
|---|---|
| `log_request()` | Appends one row per request. `garak_passed` is left empty and filled by `patch_garak_passed()`. Thread-safe via `_csv_lock`. |
| `patch_garak_passed()` | Reads `*.report.jsonl`, aggregates pass/total per probe (primary detector only), majority-vote fills `garak_passed` (1 if pass_rate ≥ 0.5). Returns count of rows updated. |
| `_parse_garak_tag()` | Splits `"SUITE\|probe.Name"` into `(suite, probe, subdimension)`. |
| `_ensure_header()` | Creates the CSV with the header row if it is absent or empty. |

**Key constants.**
- `SUITE_TO_SUBDIM`: `{"LLM01": "D1", "LLM02": "D2", "LLM07": "D3", "LLM08": "D4"}`
- `PRIMARY_DETECTOR`: `{"encoding.InjectBase64": "encoding.DecodeMatch", "encoding.InjectHex": "encoding.DecodeMatch"}`

**Environment variables read.** `RUN_ID` (via `os.getenv("RUN_ID", "")` inside `log_request()`).

**Files read/written.** Reads and appends to the consolidated CSV at the path provided by callers. `patch_garak_passed()` reads `*.report.jsonl` from a garak directory and rewrites the CSV in place.

**Dependencies.** Standard library only (`csv`, `json`, `os`, `threading`, `datetime`, `pathlib`).

---

## 7. `eval/process_results.py`

**Purpose.** Standalone analysis script (also callable from `cli.py metrics process`) that computes the two primary evaluation metrics — TFA (Total Filtering Accuracy) and LAS (Latency Added by Shield) — plus deep-analysis tables and optional figures. Reads Garak JSONL reports and the consolidated CSV; outputs terminal tables, `metrics.json`, and matplotlib figures.

**Key functions.**

| Name | Description |
|---|---|
| `load_tfa_from_jsonl(garak_dir)` | Parses `*.report.jsonl`, aggregates pass/total per probe and suite, returns `{per_probe, per_suite, global}` with TFA values. |
| `load_consolidated(artifacts_dir, domain, scenario, run_id)` | Loads consolidated CSV, adversarial rows only, optionally filtered by `run_id`. |
| `load_latency(latency_dir, filename)` | Loads a latency CSV, retaining only `/generate` endpoint rows. |
| `find_run_dir(runs_dir, domain, scenario)` | Returns the most recent run directory matching domain and scenario. |
| `discover_domains(runs_dir)` | Auto-discovers domain names from existing run directories. |
| `print_tfa(tfa_a, tfa_b, domain)` | Prints a terminal table comparing TFA A vs. B with Fisher exact p-values. |
| `compute_las(lat_a, lat_b)` | Prints LAS summary: Δmedian latency and Mann-Whitney U test result. |
| `deep_analysis_tfa/las/confusion/detector` | Detailed per-suite or per-scenario breakdowns. |
| `plot_tfa_by_probe()` | Grouped bar chart of TFA per probe. |
| `plot_tfa_by_suite()` | Grouped bar chart of TFA per OWASP suite. |
| `plot_tfa_domains_combined()` | Heatmap combining both domains. |
| `plot_delta_tfa()` | ΔTFA bar chart (B − A) with significance markers. |
| `plot_las_by_suite()` | Box plot of latency distributions per suite. |

**Key constants.** `PROBE_TO_SUITE`, `PROBE_SHORT`, `VECTOR_MAP`, `SUITE_COLORS`, `PRIMARY_DETECTOR`, `SUITE_TO_SUBDIM`.

**Environment variables read.** None at module level; all paths supplied via CLI args or the `cli.py` caller.

**Files read.**
- `artifacts/runs/<run_dir>/garak/*.report.jsonl`
- `artifacts/consolidated_<domain>_<scenario>.csv`
- `artifacts/latency/latency_unprotected_direct.csv`
- `artifacts/latency/latency_protected.csv`

**Files written.** `artifacts/runs/<run_dir>/metrics.json`, optional PNG figures to `artifacts/runs/<run_dir>/`.

**Dependencies.** `pandas`, `scipy`, `matplotlib`. No internal module imports.

---

## 8. `eval/garak_catalog.py`

**Purpose.** Loads and queries the OWASP probe catalog from `owasp_suites.json`. Used by `cli.py` to resolve suite/probe names before invoking Garak.

**Key functions.**

| Name | Description |
|---|---|
| `load_suites(path)` | Parses `owasp_suites.json` into a dict keyed by suite ID. |
| `list_suites(path)` | Returns suite IDs and descriptions. |
| `list_probes(path, suite)` | Returns probe names for a given suite. |

**Environment variables read.** None.

**Files read.** `app/config/global/owasp_suites.json`.

**Dependencies.** Standard library only (`json`, `pathlib`).

---

## 9. `eval/legitimate_runner.py`

**Purpose.** Sends legitimate prompts from `legitimate_prompts.json` to the active target endpoint and collects responses for FP/TN ground-truth data. Called by `cli.py attack legitimate`. Checks endpoint health before starting and logs every response via `consolidator.log_request()`.

**Key functions.**

| Name | Description |
|---|---|
| `run_legitimate_prompts(settings, target, csv_path, timeout_s, logger)` | Loads `legitimate_prompts.json`, health-checks the target, sends each prompt via HTTP POST, logs results to consolidated CSV. |

**Environment variables read.** All `Settings` fields (via the passed `settings` argument). `RUN_ID` (read inside `consolidator.log_request`).

**Files read.** `config/domains/<tag>/legitimate_prompts.json`.

**Files written.** `artifacts/consolidated_<tag>_<scenario>.csv` (via `consolidator.log_request`).

**Dependencies.** `settings`, `eval.consolidator`, `httpx`.

---

## 10. `ingestion/generic_dir.py`

**Purpose.** PDF ingestion pipeline. Discovers PDFs in a directory, splits them with LangChain's `RecursiveCharacterTextSplitter`, computes content-addressed stable IDs, and upserts all chunks into a ChromaDB collection. Supports idempotent re-ingestion (stable IDs survive) and optional collection reset. Also classifies each chunk's sensitivity (`high` / `medium` / `low`) based on `[CONFIDENTIAL]` markers and Chilean RUT patterns.

**Key functions.**

| Name | Description |
|---|---|
| `ingest_dir_pdfs(source, data_path, chroma_path, ...)` | Main entry point. Discovers PDFs, chunks them, upserts into ChromaDB. Returns total document count. |
| `load_and_chunk_pdf(pdf_path, splitter)` | Loads a PDF with `PyPDFLoader` and returns `[(chunk_text, metadata)]`. |
| `iter_pdfs(data_path, pattern)` | Returns a sorted list of PDF paths matching a glob pattern. |
| `_sha1_file(path)` | Returns SHA-1 hex digest of a file. Used to build stable doc IDs. |
| `_classify_sensitivity(text)` | Returns `"high"` / `"medium"` / `"low"` based on regex patterns. |
| `_safe_upsert(collection, ids, docs, metas)` | Upserts with deduplication; falls back to `add()` if `upsert()` is unavailable. |

**Doc ID format.** `{source}:{filename}:{file_sha1}:p{page}:c{chunk_index}:{chunk_sha1}` — stable across re-ingestion.

**Environment variables read.** None.

**Files read.** Source PDFs from the specified directory. **Files written.** ChromaDB persistent storage at `chroma_path`.

**Dependencies.** `chromadb`, `langchain`, `langchain_community`.

---

## 11. `ingestion/registry.py`

**Purpose.** Dispatch layer mapping logical domain names (e.g. `regulatory_technical`) to their data paths and ingestion parameters. Calls `generic_dir.ingest_dir_pdfs()` with the correct arguments for each registered domain.

**Key functions.**

| Name | Description |
|---|---|
| `run_source(source, settings, reset)` | Resolves the data path and chroma path for `source`, delegates to `ingest_dir_pdfs()`, returns total chunk count. |

**Environment variables read.** All `Settings` fields (via the passed `settings` argument).

**Files read.** PDFs under `data/raw/<domain>/` and `data/synthetic/<domain>/`. **Files written.** ChromaDB persistent storage.

**Dependencies.** `settings`, `ingestion.generic_dir`.

---

## 12. `utils/paths.py`

**Purpose.** Defines the `RunPaths` frozen dataclass and helper functions for creating and reconstructing run directory layouts. Also captures run reproducibility metadata (`run_meta.json`) and copies the active config files into each run's `config_used/` directory.

**Key classes / functions.**

| Name | Description |
|---|---|
| `RunPaths` | Frozen dataclass: `run_dir`, `logs_dir`, `config_used_dir`, `garak_dir`, `summary_md`, `metrics_json`. |
| `make_run_paths(settings, target, run_id, run_kind)` | Creates the run directory layout under `settings.runs_dir`. Naming: `<ts>_<tag>_<target>_<run_kind>`. Returns a populated `RunPaths`. |
| `run_paths_from_existing(run_dir)` | Reconstructs `RunPaths` from an existing directory (used by `analyze compare`). |
| `snapshot_configs(settings, run_paths, ...)` | Copies `rag.json`, `owasp_suites.json`, `garak_rest_base.json` to `config_used/`; writes `run_meta.json` with all settings and the current git commit hash. |
| `utc_run_id(prefix)` | Returns `YYYYMMDD_HHMMSS[_prefix]`. |

**Environment variables read.** None directly; all config via the passed `Settings` instance.

**Files read.** Config files listed above. **Files written.** `artifacts/runs/<run_id>/run_meta.json`, `artifacts/runs/<run_id>/config_used/*`.

**Dependencies.** `settings`.

---

## 13. `utils/logging.py`

**Purpose.** Configures a shared structlog/stdlib logger used across CLI commands and API servers. Clears existing handlers on repeated calls (idempotent).

**Key functions.**

| Name | Description |
|---|---|
| `setup_logging(level, log_file)` | Configures root logger with console (and optional file) handlers. Returns the configured logger. |

**Environment variables read.** None.

**Files read/written.** Optionally writes to the log file path provided.

**Dependencies.** Standard library `logging`.

---

## 14. `docker-compose.yml`

**Purpose.** Defines all services, networks, volumes, and profiles for the containerised experiment environment.

### Profiles

| Profile | Services | Use case |
|---|---|---|
| `lab` | `ollama_core`, `rag_api`, `shield_api` | Normal experiment operation |
| `attacks` | `garak_runner` | Launching Garak probes or legitimate-prompt runs |
| `bootstrap` | `ollama_bootstrap`, `chroma_bootstrap` | One-time first-run setup |

### Services

#### `rag_api` (profile: `lab`, port 8000)

- Runs `api.rag:app` via uvicorn on port 8000 (internal only).
- Creates `artifacts/latency/` and `artifacts/runs/` before starting.
- Health-checked every 10 s (12 retries) via Python `urllib`.
- **Key env vars:** `SCENARIO=unprotected`, `DATASET_TAG`, `OLLAMA_HOST=http://ollama_core:11434`, `CHROMA_PATH`, `CONSOLIDATED_CSV`, `LATENCY_CSV_DIRECT`, `LATENCY_CSV_VIA_SHIELD`.

#### `shield_api` (profile: `lab`, port 8001)

- Runs `api.shield:app` via uvicorn on port 8001 (exposed on host).
- Depends on `ollama_core` and `rag_api`.
- **Key env vars:** `SCENARIO=protected`, `ENABLE_LLM_GUARD=1`, `RAG_BASE_URL=http://rag_api:8000`, `CONSOLIDATED_CSV`, `LLM_GUARD_CONFIG_PATH`, `LLM_GUARD_LOG_FILE`.

#### `ollama_core` (profile: `lab`)

- Serves the `llama3:8b` model via Ollama REST API.
- GPU access via NVIDIA runtime (`NVIDIA_VISIBLE_DEVICES=all`).
- Model weights persisted in `./ollama_data`.

#### `garak_runner` (profile: `attacks`)

- Runs Garak probes or legitimate-prompt batches through `cli.py`.
- Default command: `attack garak --target ${GARAK_TARGET} --repetitions 5`.
- `restart: "no"` — exits after a single run.
- Mounts `artifacts/`, `app/config/` (read-only), `app/src/` (read-only), `garak_runs/`.

#### `ollama_bootstrap` / `chroma_bootstrap` (profile: `bootstrap`)

- `ollama_bootstrap`: used to pull the Ollama model into the shared volume.
- `chroma_bootstrap`: pre-caches ONNX embedding model weights for ChromaDB.

### Networks

| Network | Type | Purpose |
|---|---|---|
| `red_internal` | bridge (internal) | Isolated service-to-service communication; no external access |
| `red_front` | bridge | External access; only `shield_api` and bootstrap services attach |

### Volumes (bind mounts)

| Host path | Container path | Services |
|---|---|---|
| `./data` | `/root/proyecto_tesis/data` | rag_api, garak_runner |
| `./artifacts` | `/root/proyecto_tesis/artifacts` | rag_api, shield_api, garak_runner |
| `./chroma_db` | `/root/proyecto_tesis/chroma_db` | rag_api, shield_api, garak_runner |
| `./app/config` | `/root/proyecto_tesis/app/config` | all (read-only for attacks) |
| `./app/src` | `/root/proyecto_tesis/app/src` | all (read-only for attacks) |
| `./garak_runs` | `/root/.local/share/garak/garak_runs` | rag_api, shield_api, garak_runner |
| `./ollama_data` | `/root/.ollama` | ollama_core, ollama_bootstrap |
| `./llm_guard_cache` | `/root/.cache/huggingface` | shield_api |
| `./chroma_cache` | `/root/.cache/chroma` | rag_api, chroma_bootstrap |

---

## Data Flow Summary

```
PDFs ──► ingest_dir_pdfs() ──► ChromaDB
                                   │
         Garak / HTTP client        │
              │                     │
              ▼                     ▼
         shield_api:8001     rag_api:8000
         guard_input()   ──► /generate ──► ChromaDB query ──► Ollama
              │               (controls         │
              │               C4/C8/C9/         │
              │               C11/C12/C17)      │
              │◄──── response ──────────────────┘
         guard_output()
              │
              ▼
      consolidated_<tag>_<scenario>.csv
              │
              ▼
      process_results.py ──► TFA, LAS, figures, metrics.json
```

1. **Ingestion**: PDFs → chunked → ChromaDB via `ingestion/generic_dir.py`.
2. **Unprotected query**: `POST rag_api:8000/generate` → ChromaDB semantic search → Ollama → response.
3. **Protected query**: `POST shield_api:8001/generate` → `guard_input()` (C1/C2/C3) → proxy to `rag_api:8000/generate` → `guard_output()` (C19/C20) → response.
4. **Logging**: Every request appends one row to the consolidated CSV via `consolidator.log_request()`. The `RUN_ID` env var (set by `cli.py`) tags each row to the active run.
5. **Attack**: `garak_runner` calls `cli.py attack garak`, which sets env vars and forks a Garak subprocess; results land in `artifacts/runs/<run_id>/garak/*.report.jsonl`.
6. **Patch**: `consolidator.patch_garak_passed()` back-fills `garak_passed` by majority-voting JSONL results.
7. **Analysis**: `process_results.py` reads JSONL + consolidated CSV + latency CSVs → computes TFA/LAS → writes `metrics.json` and optional figures.
