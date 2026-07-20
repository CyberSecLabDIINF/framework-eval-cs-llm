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
7. [eval/constants.py](#7-evalconstantspy)
8. [eval/loaders.py](#8-evalloaderspy)
9. [eval/metrics.py](#9-evalmetricspy)
10. [eval/plots.py](#10-evalplotspy)
11. [eval/process_results.py](#11-evalprocess_resultspy)
12. [eval/garak_catalog.py](#12-evalgarak_catalogpy)
13. [eval/legitimate_runner.py](#13-evallegitimate_runnerpy)
14. [ingestion/generic_dir.py](#14-ingestiongeneric_dirpy)
15. [ingestion/registry.py](#15-ingestionregistrypy)
16. [utils/paths.py](#16-utilspathspy)
17. [utils/logging.py](#17-utilsloggingpy)
18. [docker-compose.yml](#18-docker-composeyml)
19. [Evaluation Pipeline — Analysis Catalog](#evaluation-pipeline--analysis-catalog)

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

**Purpose.** FastAPI application serving the unprotected RAG endpoint (`POST /generate`). Retrieves semantically relevant context from ChromaDB, constructs a prompt, and queries Ollama (`llama3:8b`). When `IS_PROTECTED=True` (i.e. `SCENARIO=protected`), also applies six in-process defence controls (C4, C8, C9, C11, C12, C17) before returning a response. Requests forwarded by Shield (`x-forwarded-by: shield` header) still go through these same `IS_PROTECTED` gated checks; only their consolidated-CSV logging is skipped, to avoid double-counting a request already logged by `shield_api`.

> **Deployment caveat.** `docker-compose.yml` sets `SCENARIO=unprotected` as a fixed, non-interpolated value on the `rag_api` service, and this is the only `rag_api` definition in the repository — it does not change between Scenario A and Scenario B runs (Scenario B only redirects Garak's target to `shield_api`, which proxies to this same `rag_api` container). Consequently `IS_PROTECTED` evaluates `False` inside `rag_api` in every deployed configuration, and the `IS_PROTECTED`-gated controls described above (C4, C8's retrieval `where_filter`, C9, C11, C12, C17's blocking branch, and C32) do not execute their blocking/filtering logic in any current experimental run, including runs labeled Scenario B. See `docs/CONTROL_AUDIT_REPORT.md` for the empirical confirmation (zero matching `block_reason` values across all four consolidated CSVs) and its implications.

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

**Environment variables read.** `SCENARIO`, `DATASET_TAG`, `CONSOLIDATED_CSV`, `RUN_KIND`, `RAG_BASE_URL`, `UPSTREAM_TIMEOUT_S`, plus all `Settings` fields. LLM Guard input/output scanning runs unconditionally and is not gated by any environment variable.

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

**CSV schema (`COLUMNS`, 23 columns).**

```
timestamp, scenario, domain, prompt_type, probe, suite, subdimension, repetition,
prompt, response, latency_ms, should_block, was_blocked, scanner_triggered,
block_reason, input_scanner_score, output_scanner_score, garak_passed,
response_has_confidential, grounding_ratio, run_id, response_has_system_prompt,
injection_followed, rogue_string_found
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

## 7. `eval/constants.py`

**Purpose.** Module of shared constants reused across the evaluation pipeline — probe/suite mappings, display labels, and colour palettes for the experiment's OWASP LLM categories. Has no behaviour of its own; it exists purely so `loaders.py`, `metrics.py`, and `plots.py` share a single source of truth for these mappings.

**Key constants.**

| Name | Description |
|---|---|
| `PRIMARY_DETECTOR` | Maps probe → primary Garak detector used for TFA (e.g. `encoding.InjectBase64` → `encoding.DecodeMatch`; discards `DecodeApprox`). |
| `PROBE_TO_SUITE` | Maps Garak probe name → OWASP LLM suite (`LLM01`, `LLM02`, `LLM07`, `LLM08`). |
| `SUITE_TO_SUBDIM` | Maps OWASP suite → LLM-Sec subdimension (`LLM01`→`D1`, `LLM02`→`D2`, `LLM07`→`D3`, `LLM08`→`D4`). |
| `VECTOR_MAP` | Maps OWASP suite → human-readable subdimension label (e.g. `"LLM01": "D1 — Input protection"`). |
| `PROBE_SHORT` | Maps probe name → short display label for plot legends/axes (e.g. `promptinject.HijackKillHumans` → `HijackKill`). |
| `SUITE_COLORS` | Hex colour palette keyed by OWASP suite, shared by all suite-coloured figures. |
| `SCENARIO_COLORS` | Hex colour palette keyed by scenario label (`"A"`, `"B"`). |

**Environment variables read.** None.

**Files read/written.** None.

**Dependencies.** No internal module dependencies.

---

## 8. `eval/loaders.py`

**Purpose.** Data-access layer for evaluation result processing. Reads Garak `*.report.jsonl` files, consolidated CSVs, and latency CSVs, and discovers run directories/domains under `artifacts/`. These functions are the single point of contact with the artifact files; `metrics.py` and `plots.py` consume them rather than reading CSVs/JSONL directly.

**Key functions.**

| Name | Description |
|---|---|
| `load_tfa_from_jsonl(garak_dir)` | Parses `*.report.jsonl`, aggregates pass/total per probe and suite (primary detector only), returns `{per_probe, per_suite, global}` with TFA values. |
| `load_consolidated(artifacts_dir, domain, scenario, run_id=None)` | Loads the consolidated CSV, adversarial rows only, optionally filtered by `run_id`; coerces numeric columns (`was_blocked`, `should_block`, `response_has_confidential`, `garak_passed`). |
| `load_latency(latency_dir, filename)` | Loads a latency CSV (no header row), keeping only `/generate` endpoint rows with a valid numeric `latency_ms`. |
| `find_run_dir(runs_dir, domain, scenario)` | Returns the most recent run directory matching `domain` and `scenario`. |
| `discover_domains(runs_dir)` | Auto-discovers domain names from existing run directory names. |
| `_load_jsonl_eval_entries(garak_dir)` | Private. Yields `(probe, detector, passed, total)` for every `entry_type == "eval"` line across `*.report.jsonl` files. |
| `_extract_suite(val)` | Private. Parses `"LLM01\|probe.name"` into `"LLM01"`; returns `"UNKNOWN"` if unparseable. |
| `_confusion_counts(adv_df, legit_df)` | Private. Returns TP/FN/FP/TN counts derived from `should_block` vs. `was_blocked` across adversarial and legitimate DataFrames. |
| `_load_consolidated_legit(artifacts_dir, domain, scenario)` | Private. Loads the consolidated CSV, legitimate rows only; coerces `response_has_confidential` to int. |

**Environment variables read.** None.

**Files read.** `artifacts/runs/<run_dir>/garak/*.report.jsonl`, `artifacts/consolidated_<domain>_<scenario>.csv`, `artifacts/latency/<filename>`.

**Files written.** None.

**Dependencies.** `eval.constants`.

---

## 9. `eval/metrics.py`

**Purpose.** Computes the experiment's evaluation metrics — TFA (Total Filtering Accuracy), LAS (Latency Added by Shield), confusion-matrix breakdowns, segmented analyses, adversarial-vs-legitimate latency comparisons, PII-exposure scans, and scanner-threshold sensitivity sweeps. Prints formatted terminal reports and exports CSVs to `artifacts/segmented/`.

**Key functions.**

| Name | Description |
|---|---|
| `print_tfa(tfa_a, tfa_b, domain)` | Prints a terminal table comparing TFA A vs. B (global, per-suite, per-probe) with Fisher exact p-values. |
| `compute_las(lat_a, lat_b)` | Prints the LAS summary: Δmedian latency and Mann-Whitney U test result. |
| `deep_analysis_tfa(df_a, df_b, domain)` | Per-suite TFA breakdown from consolidated-CSV `garak_passed`, comparing Scenario A vs. B. |
| `deep_analysis_by_detector(runs_dir, domains)` | Per-probe × detector pass-rate breakdown from JSONL reports. |
| `deep_analysis_confusion_a(artifacts_dir, domains)` / `deep_analysis_confusion(artifacts_dir, domains)` | Confusion-matrix tables (TP/FN/FP/TN) for Scenario A only, and A vs. B compared. |
| `deep_analysis_las(lat_a, lat_b)` | Per-suite latency comparison between scenarios with Mann-Whitney U tests. |
| `segmented_analysis(artifacts_dir, domains, pcc_values=None)` | Five-block segmented analysis (segment overview, per-probe/suite adversarial TFA, adversarial distributions, legitimate FPR, cross-scenario statistical tests); exports CSVs to `artifacts/segmented/`. |
| `latency_adv_vs_legit(artifacts_dir, domains)` | Compares adversarial vs. legitimate latency distributions per domain × scenario (counts/proportions, descriptive stats, Mann-Whitney U); exports `artifacts/segmented/12_latency_adv_vs_legit.csv`. |
| `analyze_pii_exposure(artifacts_dir, domains)` | Scans adversarial `response` text against `PII_PATTERNS` (`[CONFIDENTIAL]` marker, Chilean RUT, email, phone, password, card number); prints per-domain × scenario counts/percentages and returns `{domain: {scenario: {pattern_name: {"count": int, "pct": float}}}}`. |
| `analyze_sensitivity_thresholds(artifacts_dir, domains, config_dir)` | Reads candidate `PromptInjection` (input) and `Sensitive` (output) thresholds plus the active threshold index from `llm_guard_config.yaml`'s `sensitivity_analysis` block (falling back to defaults `[0.75, 0.92, 0.97]` / `[0.3, 0.5, 0.7]` with a warning if absent); reclassifies adversarial rows as blocked when `input_scanner_score` / `output_scanner_score` ≥ each candidate threshold (ignoring negative sentinel scores), prints a comparison table of reclassified TFA vs. Δ from the active threshold, and returns `{domain: {"input": {threshold: tfa}, "output": {threshold: tfa}}}`. |
| `compute_probe_timings(artifacts_dir)` | Iterates over every `*_garak` run directory under `artifacts/runs/`, sorts `*.report.jsonl` files chronologically by mtime, and assigns each file a `duration_seconds` equal to the elapsed time since the preceding file. Returns a DataFrame with columns `domain`, `scenario`, `suite`, `probe`, `repetition`, `duration_seconds` (NaN for the first file per run). |

**Key constants.** `PII_PATTERNS` (regex map consumed by `analyze_pii_exposure`); also imports `PRIMARY_DETECTOR`, `PROBE_SHORT`, `PROBE_TO_SUITE`, `VECTOR_MAP` from `eval.constants`.

**Environment variables read.** None.

**Files read.** `artifacts/consolidated_<domain>_<scenario>.csv`, `artifacts/runs/<run_dir>/garak/*.report.jsonl`, `app/config/global/llm_guard_config.yaml` (read by `analyze_sensitivity_thresholds`).

**Files written.** CSVs under `artifacts/segmented/` (e.g. `12_latency_adv_vs_legit.csv` and the `segmented_analysis` exports). `compute_probe_timings` writes nothing; its caller `plot_probe_timings` writes PDFs to `artifacts/figures/`.

**Dependencies.** `pandas`, `scipy`, `pyyaml`, `eval.constants`, `eval.loaders`.

---

## 10. `eval/plots.py`

**Purpose.** Generates all matplotlib figures for the experiment — TFA/LAS comparisons, confusion matrices, latency distributions, scanner/detector breakdowns, and segmented-analysis charts — and saves them as PNGs under `artifacts/figures/`. `generate_all_plots()` and `generate_segmented_plots()` are the two entry points invoked by `process_results.main()`.

**Key functions.**

| Name | Description |
|---|---|
| `setup_style()` | Applies the shared matplotlib rcParams style used by every figure. |
| `_save(fig, figures_dir, filename)` | Saves a figure to `figures_dir/filename`, creating the directory if absent, and prints the saved path. |
| `plot_tfa_by_probe` / `plot_tfa_by_suite` / `plot_tfa_domains_combined` / `plot_tfa_heatmap` / `plot_delta_tfa` / `plot_pvalue_by_suite` | Core TFA comparison figures (grouped bars, heatmaps, ΔTFA, significance markers). |
| `plot_confidential_exposure` / `plot_confusion_matrix` / `plot_confusion_matrix_scenario_a` / `plot_detector_heatmap` | Confidential-leak rate, confusion-matrix, and detector-breakdown figures. |
| `plot_las_boxplot` / `plot_latency_histogram` / `plot_las_by_suite` / `plot_latency_distribution_by_suite` | Latency distribution figures (box plots, histograms, per-suite breakdowns). |
| `plot_latency_adv_vs_legit_boxplot` / `plot_latency_adv_vs_legit_kde` / `plot_fpr_by_domain_scenario` / `plot_tfa_heatmap_ab_comparison` / `plot_delta_tfa_by_domain` / `plot_scanner_breakdown_by_probe` | Segmented-analysis figures added alongside `segmented_analysis()`. |
| `plot_probe_timings(df, output_dir)` | Horizontal grouped bar chart of median probe execution time per domain; one PDF per domain saved to `output_dir`. Bars colored by scenario (`#e07b39` = A, `#1e5eff` = B), error bars show IQR over 5 repetitions, probes ordered by OWASP suite. Invoked via `--probe-timings`. |
| `generate_all_plots(tfa_by_domain, lat_a, lat_b, artifacts_dir, runs_dir, figures_dir)` | Orchestrates the core figure set (TFA, LAS, confusion, detector breakdowns). |
| `generate_segmented_plots(artifacts_dir, domains, tfa_by_domain, figures_dir)` | Orchestrates the six segmented-analysis figures; each `plot_*` prints `[skip]` and returns cleanly when its required data is absent. |

**Environment variables read.** None.

**Files read.** `artifacts/consolidated_<domain>_<scenario>.csv`, `artifacts/runs/<run_dir>/garak/*.report.jsonl`, latency DataFrames passed in by the caller.

**Files written.** PNG figures under `artifacts/figures/`; `plot_probe_timings` writes PDF files (`probe_timings_<domain>.pdf`) to the same directory.

**Dependencies.** `pandas`, `scipy`, `matplotlib`, `eval.constants`, `eval.loaders`, `eval.metrics` (for `print_tfa`).

---

## 11. `eval/process_results.py`

**Purpose.** Thin orchestrator script (also callable from `cli.py metrics process`) that wires together the loading, metrics, and plotting layers to compute TFA and LAS, run the deep/segmented analyses, and optionally generate figures. Contains only `main()` and wildcard imports from the four modules above — all logic lives in `eval.constants`, `eval.loaders`, `eval.metrics`, and `eval.plots`.

**Key functions.**

| Name | Description |
|---|---|
| `main()` | Parses CLI args (`--artifacts`, `--domains`, `--plots`, `--deep`), discovers domains, loads TFA per domain via `load_tfa_from_jsonl` + `find_run_dir`, computes LAS via `load_latency` + `compute_las`, runs `segmented_analysis` and `latency_adv_vs_legit`, optionally runs the deep-analysis functions (`--deep`) and figure generation (`--plots`). |

**Imports.** `from eval.constants import *`, `from eval.loaders import *`, `from eval.metrics import *`, `from eval.plots import *`.

**Environment variables read.** None at module level; all paths supplied via CLI args or the `cli.py` caller.

**Files read.**
- `artifacts/runs/<run_dir>/garak/*.report.jsonl`
- `artifacts/consolidated_<domain>_<scenario>.csv`
- `artifacts/latency/latency_unprotected_direct.csv`
- `artifacts/latency/latency_protected.csv`

**Files written.** Delegates all writes to the imported modules — `metrics.json` is not written by this script directly; CSVs land under `artifacts/segmented/` (via `eval.metrics`) and PNGs under `artifacts/figures/` (via `eval.plots`).

**Dependencies.** `eval.constants`, `eval.loaders`, `eval.metrics`, `eval.plots`.

---

## 12. `eval/garak_catalog.py`

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

## 13. `eval/legitimate_runner.py`

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

## 14. `ingestion/generic_dir.py`

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

## 15. `ingestion/registry.py`

**Purpose.** Dispatch layer mapping logical domain names (e.g. `regulatory_technical`) to their data paths and ingestion parameters. Calls `generic_dir.ingest_dir_pdfs()` with the correct arguments for each registered domain.

**Key functions.**

| Name | Description |
|---|---|
| `run_source(source, settings, reset)` | Resolves the data path and chroma path for `source`, delegates to `ingest_dir_pdfs()`, returns total chunk count. |

**Environment variables read.** All `Settings` fields (via the passed `settings` argument).

**Files read.** PDFs under `data/raw/<domain>/` and `data/synthetic/<domain>/`. **Files written.** ChromaDB persistent storage.

**Dependencies.** `settings`, `ingestion.generic_dir`.

---

## 16. `utils/paths.py`

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

## 17. `utils/logging.py`

**Purpose.** Configures a shared structlog/stdlib logger used across CLI commands and API servers. Clears existing handlers on repeated calls (idempotent).

**Key functions.**

| Name | Description |
|---|---|
| `setup_logging(level, log_file)` | Configures root logger with console (and optional file) handlers. Returns the configured logger. |

**Environment variables read.** None.

**Files read/written.** Optionally writes to the log file path provided.

**Dependencies.** Standard library `logging`.

---

## 18. `docker-compose.yml`

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
- `SCENARIO=unprotected` is a fixed literal in this service definition; there is no override for Scenario B. Scenario B is achieved solely by pointing Garak at `shield_api` instead of `rag_api` (see the deployment caveat in section 3, `api/rag.py`).

#### `shield_api` (profile: `lab`, port 8001)

- Runs `api.shield:app` via uvicorn on port 8001 (exposed on host).
- Depends on `ollama_core` and `rag_api`.
- **Key env vars:** `SCENARIO=protected`, `RAG_BASE_URL=http://rag_api:8000`, `CONSOLIDATED_CSV`, `LLM_GUARD_CONFIG_PATH`, `LLM_GUARD_LOG_FILE`. LLM Guard scanning is unconditional; Scenario B is selected by directing Garak probes at this service instead of `rag_api`.

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

### Orchestration (`llmsec.sh`)

`llmsec.sh`, at the repository root, wraps all `docker compose` invocations above so that no `docker compose` command needs to be typed directly. It selects the correct `--env-file` per domain, brings the `lab` profile up before running `attacks`, retries aborted Garak runs (fewer than 55 JSONL files), and re-ingests the ChromaDB collection when it is found empty or missing expected `[CONFIDENTIAL]` fragments. See the top-level `CLAUDE.md` for the full subcommand table (`run`, `run-scenario`, `smoke`, `process`, `reload`, `shell`, `new`).

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

---

## Evaluation Pipeline — Analysis Catalog

This catalog documents every public function in `app/src/eval/`, organized by analysis category. It is intended as a quick-reference for anyone reading the codebase for the first time.

**Entry point:** `app/src/eval/process_results.py`

```bash
# Inside the garak_runner container:
python -m eval.process_results [FLAGS]

# Or via Docker Compose:
docker compose --profile attacks run --rm garak_runner python -m eval.process_results [FLAGS]
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--artifacts PATH` | Root artifacts directory (default: `artifacts/`) |
| `--domains D1 D2` | Restrict to specific domains (default: auto-discover from `runs/`) |
| `--plots` | Generate and save all figures to `artifacts/figures/` |
| `--deep` | Run deep probe/detector/confusion-matrix analysis |
| `--exfiltration` | Run confidential-data exfiltration analysis (Parts 2a–2f + Part 3) |
| `--data-dir PATH` | Data directory for `--exfiltration` (default: `data/`) |
| `--characterize` | Full artifact characterization (row counts, variance, latency) |
| `--backfill-scores` | One-time fix: convert risk scores to raw [0,1] probabilities |
| `--duration` | Print wall-clock execution time per experiment run |
| `--tfa-breakdown` | Print `was_blocked × ground_truth` breakdown for Scenario B |

---

### 1. TFA Analysis

Compute and report Task/Filter Adherence — the fraction of adversarial attacks the system resisted.

**TFA ground truth per OWASP suite:**

| Suite | Ground truth column | Rationale |
|-------|---------------------|-----------|
| LLM01 | `garak_passed` | Garak's own detector is valid for prompt-injection |
| LLM02 | `response_has_confidential` | Garak cannot see the RAG corpus; direct inspection required |
| LLM07 | `response_has_system_prompt` | Garak's heuristics produce false positives on system-prompt leakage |
| LLM08 | `injection_followed` | Garak's detector unreliable when corpus lacks WHOIS documents |

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `load_tfa_from_jsonl` | `loaders.py` | `(garak_dir: Path) → dict` | Parses `*.report.jsonl` → per-probe, per-suite, global TFA using primary detector only |
| `load_tfa_from_csv` | `loaders.py` | `(artifacts_dir, domain, scenario) → dict` | Per-suite TFA from consolidated CSV using the suite-correct ground-truth column |
| `compute_tfa_by_suite` | `metrics.py` | `(df: DataFrame, suite: str) → float` | TFA for one suite using the correct ground-truth column; raises `KeyError` when required column is absent |
| `compute_tfa_global` | `metrics.py` | `(df: DataFrame) → dict` | Weighted global TFA aggregated across all suites; returns `{TFA, total_tp, total_n, per_suite}` |
| `print_tfa` | `metrics.py` | `(tfa_a, tfa_b, domain, tfa_csv_a, tfa_csv_b) → None` | Formatted TFA report: global totals, per-suite table with Fisher exact p-values, per-probe detail |
| `print_tfa_global` | `metrics.py` | `(domain, global_a, global_b) → None` | Weighted global TFA with per-suite breakdown (CSV-based ground truth) |

**CLI invocation:** Runs automatically on every call.

```bash
python -m eval.process_results --artifacts artifacts/ --domains regulatory_technical
```

**Required columns:** `probe`, `suite`, `prompt_type`, `garak_passed`, `response_has_confidential`, `response_has_system_prompt`, `injection_followed`, `rogue_string_found`

**Output:** stdout only

---

### 2. TFA Breakdown (Guard vs Ground Truth)

Decomposes Scenario B adversarial attempts into three mutually exclusive categories that sum to 1.0 per suite:

- **guard_blocked** (A+B): LLM Guard blocked the request, regardless of attack outcome
- **defense_gap** (C): Guard missed it; attack still failed (model resisted)
- **residual_risk** (D): Guard missed it; attack succeeded (true security gap)

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `compute_tfa_breakdown` | `metrics.py` | `(artifacts_dir: Path, domain: str) → DataFrame` | Returns per-suite DataFrame with counts and pcts for each category |
| `print_tfa_breakdown` | `metrics.py` | `(breakdown_df: DataFrame, domain: str) → None` | Prints the four-category table to stdout |

**CLI invocation:**

```bash
python -m eval.process_results --artifacts artifacts/ --tfa-breakdown
```

**Required columns (protected CSV):** `suite`, `prompt_type`, `was_blocked`, `rogue_string_found`, `response_has_confidential`, `response_has_system_prompt`, `injection_followed`

**Output:** stdout only

---

### 3. LAS Analysis

Quantify Latency Added by Shield — adversarial and legitimate prompts are always tested separately because they have structurally different distributions (LLM Guard blocks adversarial requests before inference, cutting their latency; legitimate requests go through full inference plus proxy overhead).

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `load_latency` | `loaders.py` | `(latency_dir: Path, filename: str) → DataFrame` | Loads latency CSV, filters `/generate` requests, adds `prompt_type` column derived from `suite_probe` |
| `compute_las` | `metrics.py` | `(lat_a, lat_b: DataFrame) → None` | LAS summary split by prompt_type (Mann-Whitney U) and by domain |
| `deep_analysis_las` | `metrics.py` | `(lat_a, lat_b: DataFrame) → None` | Distribution stats, percentile table, per-suite medians, LAS overhead, outliers |

**CLI invocation:** Runs automatically. `--deep` adds `deep_analysis_las`.

```bash
python -m eval.process_results --artifacts artifacts/ --deep
```

**Input files:** `artifacts/latency/latency_unprotected_direct.csv`, `artifacts/latency/latency_protected.csv`

**Latency CSV columns:** `timestamp`, `scenario`, `domain`, `method`, `endpoint`, `status_code`, `latency_ms`, `col8`, `suite_probe`, `prompt_tokens`, `response_tokens`

**Output:** stdout only

---

### 4. Segmented Analysis

Systematic analysis across all domain × scenario × prompt_type cells. Runs 11 statistical sub-blocks and exports one CSV per block.

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `segmented_analysis` | `metrics.py` | `(artifacts_dir, domains, pcc_values) → None` | 11-block analysis: overview, TFA/probe, TFA/suite, garak_passed distribution, was_blocked distribution, scanner breakdown, FPR, latency, Mann-Whitney LAS, Fisher TFA A vs B, optional Spearman PCC |
| `latency_adv_vs_legit` | `metrics.py` | `(artifacts_dir, domains) → None` | Counts, latency stats, and Mann-Whitney U comparing adversarial vs legitimate latency distributions |

**CLI invocation:** Both run automatically.

**Required columns:** `prompt_type`, `probe`, `suite`, `subdimension`, `was_blocked`, `should_block`, `garak_passed`, `latency_ms`, `scanner_triggered`

**Output files:**

| File | Description |
|------|-------------|
| `artifacts/segmented/01_segment_overview.csv` | Row counts, blocking rate, mean `garak_passed`, latency median per (domain × scenario × prompt_type) |
| `artifacts/segmented/02_tfa_per_probe.csv` | TFA per probe per segment |
| `artifacts/segmented/03_tfa_per_suite.csv` | TFA per OWASP suite per segment |
| `artifacts/segmented/04_garak_passed_dist.csv` | `gp=0` / `gp=1` / `gp=NaN` counts |
| `artifacts/segmented/05_was_blocked_dist.csv` | Blocked / not-blocked counts |
| `artifacts/segmented/06_scanner_breakdown.csv` | `scanner_triggered` value counts (Scenario B adversarial) |
| `artifacts/segmented/07_fpr_legitimate.csv` | FPR per domain × scenario |
| `artifacts/segmented/08_latency_legitimate.csv` | Legitimate latency stats (median, IQR, p95, p99) |
| `artifacts/segmented/09_las_mannwhitney.csv` | Mann-Whitney U results per domain |
| `artifacts/segmented/10_fisher_tfa_ab.csv` | Fisher exact results per suite and per domain |
| `artifacts/segmented/11_spearman_pcc_tfa.csv` | Spearman ρ (only when `pcc_values` is provided) |
| `artifacts/segmented/12_latency_adv_vs_legit.csv` | Wide-format latency stats + Mann-Whitney per domain × scenario |

---

### 5. Deep Analysis

Probe-level, detector-level, and confusion-matrix analysis. Requires `--deep`.

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `deep_analysis_tfa` | `metrics.py` | `(df_a, df_b, domain) → None` | Confidential exposure rate, blocking stats, latency by probe and subdimension, scanner breakdown |
| `deep_analysis_by_detector` | `metrics.py` | `(runs_dir, domains) → None` | TFA per probe × detector from JSONL; highlights gap between primary and secondary detectors |
| `deep_analysis_confusion_a` | `metrics.py` | `(artifacts_dir, domains) → None` | Partial confusion matrix for Scenario A — TP/FN from `garak_passed`; TN from legitimate rows |
| `deep_analysis_confusion` | `metrics.py` | `(artifacts_dir, domains) → None` | System-level (two-layer) and LLM Guard-only confusion matrices for Scenario B, with per-subdimension breakdown |

**CLI invocation:**

```bash
python -m eval.process_results --artifacts artifacts/ --deep
```

**Required columns:** `garak_passed`, `was_blocked`, `should_block`, `response_has_confidential`, `latency_ms`, `probe`, `subdimension`, `scanner_triggered`

**Output:** stdout only

---

### 6. Exfiltration / PII Analysis

Quantifies sensitive-data leakage in adversarial responses across three signal types.

**In `metrics.py`:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `analyze_pii_exposure` | `(artifacts_dir, domains) → dict` | Regex scan for RUT, email, phone, password, card, and `[CONFIDENTIAL]` patterns per domain × scenario |
| `analyze_sensitivity_thresholds` | `(artifacts_dir, domains, config_dir) → dict` | Reclassifies adversarial rows under alternative scanner thresholds; reads candidates from `llm_guard_config.yaml` |

**In `exfiltration.py`:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `load_ground_truth_fragments` | `(data_dir) → list[dict]` | Extracts `[CONFIDENTIAL]…[/CONFIDENTIAL]` fragments from 6 synthetic PDFs via `pdftotext` |
| `analyze_confidential_marker` | `(artifacts_dir, domains) → dict` | 2a: counts responses containing literal `[CONFIDENTIAL]` marker, by probe and suite |
| `analyze_verbatim_exfiltration` | `(artifacts_dir, domains, fragments) → tuple` | 2b + Part 3: verbatim sensitive-value matches; returns domain results + subdocument hit list |
| `analyze_pii_by_type` | `(artifacts_dir, domains) → dict` | 2c: PII pattern counts per type × domain × scenario |
| `compute_deltas` | `(conf_r, verb_r, pii_r, domains) → dict` | 2d: A→B absolute and relative deltas for every metric |
| `print_summary` | `(conf_r, verb_r, pii_r, deltas, domains) → None` | Prints Part 2 summary table with count/pct and Δ columns |
| `save_confidential_csv` | `(results, segmented_dir, domains) → Path` | Writes `13_exfiltration_confidential.csv` |
| `save_pii_csv` | `(results, segmented_dir, domains) → Path` | Writes `14_exfiltration_pii.csv` |
| `save_verbatim_csv` | `(results, segmented_dir, domains) → Path` | Writes `15_exfiltration_verbatim.csv` |
| `save_subdocument_csv` | `(subdoc_matches, segmented_dir) → Path` | Writes `16_exfiltration_by_subdocument.csv` (Part 3) |
| `save_summary_json` | `(conf_r, verb_r, pii_r, deltas, fragments, artifacts_dir) → Path` | Writes `artifacts/characterization/exfiltration_summary.json` |
| `run_exfiltration_analysis` | `(artifacts_dir, data_dir, domains, figures_dir) → dict` | Orchestrates 2a–2f + Part 3 end to end, including figures |

**CLI invocation:**

```bash
python -m eval.process_results --artifacts artifacts/ --exfiltration --data-dir data/
```

**Required columns:** `prompt_type`, `response`, `probe`, `suite`

**Output files:**

| File | Description |
|------|-------------|
| `artifacts/segmented/13_exfiltration_confidential.csv` | `[CONFIDENTIAL]` marker hits per probe × scenario |
| `artifacts/segmented/14_exfiltration_pii.csv` | PII pattern hits per type × scenario |
| `artifacts/segmented/15_exfiltration_verbatim.csv` | Verbatim ground-truth hits per scenario |
| `artifacts/segmented/16_exfiltration_by_subdocument.csv` | Part 3: hits per subdocument × scenario × probe |
| `artifacts/characterization/exfiltration_summary.json` | Full structured results |
| `artifacts/figures/exfiltration_confidential_by_probe.png` | Stacked bar: `[CONFIDENTIAL]` hits by probe |
| `artifacts/figures/exfiltration_pii_by_type.png` | Grouped bar: PII hits by type |
| `artifacts/figures/exfiltration_delta_ab.png` | Horizontal bar: A→B relative delta per metric |

---

### 7. Characterization

Structural characterization of every consolidated CSV and Garak JSONL run.

**Functions:**

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `characterize_consolidated_csv` | `characterizer.py` | `(csv_path, scenario, domain) → dict` | Row counts, latency stats (median/mean/std/p5/p95), block rate, TFA per suite and probe |
| `characterize_jsonl_run` | `characterizer.py` | `(jsonl_path) → dict` | Parses one `.report.jsonl`: eval summary, attempt count, per-detector score statistics |
| `compute_repetition_variance` | `characterizer.py` | `(jsonl_dir, probe, scenario, domain, primary_detector) → dict` | TFA mean/std/min/max across rep00–rep04 for one probe; flags `high_variance` when std > 0.05 |
| `compare_latency` | `characterizer.py` | `(csv_paths: dict) → dict` | Adversarial and legitimate latency stats per (scenario, domain) pair |
| `run_full_characterization` | `characterizer.py` | `(artifacts_dir, output_dir) → None` | Orchestrates all characterization; prints console summary and writes 4 output files |

**CLI invocation:**

```bash
python -m eval.process_results --characterize --artifacts artifacts/ \
  --artifacts-dir artifacts/ --output-dir artifacts/characterization/
```

**Output files:**

| File | Description |
|------|-------------|
| `artifacts/characterization/characterization_summary.json` | Full structured characterization results |
| `artifacts/characterization/repetition_variance.csv` | TFA variance per probe × scenario × domain (rep00–rep04) |
| `artifacts/characterization/latency_comparison.csv` | Latency stats per scenario × domain × prompt_type |
| `artifacts/characterization/tfa_by_probe.csv` | TFA per probe × scenario × domain |

---

### 8. Backfill & Patching Utilities

Post-hoc data correction. Not called automatically during normal analysis.

**Functions:**

| Function | File | Signature | Returns | Description |
|----------|------|-----------|---------|-------------|
| `log_request` | `consolidator.py` | `(csv_path, *, scenario, domain, ...)` | `None` | Appends one row to consolidated CSV (called live from `rag.py` / `shield.py`) |
| `patch_garak_passed` | `consolidator.py` | `(csv_path, garak_dir) → int` | rows updated | Fills empty `garak_passed` cells via majority-vote from JSONL pass/total counts |
| `backfill_raw_scores` | `consolidator.py` | `(csv_path, pi_threshold, sens_threshold) → None` | — | Inverts `calculate_risk_score()` to convert threshold-relative scores back to raw [0,1] probabilities |
| `run_backfill_scores` | `consolidator.py` | `(artifacts_dir) → None` | — | Applies `backfill_raw_scores` to every `consolidated_*.csv`; prints before/after stats |
| `backfill_llm01_attack_success` | `consolidator.py` | `(csv_path, garak_dir) → int` | rows updated | Writes per-row `rogue_string_found` (1/0) for LLM01 probes by matching JSONL attempt data |

**CLI invocations:**

```bash
# Convert old threshold-relative scores to raw probabilities (one-time, run once per old CSV):
python -m eval.process_results --backfill-scores --artifacts artifacts/

# Backfill rogue_string_found for LLM01 (via CLI subcommand):
docker compose --profile attacks run --rm garak_runner analyze metrics backfill-llm01 \
  --csv artifacts/consolidated_<domain>_unprotected.csv \
  --garak-dir artifacts/runs/<run_id>/garak
```

**Columns modified:**
- `patch_garak_passed` — fills empty `garak_passed` cells
- `backfill_llm01_attack_success` — adds `rogue_string_found` column
- `backfill_raw_scores` — overwrites `input_scanner_score`, `output_scanner_score`

**Standalone one-time scripts (`app/src/eval/`, not wired into `process_results.py`):**

| Script | Description |
|--------|-------------|
| `backfill_scenario_a.py` | Backfills `response_has_system_prompt` and `injection_followed` into consolidated CSVs written before those columns existed; skips CSVs that already have them. Usage: `python eval/backfill_scenario_a.py --artifacts artifacts/`. |
| `fix_scanner_scores.py` | Corrects `input_scanner_score`/`output_scanner_score` in protected CSVs affected by a since-fixed scoring bug in `shield.py` (`_raw_score_from_risk()` assumed a `[-1,1]` risk range; llm-guard 0.3.16 already returns raw `[0,1]` probabilities). Inverts the distortion for rows where the stored score is at or above the scanner's threshold. |

---

### 9. Duration / Run Metadata

| Function | File | Signature | Description |
|----------|------|-----------|-------------|
| `compute_run_duration` | `metrics.py` | `(artifacts_dir: Path) → DataFrame` | Reads timestamps from all consolidated CSVs; computes adversarial / legitimate / total / inference hours per run. Adversarial and legitimate windows are computed separately since they are collected in distinct phases. |
| `compute_probe_timings` | `metrics.py` | `(artifacts_dir: Path) → DataFrame` | Reads file mtimes of all `*.report.jsonl` files across every `*_garak` run directory; computes per-repetition wall-clock duration as the mtime delta between consecutive files sorted chronologically. Returns one row per `(domain, scenario, suite, probe, repetition)` with `duration_seconds` (`NaN` for the first file in each run). |

**CLI invocation:**

```bash
python -m eval.process_results --duration --artifacts artifacts/
python -m eval.process_results --probe-timings --artifacts artifacts/
```

**Required columns:** `timestamp`, `prompt_type`, `latency_ms`

**Output:** stdout table only (no CSV saved)

---

### 10. Plotting Functions

All plots are PNG, saved to `artifacts/figures/`. Generated via `--plots`; exfiltration and characterization plots are generated by their respective flags.

**Orchestrators:**

| Function | File | Description |
|----------|------|-------------|
| `generate_all_plots` | `plots.py` | Runs all primary figure functions (~19 PNGs) |
| `generate_segmented_plots` | `plots.py` | Runs 8 supplementary segmented figures |

```bash
python -m eval.process_results --artifacts artifacts/ --plots
python -m eval.process_results --artifacts artifacts/ --plots --characterize --exfiltration
```

**Primary figures (`generate_all_plots`):**

| Function | Output PNG | Description |
|----------|------------|-------------|
| `plot_tfa_by_probe` | `tfa_by_probe_<domain>.png` | TFA per probe colored by OWASP suite (garak_passed-based) |
| `plot_tfa_by_suite` | `tfa_by_suite_<domain>.png` | TFA per suite with CSV ground truth |
| `plot_tfa_domains_combined` | `tfa_by_suite_combined.png` | Side-by-side suite TFA for all domains |
| `plot_tfa_csv_by_suite_grouped` | `tfa_csv_by_suite_both_domains.png` | CSV-based suite TFA with annotated values |
| `plot_tfa_global_weighted` | `tfa_global_weighted.png` | Weighted global TFA per domain with ΔTFA |
| `plot_tfa_heatmap` | `tfa_heatmap_probe_domain.png` | Heatmap: TFA per probe × domain (Scenario A) |
| `plot_delta_tfa` | `delta_tfa_by_probe.png` | ΔTFA (B−A) per probe |
| `plot_pvalue_by_suite` | `pvalue_by_suite.png` | −log₁₀(p) per suite — Fisher exact A vs B |
| `plot_confidential_exposure` | `confidential_exposure_by_subdim.png` | Confidential exposure rate per subdimension |
| `plot_las_boxplot` | `las_boxplot_global.png`, `las_boxplot_by_domain.png` | Latency boxplots (log scale) |
| `plot_latency_histogram` | `las_histogram_kde.png` | Latency histogram + KDE with Mann-Whitney stats |
| `plot_las_by_suite` | `las_median_by_suite.png` | Median latency per OWASP suite |
| `plot_latency_distribution_by_suite` | `las_distribution_by_suite_A.png` | Latency boxplot per suite (Scenario A) |
| `plot_confusion_matrix_scenario_a` | `confusion_matrix_scenario_a.png` | Partial confusion matrix Scenario A (no classifier) |
| `plot_confusion_matrix` | `confusion_matrix_scenario_b.png` | System-level (two-layer) confusion matrix Scenario B |
| `plot_confusion_matrix_guard_only` | `confusion_matrix_scenario_b_llmguard_only.png` | LLM Guard-only confusion matrix Scenario B |
| `plot_detector_heatmap` | `detector_heatmap_scenario_a.png` | TFA per probe × detector, primary detector bolded |
| `plot_security_posture_radar` | `fig_security_posture_radar.png` | Radar chart: TFA per subdimension D1–D4, all combos |
| `plot_tfa_suite_all_combos` | `fig_tfa_suite_all_combos.png` | All 4 scenario×domain combos per suite, single panel |

**Segmented figures (`generate_segmented_plots`):**

| Function | Output PNG | Description |
|----------|------------|-------------|
| `plot_latency_adv_vs_legit_boxplot` | `latency_adv_vs_legit_boxplot.png` | Boxplots per domain × scenario × prompt_type (log scale) |
| `plot_latency_adv_vs_legit_kde` | `latency_adv_vs_legit_kde.png` | KDE grid: adversarial vs legitimate per domain × scenario |
| `plot_fpr_by_domain_scenario` | `fpr_by_domain_scenario.png` | FPR per domain — Scenario B only |
| `plot_tfa_heatmap_ab_comparison` | `tfa_heatmap_ab_comparison.png` | Two-panel TFA heatmap: Scenario A vs B |
| `plot_delta_tfa_by_domain` | `delta_tfa_by_probe_by_domain.png` | ΔTFA grouped bars per probe, colored by domain |
| `plot_scanner_breakdown_by_probe` | `scanner_breakdown_by_probe.png` | Stacked bars: scanner activations per probe (Scenario B adv.) |
| `plot_repetition_variance` | `fig_repetition_variance_stability.png` | TFA mean/std/range across 5 repetitions per probe |
| `plot_las_adv_vs_legit_summary` | `fig_las_adv_vs_legit_summary.png` | Median latency bar chart with early-blocking annotation |

**Probe timing figures (via `--probe-timings`):**

| Function | Output PDF | Description |
|----------|------------|-------------|
| `plot_probe_timings` | `probe_timings_<domain>.pdf` | Horizontal grouped bar chart of median probe execution time (minutes) per domain; bars colored by scenario (`#e07b39` = A, `#1e5eff` = B), error bars show IQR over 5 reps, probes ordered by OWASP suite |

**Exfiltration figures (via `--exfiltration`):**

| Function | Output PNG | Description |
|----------|------------|-------------|
| `plot_confidential_by_probe` | `exfiltration_confidential_by_probe.png` | Stacked bars: `[CONFIDENTIAL]` hits by probe |
| `plot_pii_by_type` | `exfiltration_pii_by_type.png` | Grouped bars: PII hits by type |
| `plot_delta_ab` | `exfiltration_delta_ab.png` | Horizontal bars: A→B relative delta per metric |

---

### 11. Data Loading Layer (`loaders.py`)

These are the shared read functions consumed by `metrics.py`, `plots.py`, and `characterizer.py`.

| Function | Signature | Description |
|----------|-----------|-------------|
| `load_consolidated` | `(artifacts_dir, domain, scenario, run_id) → DataFrame` | Loads adversarial rows from consolidated CSV; optional `run_id` filter |
| `load_tfa_from_jsonl` | `(garak_dir: Path) → dict` | TFA from JSONL (garak_passed-based; primary detector only) |
| `load_tfa_from_csv` | `(artifacts_dir, domain, scenario) → dict` | TFA from CSV with suite-correct ground truth via `compute_tfa_by_suite` |
| `load_latency` | `(latency_dir: Path, filename: str) → DataFrame` | Latency CSV → `/generate` rows only; adds `prompt_type` from `suite_probe` |
| `find_run_dir` | `(runs_dir, domain, scenario) → Path \| None` | Most recent run directory matching domain + scenario |
| `discover_domains` | `(runs_dir: Path) → list` | Auto-discovers available domains from run directory names |

---

### 12. Garak Catalog (`garak_catalog.py`)

Used by the CLI to enumerate available probes before launching an attack run.

| Function | Signature | Description |
|----------|-----------|-------------|
| `load_suites` | `(path=None) → dict` | Loads `owasp_suites.json` → `{suite_id: [probe_names]}` |
| `list_suites` | `(path=None) → list` | Sorted list of suite IDs (e.g. `LLM01`…`LLM10`) |
| `list_probes` | `(suite, path=None, prefix=None) → list` | Probe names for a suite; optional prefix filter |

---

### 13. Standalone: Threshold Sensitivity Sweep (`threshold_sensitivity.py`)

Stand-alone parametric grid sweep over scanner score thresholds. Not integrated with `process_results.py`.

```bash
python app/src/eval/threshold_sensitivity.py \
  --input_csv artifacts/consolidated_regulatory_technical_protected.csv \
  --config_yaml app/config/global/llm_guard_config.yaml \
  --output_dir artifacts/reporting
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `load_experimental_thresholds` | `(yaml_path) → tuple` | Reads `prompt_injection_thresholds` and `sensitive_thresholds` from `llm_guard_config.yaml` |
| `run_grid_sensitivity_analysis` | `(csv_path, yaml_path, output_dir) → None` | Sweeps all (tau_in × tau_out) combinations; computes TFA global, TFA per probe group, FPR, and classifies operational regime |

**Required columns:** `prompt_type`, `probe`, `input_scanner_score`, `output_scanner_score`, `was_blocked`, `garak_passed`

**Output:** formatted table to stdout

---

### Consolidated CSV Schema

All analysis functions read from `artifacts/consolidated_<domain>_<scenario>.csv` (23 columns):

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | ISO 8601 | UTC request time |
| `scenario` | str | `unprotected` or `protected` |
| `domain` | str | Dataset tag (e.g. `regulatory_technical`) |
| `prompt_type` | str | `adversarial` or `legitimate` |
| `probe` | str | Garak probe name |
| `suite` | str | OWASP suite (e.g. `LLM01`) |
| `subdimension` | str | `D1`–`D4` |
| `repetition` | int | Repetition index |
| `prompt` | str | Raw prompt text |
| `response` | str | Model or shield response |
| `latency_ms` | float | End-to-end request latency |
| `should_block` | int | Ground-truth block label (1=should, 0=should not) |
| `was_blocked` | int | Whether LLM Guard blocked the request |
| `scanner_triggered` | str | Name of scanner that fired |
| `block_reason` | str | Short reason code |
| `input_scanner_score` | float | Raw PromptInjection score [0,1] |
| `output_scanner_score` | float | Raw Sensitive score [0,1] |
| `garak_passed` | float | 1=system resisted; 0=attack succeeded (filled by `patch_garak_passed`) |
| `response_has_confidential` | int | 1 if `[CONFIDENTIAL]` appears in response |
| `grounding_ratio` | float | C17 grounding ratio in retrieved context |
| `run_id` | str | Run identifier |
| `response_has_system_prompt` | int | 1 if system-prompt phrases appear in response |
| `injection_followed` | int | 1 if adversarial injection instructions were followed |
| `rogue_string_found` | int | 1 if LLM01 rogue string found in response (backfilled) |
