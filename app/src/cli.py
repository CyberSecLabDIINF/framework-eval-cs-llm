from __future__ import annotations

import json
import os
import re
import glob
import argparse
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Literal, List

import typer

from settings import get_settings
from utils.paths import make_run_paths, snapshot_configs, run_paths_from_existing
from utils.logging import setup_logging
from eval.garak_catalog import list_probes as catalog_list_probes, list_suites as catalog_list_suites

REPS_EXPECTED = 5  # rep00 … rep04

app = typer.Typer(help="Security evaluation lab CLI (RAG + Shield + Garak + metrics).")
serve_app = typer.Typer(help="Start API services (RAG / Shield).")
ingest_app = typer.Typer(help="Ingest documents into ChromaDB.")
attack_app = typer.Typer(help="Run adversarial probes via Garak.")
analyze_app = typer.Typer(help="Analyze run results (latency / ASR comparison).")
metrics_app = typer.Typer(help="Compute and patch experimental metrics.")

app.add_typer(serve_app, name="serve")
app.add_typer(ingest_app, name="ingest")
app.add_typer(attack_app, name="attack")
app.add_typer(analyze_app, name="analyze")
app.add_typer(metrics_app, name="metrics")

def _check_health(url: str, timeout_s: int = 2) -> bool:
    import urllib.request

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return 200 <= resp.status < 500
    except Exception:
        return False


def _load_owasp_suites(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_subprocess(cmd: List[str], cwd: Optional[Path] = None, logger=None) -> int:
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,   # merge stderr into stdout
        text=True,
        bufsize=1,                  # line-buffered
    )
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        if logger:
            logger.info(f"[garak] {line}")
        else:
            print(line)            
    proc.wait()
    return int(proc.returncode)


@serve_app.command("rag")
def serve_rag(
    host: str = typer.Option("0.0.0.0", help="Host bind"),
    port: Optional[int] = typer.Option(None, help="Port (default: settings.rag_port)"),
    reload: bool = typer.Option(False, help="Auto-reload (dev)"),
    log_level: str = typer.Option("info", help="uvicorn log level"),
):
    """
    Start the unprotected RAG API.
    Expects `app = FastAPI()` in api.rag.
    """
    s = get_settings()
    p = port or s.rag_port
    logger = setup_logging(level="INFO", run_paths=None)
    logger.info(f"Starting RAG API on {host}:{p}")

    cmd = [
        "python3",
        "-m",
        "uvicorn",
        "api.rag:app",
        "--host",
        host,
        "--port",
        str(p),
        "--log-level",
        log_level,
    ]
    if reload:
        cmd.append("--reload")

    raise typer.Exit(code=_run_subprocess(cmd))


@serve_app.command("shield")
def serve_shield(
    host: str = typer.Option("0.0.0.0", help="Host bind"),
    port: Optional[int] = typer.Option(None, help="Port (default: settings.shield_port)"),
    reload: bool = typer.Option(False, help="Auto-reload (dev)"),
    log_level: str = typer.Option("info", help="uvicorn log level"),
):
    """
    Start the protected Shield API (LLM Guard proxy over RAG).
    Expects `app = FastAPI()` in api.shield.
    """
    s = get_settings()
    p = port or s.shield_port
    logger = setup_logging(level="INFO", run_paths=None)
    logger.info(f"Starting Shield API on {host}:{p}")

    cmd = [
        "python3",
        "-m",
        "uvicorn",
        "api.shield:app",
        "--host",
        host,
        "--port",
        str(p),
        "--log-level",
        log_level,
    ]
    if reload:
        cmd.append("--reload")

    raise typer.Exit(code=_run_subprocess(cmd))


@ingest_app.callback(invoke_without_command=True)
def ingest_callback(
    ctx: typer.Context,
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Knowledge domain folder under data/raw/<source>"),
    input_dir: Optional[Path] = typer.Option(None, "--input-dir", help="Override the default input directory"),
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="ChromaDB collection name (defaults to source)"),
    reset: bool = typer.Option(False, "--reset", help="Drop the existing collection before ingesting"),
):
    if ctx.invoked_subcommand is not None:
        return

    if not source:
        typer.echo("❌ Falta --source (ej: --source regulatory_technical)")
        raise typer.Exit(code=2)

    from ingestion.registry import run_source
    n = run_source(source, input_dir=input_dir, collection=collection, reset=reset)
    typer.echo(f"✅ Ingest '{source}' OK. docs={n} collection='{collection or source}'")

@ingest_app.command("verify")
def ingest_verify(
    collection: str = typer.Option(..., "--collection", "-c", help="ChromaDB collection name to verify"),
    show_preview: bool = typer.Option(True, "--preview/--no-preview", help="Show 80-char preview per fragment"),
):
    """
    Verify that [CONFIDENTIAL] fragments are correctly indexed and semantically
    recoverable in ChromaDB.
    Step 1 — Presence check: col.get() confirms fragments exist in the index.
    Step 2 — Semantic check: col.query() confirms fragments are retrievable
             via thematically related queries (simulating realistic attack conditions).
    Success criterion: at least 1 sensitive fragment recoverable per synthetic document.
    Verification queries are loaded from config/verification_queries_<collection>.json.
    """
    import json
    import chromadb

    s = get_settings()
    client = chromadb.PersistentClient(path=str(s.chroma_db_path))

    try:
        col = client.get_collection(collection)
    except Exception:
        typer.echo(f"❌ Collection '{collection}' not found.", err=True)
        raise typer.Exit(code=1)

    # ------------------------------------------------------------------ #
    # Step 1 — Presence check
    # ------------------------------------------------------------------ #
    all_docs = col.get(include=["documents", "metadatas"])
    confidential = [
        (doc, meta)
        for doc, meta in zip(all_docs["documents"], all_docs["metadatas"])
        if "[CONFIDENTIAL]" in doc
    ]

    typer.echo(f"\nCollection : {collection}")
    typer.echo(f"Total chunks: {len(all_docs['documents'])}")
    typer.echo(f"CONFIDENTIAL fragments (presence): {len(confidential)}")
    typer.echo("-" * 80)

    if not confidential:
        typer.echo("❌ No sensitive fragments found. Check ingestion.", err=True)
        raise typer.Exit(code=1)

    sources_found = set()
    for doc, meta in confidential:
        src = meta.get("source", "?")
        sources_found.add(src)
        if show_preview:
            page = meta.get("page", "?")
            cidx = meta.get("chunk_index", "?")
            preview = doc[:80].replace("\n", " ")
            typer.echo(f"{src[:50]} | p{page} | c{cidx} | {preview}")

    typer.echo("-" * 80)
    typer.echo(f"✅ Sources with sensitive fragments: {len(sources_found)}")
    for src in sorted(sources_found):
        typer.echo(f"   · {src}")

    # ------------------------------------------------------------------ #
    # Step 2 — Semantic recoverability check
    # ------------------------------------------------------------------ #
    typer.echo(f"\n{'─' * 80}")
    typer.echo("Step 2 — Semantic recoverability verification")
    typer.echo(f"{'─' * 80}")

    queries_path = s.get_verification_queries_path(collection)
    verification_queries: dict = {}
    if queries_path.exists():
        verification_queries = json.loads(queries_path.read_text(encoding="utf-8"))
        typer.echo(f"Loaded verification queries from: {queries_path.name}")
    else:
        typer.echo(f"⚠️  No verification queries file found at {queries_path}. Using generic fallback.")

    FALLBACK_QUERY = "What confidential information is stored in this document?"

    def _normalize(text: str) -> str:
        """Collapse whitespace and newlines for robust string comparison."""
        return " ".join(text.split())

    not_recoverable: list[tuple[str, str]] = []
    semantically_verified: list[str] = []

    for doc, meta in confidential:
        src = meta.get("source", "?")
        cidx = meta.get("chunk_index", "?")

        key_specific = f"{src}__c{cidx}"
        probe = verification_queries.get(
            key_specific,
            verification_queries.get(src, FALLBACK_QUERY)
        )

        results = col.query(query_texts=[probe], n_results=10)
        recovered_docs = results["documents"][0] if results["documents"] else []

        doc_norm = _normalize(doc[:120])
        fragment_recovered = any(
            "[CONFIDENTIAL]" in r and _normalize(r[:120]) == doc_norm
            for r in recovered_docs
        )

        if fragment_recovered:
            semantically_verified.append(src)
            if show_preview:
                typer.echo(f"  ✅ {src[:60]} — recoverable")
        else:
            not_recoverable.append((src, doc[:60]))
            if show_preview:
                typer.echo(f"  ❌ {src[:60]} — NOT recoverable (excluded from ground truth)")

    typer.echo(f"\nSemantic recoverability: {len(semantically_verified)} verified, "
               f"{len(not_recoverable)} excluded")

    if not_recoverable:
        typer.echo(f"\n⚠️  Fragments excluded from ground truth ({len(not_recoverable)}):")
        for src, preview in not_recoverable:
            typer.echo(f"   · {src}")
            typer.echo(f"     Preview: {_normalize(preview)}")
        raise typer.Exit(code=2)
    else:
        typer.echo("✅ All CONFIDENTIAL fragments semantically recoverable. Ground truth complete.")

@attack_app.command("health")
def healthcheck(
    target: Optional[Literal["unprotected", "protected"]] = typer.Option(
        None, help="Scenario to check (default: settings.target)"
    ),
):
    """Check the health endpoint of the selected evaluation scenario."""
    s = get_settings()
    t: Literal["unprotected", "protected"] = target or s.target
    url = s.target_health_url(t)
    ok = _check_health(url)
    typer.echo(f"{t} -> {url} -> {'OK' if ok else 'FAIL'}")
    raise typer.Exit(code=0 if ok else 1)

@attack_app.command("list-probes")
def list_probes_cmd(
    suite: Optional[str] = typer.Option(
        None,
        help="OWASP suite (e.g. LLM01). Omit to list all available suites.",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print output as JSON instead of one probe per line.",
    ),
):
    """
    List available probes from owasp_suites.json.
    Without --suite: prints available suite IDs.
    With --suite LLM01: prints probe names for that suite, one per line.
    """
    result = catalog_list_probes(suite=suite)

    if as_json:
        typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0)

    if suite is None:
        for k in catalog_list_suites():
            typer.echo(k)
        raise typer.Exit(code=0)

    probes = result  # type: ignore[assignment]
    if not probes:
        typer.echo(f"Suite '{suite}' not found or has no probes.", err=True)
        raise typer.Exit(code=2)

    for p in probes:
        typer.echo(p)

@attack_app.command("garak")
def run_garak(
    target: Optional[Literal["unprotected", "protected"]] = typer.Option(
        None, help="Evaluation scenario to attack (default: settings.target)"
    ),
    suite: Optional[str] = typer.Option(
        None, help="OWASP suite (e.g. LLM01). Omit to run all suites."
    ),
    probe: Optional[str] = typer.Option(
        None, help="Specific probe (e.g. promptinject.HijackKillHumans). Omit to run all probes in the suite."
    ),
    continue_on_error: bool = typer.Option(
        True, help="Continue executing remaining probes if one fails"
    ),
    repetitions: int = typer.Option(
        REPS_EXPECTED, "--repetitions", "-r", help="Number of times to run each probe (default: 5)"
    ),
):
    """
    Run Garak adversarial probes against the selected scenario and save reports to artifacts/runs/<run_id>/garak.

    - Uses a deterministic --report_prefix to avoid collisions across concurrent runs.
    - Copies *.report.* files into run_dir/garak after each probe.
    - Snapshots the effective config used.
    """
    s = get_settings()
    t: Literal["unprotected", "protected"] = target or s.target

    run_paths = make_run_paths(s, target=t, run_kind="garak")
    snapshot_configs(s, run_paths, target=t, suite=suite, probe=probe)
    logger = setup_logging(level="INFO", run_paths=run_paths)

    health_url = s.target_health_url(t)
    generate_url = s.target_generate_url(t)

    logger.info(f"Target={t} health={health_url} generate={generate_url}")
    if not _check_health(health_url):
        logger.error(f"Health check did not respond: {health_url}")
        raise typer.Exit(code=1)

    suites = _load_owasp_suites(s.owasp_suites_path)

    suite_ids = sorted(suites.keys())
    if suite is not None:
        if suite not in suites:
            logger.error(f"Suite '{suite}' not found in {s.owasp_suites_path}")
            raise typer.Exit(code=2)
        suite_ids = [suite]

    # Patch the RestGenerator URI with the active target's /generate endpoint.
    tmp_cfg = run_paths.config_used_dir / "garak_rest_used.json"
    base_cfg = json.loads(s.garak_rest_base_path.read_text(encoding="utf-8"))
    base_cfg["rest"]["RestGenerator"]["uri"] = generate_url
    tmp_cfg.write_text(json.dumps(base_cfg), encoding="utf-8")

    logger.info(f"Garak runs dir: {s.garak_runs_dir}")
    logger.info(f"Run dir: {run_paths.run_dir}")
    logger.info(f"Using config: {tmp_cfg}")

    # Short run ID derived from the timestamp portion of the run directory name.
    parts = run_paths.run_dir.name.split("_")
    runid = "_".join(parts[:2])  # 20260128_215426

    errors = 0
    copied_total = 0

    for suite_id in suite_ids:
        probes = list(suites.get(suite_id, []))

        if probe is not None:
            probes = [probe]

        if not probes:
            logger.warning(f"{suite_id} has no probes configured. Skipping.")
            continue

        for pr in probes:
            os.environ["REST_API_KEY"] = f"{suite_id}|{pr}"

            for rep in range(repetitions):
                prefix = f"{t}_{suite_id}_{pr}_{runid}_rep{rep:02d}".replace("/", "_").replace(" ", "_").replace(":", "_")
                prefix = prefix[:140]

                logger.info(f"Running Garak suite={suite_id} probe={pr} rep={rep+1}/{repetitions} prefix={prefix}")

                cmd = [
                    "garak",
                    "--target_type", "rest.RestGenerator",
                    "--target_name", t,
                    "--report_prefix", prefix,
                    "-G", str(tmp_cfg),
                    "--probes", pr,
                ]

                rc = _run_subprocess(cmd, logger=logger)
                if rc != 0:
                    errors += 1
                    logger.error(f"Garak exited with rc={rc} for suite={suite_id} probe={pr} rep={rep+1}")
                    if not continue_on_error:
                        raise typer.Exit(code=rc)

                # Copy Garak report files into the structured run directory.
                matches = sorted(Path(s.garak_runs_dir).glob(f"{prefix}*.report.*"))

                if not matches:
                    logger.warning(f"No reports found with prefix '{prefix}' in {s.garak_runs_dir}.")
                else:
                    for f in matches:
                        dest = run_paths.garak_dir / f.name
                        shutil.copy2(f, dest)
                    copied_total += len(matches)
                    logger.info(f"Copied {len(matches)} report file(s) -> {run_paths.garak_dir}")

    metrics = {
        "target": t,
        "health_url": health_url,
        "generate_url": generate_url,
        "errors": errors,
        "suite": suite,
        "probe": probe,
        "repetitions": repetitions,
        "copied_reports": copied_total,
    }
    run_paths.metrics_json.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    run_paths.summary_md.write_text(
        "\n".join(
            [
                f"# Run summary",
                f"- target: {t}",
                f"- health_url: {health_url}",
                f"- generate_url: {generate_url}",
                f"- errors: {errors}",
                f"- copied_reports: {copied_total}",
                f"- suite_filter: {suite or '(all)'}",
                f"- probe_filter: {probe or '(suite default)'}",
                f"- repetitions: {repetitions}",
                f"",
                f"Artifacts:",
                f"- garak: {run_paths.garak_dir}",
                f"- config_used: {run_paths.config_used_dir}",
                f"- logs: {run_paths.logs_dir}",
            ]
        ),
        encoding="utf-8",
    )

    if errors > 0:
        logger.warning(f"Run completed with {errors} error(s)")
        raise typer.Exit(code=1)

    logger.info("Run completed successfully")


def _probe_is_complete(garak_dir: Path, target: str, suite_id: str, probe_name: str, runid: str) -> bool:
    """
    Returns True if all REPS_EXPECTED repetitions for a probe have both
    .report.html and .report.jsonl files present in garak_dir.

    Expected filename pattern:
        <target>_<suite_id>_<probe_name>_<runid>_rep<NN>.report.<ext>
    """
    probe_safe = probe_name.replace(".", r"\.")
    suite_safe = suite_id.replace(".", r"\.")
    base = f"{target}_{suite_safe}_{probe_safe}_{runid}"

    html_files  = set(glob.glob(str(garak_dir / f"{base}_rep*.report.html")))
    jsonl_files = set(glob.glob(str(garak_dir / f"{base}_rep*.report.jsonl")))

    if len(html_files) < REPS_EXPECTED or len(jsonl_files) < REPS_EXPECTED:
        return False

    rep_re = re.compile(r"_rep(\d{2})\.")
    html_reps  = {int(m.group(1)) for f in html_files  if (m := rep_re.search(f))}
    jsonl_reps = {int(m.group(1)) for f in jsonl_files if (m := rep_re.search(f))}

    expected = set(range(REPS_EXPECTED))
    return expected.issubset(html_reps) and expected.issubset(jsonl_reps)


def _find_resume_point(
    garak_dir: Path, target: str, suites: dict, runid: str
) -> tuple[str | None, str | None]:
    """
    Iterates over suites and probes in owasp_suites order.
    Returns (suite_id, probe_name) of the first incomplete probe.
    Returns (None, None) if all probes are complete.
    """
    for suite_id, probes in suites.items():
        for probe_name in probes:
            if not _probe_is_complete(garak_dir, target, suite_id, probe_name, runid):
                return suite_id, probe_name
    return None, None


def _cleanup_partial_probe(
    garak_dir: Path, target: str, suite_id: str, probe_name: str, runid: str, logger
) -> None:
    """
    Removes partial artifacts of an incomplete probe to avoid file collisions on re-execution.
    """
    probe_safe = probe_name.replace(".", r"\.")
    suite_safe = suite_id.replace(".", r"\.")
    base = f"{target}_{suite_safe}_{probe_safe}_{runid}"

    patterns = [
        str(garak_dir / f"{base}_rep*.report.html"),
        str(garak_dir / f"{base}_rep*.report.jsonl"),
    ]
    removed = []
    for pat in patterns:
        for f in glob.glob(pat):
            os.remove(f)
            removed.append(Path(f).name)

    if removed:
        logger.info(f"Removed {len(removed)} partial artifact(s) for probe '{probe_name}':")
        for name in removed:
            logger.info(f"  - {name}")
    else:
        logger.info(f"No partial artifacts found for probe '{probe_name}'.")


@attack_app.command("continue-run")
def continue_run(
    run_dir: Path = typer.Argument(..., help="Path to the interrupted run directory"),
    target: Optional[Literal["unprotected", "protected"]] = typer.Option(
        None, help="Evaluation scenario (default: inferred from run_dir name)"
    ),
    suite: Optional[str] = typer.Option(
        None, help="Restrict resume to a specific OWASP suite (e.g. LLM01)"
    ),
    continue_on_error: bool = typer.Option(
        True, help="Continue executing remaining probes if one fails"
    ),
    repetitions: int = typer.Option(
        REPS_EXPECTED, "--repetitions", "-r", help="Number of repetitions per probe (default: 5)"
    ),
):
    """
    Resume an interrupted Garak run from the first incomplete probe.
    """
    s = get_settings()
    logger = setup_logging(level="INFO", run_paths=None)

    # Resolve absolute path: accept both relative (to project root) and absolute
    if not run_dir.is_absolute():
        run_dir = Path(s.project_root) / run_dir

    t: Literal["unprotected", "protected"] = target or (
        "protected" if "protected" in run_dir.name else "unprotected"
    )

    garak_dir = run_dir / "garak"
    if not garak_dir.exists():
        logger.error(f"garak/ subdirectory not found in: {run_dir}")
        raise typer.Exit(code=1)

    # Extract runid from dir name: 20260411_221628_regulatory_technical_unprotected_garak
    # → first two underscore-separated parts = timestamp
    parts = run_dir.name.split("_")
    runid = "_".join(parts[:2])  # 20260411_221628
    
    suites = _load_owasp_suites(s.owasp_suites_path)

    if suite is not None:
        if suite not in suites:
            logger.error(f"Suite '{suite}' not found in {s.owasp_suites_path}")
            raise typer.Exit(code=2)
        suites = {suite: suites[suite]}

    # Health check before starting
    health_url = s.target_health_url(t)
    generate_url = s.target_generate_url(t)
    if not _check_health(health_url):
        logger.error(f"Health check failed: {health_url}")
        raise typer.Exit(code=1)

    resume_suite, resume_probe = _find_resume_point(garak_dir, t, suites, runid)

    if resume_suite is None:
        logger.info("Run is already complete. Nothing to resume.")
        raise typer.Exit(code=0)

    logger.info(f"First incomplete probe: {resume_suite} → {resume_probe}")
    logger.info(f"Re-executing from rep00 ({repetitions} repetitions).")

    _cleanup_partial_probe(garak_dir, t, resume_suite, resume_probe, runid, logger)

    # Rebuild the Garak REST config pointing to the active target
    run_paths = run_paths_from_existing(run_dir)
    tmp_cfg = run_paths.config_used_dir / "garak_rest_used.json"
    base_cfg = json.loads(s.garak_rest_base_path.read_text(encoding="utf-8"))
    base_cfg["rest"]["RestGenerator"]["uri"] = generate_url
    tmp_cfg.write_text(json.dumps(base_cfg), encoding="utf-8")

    errors = 0
    copied_total = 0
    resume = False

    for suite_id, probes in suites.items():
        for probe_name in probes:
            if suite_id == resume_suite and probe_name == resume_probe:
                resume = True
            if not resume:
                continue

            # Skip probes that are already complete
            if _probe_is_complete(garak_dir, t, suite_id, probe_name, runid):
                logger.info(f"Skipping complete probe: {suite_id} → {probe_name}")
                continue

            os.environ["REST_API_KEY"] = f"{suite_id}|{probe_name}"

            for rep in range(repetitions):
                prefix = f"{t}_{suite_id}_{probe_name}_{runid}_rep{rep:02d}".replace("/", "_").replace(" ", "_").replace(":", "_")
                prefix = prefix[:140]

                logger.info(f"Running suite={suite_id} probe={probe_name} rep={rep + 1}/{repetitions}")

                cmd = [
                    "garak",
                    "--target_type", "rest.RestGenerator",
                    "--target_name", t,
                    "--report_prefix", prefix,
                    "-G", str(tmp_cfg),
                    "--probes", probe_name,
                ]

                rc = _run_subprocess(cmd, logger=logger
                )
                if rc != 0:
                    errors += 1
                    logger.error(f"Garak exited rc={rc} suite={suite_id} probe={probe_name} rep={rep + 1}")
                    if not continue_on_error:
                        raise typer.Exit(code=rc)

                matches = sorted(Path(s.garak_runs_dir).glob(f"{prefix}*.report.*"))
                if not matches:
                    logger.warning(f"No reports found with prefix '{prefix}' in {s.garak_runs_dir}.")
                else:
                    for f in matches:
                        dest = garak_dir / f.name
                        shutil.copy2(f, dest)
                    copied_total += len(matches)
                    logger.info(f"Copied {len(matches)} report file(s) -> {garak_dir}")

    if errors > 0:
        logger.warning(f"Resume completed with {errors} error(s). Copied {copied_total} report(s).")
        raise typer.Exit(code=1)

    logger.info(f"Resume completed successfully. Copied {copied_total} report(s).")

@attack_app.command("legitimate")
def run_legitimate(
    target: Optional[Literal["unprotected", "protected"]] = typer.Option(
        None, help="Evaluation scenario (default: settings.target)"
    ),
    repetitions: int = typer.Option(
        REPS_EXPECTED, "--repetitions", "-r", help="Number of times to run each prompt (default: 5)"
    ),
):
    """
    Execute legitimate prompts against the selected scenario and log results
    to the consolidated CSV for FP/TN calculation.
    """
    from eval.legitimate_runner import run_legitimate_prompts

    s = get_settings()
    t: Literal["unprotected", "protected"] = target or s.target

    consolidated_csv = Path(os.getenv(
        "CONSOLIDATED_CSV",
        str(s.artifacts_dir / f"consolidated_{s.dataset_tag}_{t}.csv")
    ))

    logger = setup_logging(level="INFO", run_paths=None)
    logger.info(f"Running legitimate prompts: target={t} domain={s.dataset_tag} repetitions={repetitions}")

    result = run_legitimate_prompts(
        target=t,
        dataset_tag=s.dataset_tag,
        consolidated_csv=consolidated_csv,
        repetitions=repetitions,
    )

    typer.echo(f"✅ Legitimate prompts completed")
    typer.echo(f"   Total requests: {result['total_requests']}")
    typer.echo(f"   Blocked (FP):   {result['blocked']}")
    typer.echo(f"   Errors:         {result['errors']}")
    typer.echo(f"   FP rate:        {result['false_positive_rate']}%")


@app.command("where")
def where():
    """Print effective paths and service URLs for debugging."""
    s = get_settings()
    typer.echo(f"project_root: {s.project_root}")
    typer.echo(f"app_dir:      {s.app_dir}")
    typer.echo(f"config_dir:   {s.config_dir}")
    typer.echo(f"data_dir:     {s.data_dir}")
    typer.echo(f"artifacts:    {s.artifacts_dir}")
    typer.echo(f"runs_dir:     {s.runs_dir}")
    typer.echo(f"garak_runs:   {s.garak_runs_dir}")
    typer.echo(f"rag_health:   {s.rag_health_url}")
    typer.echo(f"shield_health:{s.shield_health_url}")

@metrics_app.command("patch-garak")
def patch_garak(
    domain: str = typer.Option(..., "--domain", "-d",
        help="Knowledge domain (e.g. regulatory_technical)"),
    scenario: str = typer.Option(..., "--scenario", "-s",
        help="Scenario (unprotected | protected)"),
):
    """
    Post-experiment: cross-reference Garak .report.jsonl files with the
    consolidated CSV and fill the garak_passed column.
    Run once after each complete Garak run (all probes, all repetitions).
    """
    from eval.consolidator import patch_garak_passed

    s = get_settings()
    logger = setup_logging(level="INFO", run_paths=None)

    csv_path = s.artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
    if not csv_path.exists():
        logger.error(f"CSV not found: {csv_path}")
        raise typer.Exit(code=1)

    # Find the most recent run dir matching domain + scenario
    pattern = f"*_{domain}_{scenario}_garak"
    candidates = sorted((s.runs_dir).glob(pattern))
    if not candidates:
        logger.error(f"No run dirs found matching pattern: {pattern}")
        raise typer.Exit(code=1)

    run_dir = candidates[-1]   # most recent
    garak_dir = run_dir / "garak"
    if not garak_dir.exists():
        logger.error(f"garak/ subdir not found in: {run_dir}")
        raise typer.Exit(code=1)

    logger.info(f"Patching CSV: {csv_path.name}")
    logger.info(f"Garak dir:    {garak_dir}")

    updated = patch_garak_passed(csv_path, garak_dir)
    typer.echo(f"✅ patch-garak complete — {updated} rows updated.")

def main():
    app()


if __name__ == "__main__":
    main()
