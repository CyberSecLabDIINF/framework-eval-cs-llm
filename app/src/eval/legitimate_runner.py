# app/src/eval/legitimate_runner.py
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional
import httpx

from settings import get_settings
from eval.consolidator import log_request


def run_legitimate_prompts(
    *,
    target: str,
    dataset_tag: str,
    consolidated_csv: Path,
    repetitions: int = 5,
    timeout_s: float = 120.0,
    logger: Optional[logging.Logger] = None,
) -> dict:
    """
    Execute legitimate prompts against the target endpoint and log results
    to the consolidated CSV.

    Args:
        target: Evaluation scenario — ``"unprotected"`` or ``"protected"``.
        dataset_tag: Domain tag (e.g. ``"regulatory_technical"``).
        consolidated_csv: Path to the consolidated results CSV.
        repetitions: Number of times each prompt is executed.
        timeout_s: Per-request HTTP timeout in seconds.
        logger: Optional logger instance; a default logger is used when ``None``.

    Returns:
        A dict summarising the run with keys ``target``, ``domain``,
        ``prompts``, ``repetitions``, ``total_requests``, ``blocked``,
        ``errors``, and ``false_positive_rate``.

    Raises:
        FileNotFoundError: If the legitimate prompts config file is missing.
        RuntimeError: If the target service is unhealthy at startup.
    """
    if logger is None:
        logger = logging.getLogger("framework_eval_cs_llm")

    s = get_settings()

    prompts_path = s.get_legitimate_prompts_path(dataset_tag)
    if not prompts_path.exists():
        raise FileNotFoundError(f"Legitimate prompts file not found: {prompts_path}")

    prompts = json.loads(prompts_path.read_text(encoding="utf-8"))

    generate_url = s.target_generate_url(target)
    health_url = s.target_health_url(target)

    try:
        resp = httpx.get(health_url, timeout=5.0)
        if resp.status_code != 200:
            raise RuntimeError(f"Target {target} health check failed: {resp.status_code}")
    except Exception as e:
        raise RuntimeError(f"Target {target} unreachable: {e}")

    total = 0
    errors = 0
    blocked = 0
    total_requests = len(prompts) * repetitions
    i = 0

    for prompt_obj in prompts:
        prompt_id = prompt_obj["id"]
        prompt_text = prompt_obj["prompt"]
        subdimension = prompt_obj.get("subdimension", "")

        for rep in range(repetitions):
            i += 1
            logger.info(
                "Running legitimate prompt %d/%d id=%s subdimension=%s",
                i, total_requests, prompt_id, subdimension,
            )
            start = time.perf_counter()
            was_blocked = False
            scanner_triggered = None
            response_text = ""

            try:
                resp = httpx.post(
                    generate_url,
                    json={"prompt": prompt_text},
                    timeout=timeout_s,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                data = resp.json()
                response_text = str(data.get("response", ""))

                if "Blocked:" in response_text:
                    was_blocked = True
                    scanner_triggered = "LLMGuard"
                    blocked += 1

                logger.info(
                    "  → latency=%.0fms blocked=%s scanner=%s",
                    elapsed_ms, was_blocked, scanner_triggered or "none",
                )

            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                response_text = f"ERROR: {e}"
                errors += 1
                logger.warning("  ✗ Error: %s", e)

            log_request(
                consolidated_csv,
                scenario=target,
                domain=dataset_tag,
                prompt=prompt_text,
                response=response_text,
                latency_ms=elapsed_ms,
                was_blocked=was_blocked,
                scanner_triggered=scanner_triggered,
                garak_tag="",
                prompt_type="legitimate",
                repetition=rep,
                should_block=0,
            )
            total += 1

    return {
        "target": target,
        "domain": dataset_tag,
        "prompts": len(prompts),
        "repetitions": repetitions,
        "total_requests": total,
        "blocked": blocked,
        "errors": errors,
        "false_positive_rate": round(blocked / total * 100, 2) if total > 0 else 0.0,
    }