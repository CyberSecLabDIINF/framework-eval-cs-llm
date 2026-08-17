#!/usr/bin/env python3
"""Standalone behavioral test for the is_protected header-propagation fix (item 58).

Verifies, without containers, without real Ollama/ChromaDB, and without touching
docker-compose.yml or artifacts/:

  PART A — shield.py's _extract_forward_headers() adds {"x-scenario": "protected"}
           to every forwarded request, unconditionally.

  PART B — rag.py's generate() gates the six defence-control functions on the
           per-request `is_protected` value derived from the x-scenario header,
           instead of the old module-level IS_PROTECTED constant.

Run: python3 test_is_protected_propagation.py
Discardable script — not wired into any test runner, not added to git unless
requested.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "app" / "src"))

# --- Settings env vars normally provided by the container; set here so
# --- get_settings() validates outside Docker, without touching .env files.
os.environ.setdefault("APP_DIR", str(REPO_ROOT / "app"))
os.environ.setdefault("DATA_DIR", str(REPO_ROOT / "data"))
os.environ.setdefault("ARTIFACTS_DIR", str(REPO_ROOT / "artifacts"))
os.environ.setdefault("GARAK_RUNS_DIR", str(REPO_ROOT / "artifacts" / "runs"))
os.environ.setdefault("CHROMA_DB_PATH", str(REPO_ROOT / "chroma_db"))
os.environ.setdefault("CONFIG_DIR", str(REPO_ROOT / "app" / "config"))
os.environ.setdefault("OWASP_SUITES_PATH", str(REPO_ROOT / "app" / "config" / "global" / "owasp_suites.json"))
os.environ.setdefault("GARAK_REST_BASE_PATH", str(REPO_ROOT / "app" / "config" / "global" / "garak_rest_base.json"))
os.environ.setdefault("RUNS_DIR", str(REPO_ROOT / "artifacts" / "runs"))
os.environ.setdefault("LATENCY_DIR", str(REPO_ROOT / "artifacts" / "latency"))
os.environ.setdefault("DATASET_TAG", "regulatory_technical")

results = []


def check(description, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((description, condition))
    print(f"[{status}] {description}" + (f" — {detail}" if detail else ""))
    if not condition:
        raise AssertionError(f"{description} — {detail}")


# ============================================================
# PART A — shield.py: _extract_forward_headers adds x-scenario
# ============================================================
print("=== PARTE A: shield._extract_forward_headers ===")

# llm_guard pulls in heavy ML deps (transformers/spacy/presidio); stub it and
# its submodules so importing api.shield doesn't require installing them.
sys.modules["llm_guard"] = MagicMock()
sys.modules["llm_guard.input_scanners"] = MagicMock()
sys.modules["llm_guard.output_scanners"] = MagicMock()

import api.shield as shield_mod  # noqa: E402


class FakeRequest:
    """Minimal stand-in for fastapi.Request — _extract_forward_headers only
    touches .headers.get(...)."""

    def __init__(self, headers: dict):
        self.headers = headers


fake_req = FakeRequest(
    {
        "x-request-id": "req-123",
        "x-garak-tag": "dan.Dan_11_0",
        "x-run-id": "run-abc",
        "x-run-kind": "experiment",
    }
)

headers_out = shield_mod._extract_forward_headers(fake_req)
print(f"  headers_out = {headers_out!r}")

check(
    "x-scenario header present with exact value 'protected'",
    headers_out.get("x-scenario") == "protected",
    f"got={headers_out.get('x-scenario')!r}",
)
check(
    "x-forwarded-by unchanged (still 'shield')",
    headers_out.get("x-forwarded-by") == "shield",
    f"got={headers_out.get('x-forwarded-by')!r}",
)
check(
    "no key-name typo: exact string 'x-scenario' present in dict keys",
    "x-scenario" in headers_out,
    f"keys={list(headers_out.keys())}",
)

# Confirm the value is a bare literal, not conditioned on the (unrelated) run_id
# / garak_tag / run_kind headers being present or absent.
fake_req_minimal = FakeRequest({})
headers_out_minimal = shield_mod._extract_forward_headers(fake_req_minimal)
check(
    "x-scenario still 'protected' even with no other headers present (literal, unconditional)",
    headers_out_minimal.get("x-scenario") == "protected",
    f"got={headers_out_minimal.get('x-scenario')!r}",
)


# ============================================================
# PART B — rag.py: is_protected gates the control functions
# ============================================================
print("\n=== PARTE B: rag.generate() control gating ===")

import api.rag as rag_mod  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import api.middleware as middleware_mod  # noqa: E402


async def _passthrough_dispatch(self, request, call_next):
    """Replacement for LatencyCSVLogger.dispatch that skips the CSV append
    entirely. rag.py registers this middleware on the app unconditionally
    (app.add_middleware(...) at import time, latency_unprotected_direct.csv /
    latency_unprotected_via_shield.csv), so without this patch every
    TestClient request would append a real row to artifacts/latency/*.csv."""
    return await call_next(request)


patch.object(middleware_mod.LatencyCSVLogger, "dispatch", _passthrough_dispatch).start()

CONTROL_NAMES = [
    "validate_system_prompt_integrity",
    "is_on_domain",
    "is_coherent_query",
    "is_safe_from_reconnaissance",
    "validate_corpus_integrity",
    "is_grounded_response",
]

canned_fragments = [("doc1", "canned fragment text about the regulated domain")]


def run_scenario(headers: dict):
    """POST /generate with the six controls, collection.query, client.generate
    and log_request mocked. Returns (response, mocks_dict)."""
    with patch.object(rag_mod, "validate_system_prompt_integrity", return_value=True) as m1, \
         patch.object(rag_mod, "is_on_domain", return_value=True) as m2, \
         patch.object(rag_mod, "is_coherent_query", return_value=True) as m3, \
         patch.object(rag_mod, "is_safe_from_reconnaissance", return_value=True) as m4, \
         patch.object(rag_mod, "validate_corpus_integrity", return_value=(True, None)) as m5, \
         patch.object(rag_mod, "is_grounded_response", return_value=(True, 1.0)) as m6, \
         patch.object(
             rag_mod.collection,
             "query",
             return_value={
                 "documents": [[t for _, t in canned_fragments]],
                 "ids": [[i for i, _ in canned_fragments]],
                 "distances": [[0.01]],
             },
         ) as m_query, \
         patch.object(
             rag_mod.client, "generate", return_value={"response": "canned model output"}
         ) as m_ollama, \
         patch.object(rag_mod, "log_request") as m_log:
        mocks = {
            "validate_system_prompt_integrity": m1,
            "is_on_domain": m2,
            "is_coherent_query": m3,
            "is_safe_from_reconnaissance": m4,
            "validate_corpus_integrity": m5,
            "is_grounded_response": m6,
            "collection.query": m_query,
            "client.generate": m_ollama,
            "log_request": m_log,
        }
        with TestClient(rag_mod.app) as tc:
            resp = tc.post("/generate", json={"prompt": "What is the CRMA?"}, headers=headers)
    return resp, mocks


# --- Scenario A: no x-scenario header (Garak hits rag_api directly) ---
print("\n-- Scenario A: sin header x-scenario (equivalente a Garak -> rag_api directo) --")
resp_a, mocks_a = run_scenario(headers={})

check("HTTP 200 in Scenario A", resp_a.status_code == 200, f"got={resp_a.status_code} body={resp_a.text}")
check(
    "Scenario A: response body has blocked_by_rag=False (nothing blocked)",
    resp_a.json().get("blocked_by_rag") is False,
    f"body={resp_a.json()}",
)

GATED_CONTROLS = [n for n in CONTROL_NAMES if n != "is_grounded_response"]
for name in GATED_CONTROLS:
    m = mocks_a[name]
    check(
        f"Scenario A: {name}() NOT called (is_protected=False gates it, unchanged from pre-fix behavior)",
        not m.called,
        f"call_count={m.call_count}",
    )

# FINDING: is_grounded_response() is called unconditionally at rag.py:544,
# outside any `if is_protected:` guard — only its BLOCKING effect (line 545:
# `if is_protected and not grounded:`) is gated. This was true before the fix
# too; the fix does not change this. Documenting actual behavior instead of
# assuming all six controls are call-gated identically.
check(
    "Scenario A: is_grounded_response() IS called regardless (pre-existing, unconditional call — only its block effect is gated by is_protected)",
    mocks_a["is_grounded_response"].called,
    f"call_count={mocks_a['is_grounded_response'].call_count}",
)

call_a = mocks_a["collection.query"].call_args_list[0]
where_filter_a = call_a.kwargs.get("where")
check(
    "Scenario A: C8 where_filter passed to collection.query is None (no sensitivity restriction, retrieve_context's is_protected=False branch)",
    where_filter_a is None,
    f"where={where_filter_a!r}",
)


# --- Scenario B: x-scenario: protected header (forwarded by shield_api) ---
print("\n-- Scenario B: con header x-scenario: protected (equivalente a shield_api -> rag_api) --")
resp_b, mocks_b = run_scenario(headers={"x-scenario": "protected"})

check("HTTP 200 in Scenario B", resp_b.status_code == 200, f"got={resp_b.status_code} body={resp_b.text}")
check(
    "Scenario B: response body has blocked_by_rag=False (all controls mocked to pass)",
    resp_b.json().get("blocked_by_rag") is False,
    f"body={resp_b.json()}",
)

for name in CONTROL_NAMES:
    m = mocks_b[name]
    check(
        f"Scenario B: {name}() IS called (is_protected=True activates it — this is the fix)",
        m.called,
        f"call_count={m.call_count}",
    )

call_b = mocks_b["collection.query"].call_args_list[0]
where_filter_b = call_b.kwargs.get("where")
expected_where_b = {"sensitivity": {"$in": rag_mod.ALLOWED_SENSITIVITY}}
check(
    "Scenario B: C8 where_filter passed to collection.query is the sensitivity-restriction dict",
    where_filter_b == expected_where_b,
    f"where={where_filter_b!r} expected={expected_where_b!r}",
)


# --- Cross-scenario comparison: C8 where_filter must differ ---
print("\n-- Comparación cruzada C8 --")
check(
    "C8: where_filter DIFFERS between Scenario A and Scenario B (proves the fix actually changes retrieval behavior, not just a no-op flag)",
    where_filter_a != where_filter_b,
    f"A={where_filter_a!r} vs B={where_filter_b!r}",
)

# --- artifacts/ untouched check ---
check(
    "log_request() was mocked (no real writes to artifacts/ consolidated CSV occurred)",
    mocks_a["log_request"].called and mocks_b["log_request"].called,
    f"A_calls={mocks_a['log_request'].call_count} B_calls={mocks_b['log_request'].call_count}",
)

print(f"\n=== RESULT: {len(results)}/{len(results)} assertions passed ===")
