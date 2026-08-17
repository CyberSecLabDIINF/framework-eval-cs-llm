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

print(f"\n=== RESULT (PARTE A+B): {len(results)}/{len(results)} assertions passed ===")


# ============================================================
# PART C — per-control blocking-branch verification (item 58 extension,
# morning's test only mocked controls to "pass" to isolate whether they were
# invoked; this section mocks each one to "fail" in turn and verifies
# _blocked_response() fires with the correct block_reason, isolated from the
# other five controls).
# ============================================================
print("\n=== PARTE C: rama de bloqueo por control (mock de fallo) ===")

# Pipeline order in rag.generate(): needed to know which mocks must have
# fired (upstream, passed) vs never fired (downstream, unreached because the
# pipeline returned early) for a given control's block to be well-isolated.
CONTROL_ORDER = [
    "validate_system_prompt_integrity",  # C32
    "is_on_domain",                       # C4
    "is_coherent_query",                  # C11
    "is_safe_from_reconnaissance",        # C12
    "validate_corpus_integrity",          # C9
    "is_grounded_response",               # C17
]

CONTROL_LABEL = {
    "validate_system_prompt_integrity": "C32",
    "is_on_domain": "C4",
    "is_coherent_query": "C11",
    "is_safe_from_reconnaissance": "C12",
    "validate_corpus_integrity": "C9",
    "is_grounded_response": "C17",
}

# Passing return values (same shape rag.py's morning test used).
PASS_VALUES = {
    "validate_system_prompt_integrity": True,
    "is_on_domain": True,
    "is_coherent_query": True,
    "is_safe_from_reconnaissance": True,
    "validate_corpus_integrity": (True, None),
    "is_grounded_response": (True, 1.0),
}

# Failing return values — exact signature per control, taken from rag.py:
# bool for C32/C4/C11/C12, (bool, tampered_id) for C9, (bool, ratio) for C17.
FAIL_VALUES = {
    "validate_system_prompt_integrity": False,
    "is_on_domain": False,
    "is_coherent_query": False,
    "is_safe_from_reconnaissance": False,
    "validate_corpus_integrity": (False, "doc1"),
    "is_grounded_response": (False, 0.05),
}

# Literal block_reason strings, copied verbatim from rag.py's _blocked_response
# call sites (lines 488/496/504/512/526/549) — not assumed.
EXPECTED_BLOCK_REASON = {
    "validate_system_prompt_integrity": "system_prompt_integrity_failed",
    "is_on_domain": "domain_validation_failed",
    "is_coherent_query": "query_coherence_failed",
    "is_safe_from_reconnaissance": "corpus_reconnaissance_detected",
    "validate_corpus_integrity": "corpus_integrity_failed",
    "is_grounded_response": "response_not_grounded",
}


def run_with_one_failing(failing_control: str, headers: dict):
    """POST /generate with `failing_control` mocked to its FAIL_VALUES entry
    and all other five controls mocked to PASS_VALUES. Mirrors run_scenario's
    mock set (collection.query, client.generate, log_request) so the flow
    reaches exactly as far as the real pipeline would."""
    rv = dict(PASS_VALUES)
    rv[failing_control] = FAIL_VALUES[failing_control]

    with patch.object(rag_mod, "validate_system_prompt_integrity", return_value=rv["validate_system_prompt_integrity"]) as m1, \
         patch.object(rag_mod, "is_on_domain", return_value=rv["is_on_domain"]) as m2, \
         patch.object(rag_mod, "is_coherent_query", return_value=rv["is_coherent_query"]) as m3, \
         patch.object(rag_mod, "is_safe_from_reconnaissance", return_value=rv["is_safe_from_reconnaissance"]) as m4, \
         patch.object(rag_mod, "validate_corpus_integrity", return_value=rv["validate_corpus_integrity"]) as m5, \
         patch.object(rag_mod, "is_grounded_response", return_value=rv["is_grounded_response"]) as m6, \
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


control_summary = []  # (label, control_name, protected_ok, unprotected_ok)

for failing_control in CONTROL_ORDER:
    label = CONTROL_LABEL[failing_control]
    expected_reason = EXPECTED_BLOCK_REASON[failing_control]
    idx = CONTROL_ORDER.index(failing_control)
    upstream = CONTROL_ORDER[:idx]
    downstream = CONTROL_ORDER[idx + 1:]
    pre_retrieval = ("validate_system_prompt_integrity", "is_on_domain", "is_coherent_query", "is_safe_from_reconnaissance")

    print(f"\n-- {label} ({failing_control}) --")

    # --- protected request: this control must fire and block, isolated ---
    n_before = len(results)
    try:
        resp_p, mocks_p = run_with_one_failing(failing_control, headers={"x-scenario": "protected"})
        body_p = resp_p.json()

        check(
            f"{label} protegido: HTTP status es 200 (rag.py no fija status_code en _blocked_response; el bloqueo va en blocked_by_rag/block_reason del body)",
            resp_p.status_code == 200,
            f"got={resp_p.status_code}",
        )
        check(
            f"{label} protegido: blocked_by_rag=True",
            body_p.get("blocked_by_rag") is True,
            f"body={body_p}",
        )
        check(
            f"{label} protegido: block_reason == {expected_reason!r} (string exacto de rag.py)",
            body_p.get("block_reason") == expected_reason,
            f"got={body_p.get('block_reason')!r}",
        )
        check(
            f"{label} protegido: {failing_control}() fue invocada (es la causante del bloqueo)",
            mocks_p[failing_control].called,
            f"call_count={mocks_p[failing_control].call_count}",
        )
        for up in upstream:
            check(
                f"{label} protegido: control previo {up}() SÍ fue invocado (pasó, permitiendo llegar hasta {label})",
                mocks_p[up].called,
                f"call_count={mocks_p[up].call_count}",
            )
        for down in downstream:
            check(
                f"{label} protegido: control posterior {down}() NO fue invocado (pipeline retornó antes de alcanzarlo — bloqueo aislado en {label})",
                not mocks_p[down].called,
                f"call_count={mocks_p[down].call_count}",
            )
        if failing_control in pre_retrieval:
            check(
                f"{label} protegido: collection.query() (retrieve_context) NO fue invocado — bloqueo ocurre antes de tocar ChromaDB",
                not mocks_p["collection.query"].called,
                f"call_count={mocks_p['collection.query'].call_count}",
            )
        else:
            check(
                f"{label} protegido: collection.query() (retrieve_context) SÍ fue invocado — {label} actúa después de la recuperación",
                mocks_p["collection.query"].called,
                f"call_count={mocks_p['collection.query'].call_count}",
            )
        if failing_control == "is_grounded_response":
            check(
                f"{label} protegido: client.generate() (Ollama) SÍ fue invocado — C17 evalúa la respuesta ya generada",
                mocks_p["client.generate"].called,
                f"call_count={mocks_p['client.generate'].call_count}",
            )
        else:
            check(
                f"{label} protegido: client.generate() (Ollama) NO fue invocado — bloqueo ocurre antes de generar respuesta",
                not mocks_p["client.generate"].called,
                f"call_count={mocks_p['client.generate'].call_count}",
            )
        other_reasons = [EXPECTED_BLOCK_REASON[c] for c in CONTROL_ORDER if c != failing_control]
        check(
            f"{label} protegido: block_reason no coincide con el motivo de ningún otro control (aísla la causa)",
            body_p.get("block_reason") not in other_reasons,
            f"block_reason={body_p.get('block_reason')!r} otros={other_reasons}",
        )
    except AssertionError:
        pass
    protected_ok = all(cond for _, cond in results[n_before:])

    # --- control request: same failing mock, but is_protected=False ---
    n_before2 = len(results)
    try:
        resp_u, mocks_u = run_with_one_failing(failing_control, headers={})
        body_u = resp_u.json()

        check(f"{label} sin proteger: HTTP 200", resp_u.status_code == 200, f"got={resp_u.status_code}")
        check(
            f"{label} sin proteger: blocked_by_rag=False pese a que {failing_control}() está mockeada para fallar (el gateo por is_protected sigue protegiendo)",
            body_u.get("blocked_by_rag") is False,
            f"body={body_u}",
        )
        if failing_control == "is_grounded_response":
            # Pre-existing behavior documented in PARTE B: is_grounded_response
            # is called unconditionally regardless of is_protected — only its
            # BLOCKING effect (is_protected and not grounded) is gated. So the
            # call still happens; what must hold is that its False result did
            # not block the response.
            check(
                f"{label} sin proteger: is_grounded_response() SÍ fue invocada (llamada incondicional preexistente, no forma parte del fix) pero su resultado False no bloqueó la respuesta",
                mocks_u[failing_control].called and body_u.get("blocked_by_rag") is False,
                f"called={mocks_u[failing_control].called} blocked_by_rag={body_u.get('blocked_by_rag')}",
            )
        else:
            check(
                f"{label} sin proteger: {failing_control}() NO fue invocada (todo el bloque queda gateado por is_protected=False)",
                not mocks_u[failing_control].called,
                f"call_count={mocks_u[failing_control].call_count}",
            )
    except AssertionError:
        pass
    unprotected_ok = all(cond for _, cond in results[n_before2:])

    control_summary.append((label, failing_control, protected_ok, unprotected_ok))

print("\n=== RESUMEN PARTE C (por control, lectura rápida) ===")
for label, name, prot_ok, unprot_ok in control_summary:
    print(f"{label} ({name}) bloquea correctamente en protegido: {'PASS' if prot_ok else 'FAIL'}"
          f"  |  {label} NO bloquea sin proteger (gateo intacto): {'PASS' if unprot_ok else 'FAIL'}")

total_pass = sum(1 for _, c in results if c)
print(f"\n=== RESULT (TOTAL, PARTE A+B+C): {total_pass}/{len(results)} assertions passed ===")
