"""Shared constants for evaluation result processing.

Defines probe/suite mappings, display labels, and color palettes that are
reused across data loading (loaders.py), metrics computation (metrics.py),
and plotting (plots.py).
"""


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

PRIMARY_DETECTOR = {
    "encoding.InjectBase64": "encoding.DecodeMatch",
    "encoding.InjectHex":    "encoding.DecodeMatch",
}

SUITE_TO_SUBDIM = {
    "LLM01": "D1",
    "LLM02": "D2",
    "LLM07": "D3",
    "LLM08": "D4",
}

VECTOR_MAP = {
    "LLM01": "D1 — Input protection",
    "LLM02": "D2 — RAG context control",
    "LLM07": "D3 — Output management",
    "LLM08": "D4 — Monitoring & traceability",
}

PROBE_TO_SUITE = {
    "promptinject.HijackKillHumans":                   "LLM01",
    "promptinject.HijackHateHumans":                   "LLM01",
    "promptinject.HijackLongPrompt":                   "LLM01",
    "encoding.InjectBase64":                           "LLM01",
    "encoding.InjectHex":                              "LLM01",
    "latentinjection.LatentInjectionReport":           "LLM02",
    "latentinjection.LatentInjectionFactSnippetLegal": "LLM02",
    "latentinjection.LatentInjectionResume":           "LLM02",
    "leakreplay.GuardianComplete":                     "LLM07",
    "goodside.Tag":                                    "LLM07",
    "latentinjection.LatentWhois":                     "LLM08",
}

PROBE_SHORT = {
    "promptinject.HijackKillHumans":                   "HijackKill",
    "promptinject.HijackHateHumans":                   "HijackHate",
    "promptinject.HijackLongPrompt":                   "HijackLong",
    "encoding.InjectBase64":                           "Base64",
    "encoding.InjectHex":                              "Hex",
    "latentinjection.LatentInjectionReport":           "LatentReport",
    "latentinjection.LatentInjectionFactSnippetLegal": "LatentFact",
    "latentinjection.LatentInjectionResume":           "LatentResume",
    "leakreplay.GuardianComplete":                     "Guardian",
    "goodside.Tag":                                    "Tag",
    "latentinjection.LatentWhois":                     "LatentWhois",
}

SUITE_COLORS = {
    "LLM01": "#4C72B0",
    "LLM02": "#DD8452",
    "LLM07": "#55A868",
    "LLM08": "#C44E52",
}

SCENARIO_COLORS = {"A": "#4C72B0", "B": "#DD8452"}
