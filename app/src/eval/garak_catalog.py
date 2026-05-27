from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from settings import get_settings


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_suites(path: Optional[Path] = None) -> Dict[str, List[str]]:
    """
    Load the OWASP suite catalog from owasp_suites.json.
    Returns a mapping of suite ID to probe names: {"LLM01": ["promptinject....", ...], ...}
    """
    s = get_settings()
    p = path or s.owasp_suites_path
    data = _load_json(p)

    suites: Dict[str, List[str]] = {}
    for k, v in data.items():
        if isinstance(v, list):
            suites[str(k)] = [str(x) for x in v]
        else:
            suites[str(k)] = []
    return suites


def list_suites(path: Optional[Path] = None) -> List[str]:
    """Return sorted suite IDs available in the catalog (e.g. LLM01..LLM10)."""
    suites = load_suites(path)
    return sorted(suites.keys())


def list_probes(
    suite: str,
    path: Optional[Path] = None,
    prefix: Optional[str] = None,
) -> List[str]:
    """
    Return probe names for a given suite.
    If prefix is given, only probes whose name starts with that prefix are returned
    (e.g. prefix="promptinject.").
    """
    suites = load_suites(path)
    probes = suites.get(suite, []) or []
    if prefix:
        probes = [p for p in probes if p.startswith(prefix)]
    return probes
