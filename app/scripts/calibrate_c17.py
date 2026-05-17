#!/usr/bin/env python3
"""
C17 Calibration Script: Context-Grounded Response Validation

Determines the optimal C17_GROUNDING_THRESHOLD by measuring the token overlap
ratio between legitimate model responses and their retrieved context.

The threshold is set at the p5 of grounding ratios observed on legitimate
queries — meaning only 5% of legitimate responses would be blocked by C17.

This calibration must be run AFTER ingestion and BEFORE the experiment,
with the lab stack running in protected mode (Scenario B).

Usage:
    python app/scripts/calibrate_c17.py --domain regulatory_technical
    python app/scripts/calibrate_c17.py --domain academic_institutional
"""

import json
import sys
import argparse
import csv
import string
import time
from pathlib import Path
from typing import List, Dict

import httpx
import chromadb

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from settings import get_settings

# ---------------------------------------------------------------------------
# Stop words and tokenizer — must match the implementation in rag.py exactly.
# ---------------------------------------------------------------------------
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
    "into", "through", "during", "before", "after", "above", "below",
    "and", "but", "or", "nor", "so", "yet", "both", "either", "neither",
    "not", "no", "if", "then", "that", "this", "these", "those", "it",
    "its", "i", "you", "he", "she", "we", "they", "what", "which", "who",
})


def _tokenize(text: str) -> set:
    translator = str.maketrans("", "", string.punctuation)
    tokens = text.lower().translate(translator).split()
    return {t for t in tokens if len(t) >= 4 and t not in _STOP_WORDS}


def compute_grounding_ratio(response: str, context: str) -> float:
    """
    Compute token overlap ratio between response and context.
    Returns 1.0 for empty responses or responses with no significant tokens.
    Returns 0.0 for empty context (fail closed).
    """
    if not response.strip():
        return 1.0
    if not context.strip():
        return 0.0
    response_tokens = _tokenize(response)
    if not response_tokens:
        return 1.0
    context_tokens = _tokenize(context)
    overlap = response_tokens & context_tokens
    return len(overlap) / len(response_tokens)


def load_legitimate_prompts(domain: str, s) -> List[Dict]:
    """Load legitimate prompts from the domain-specific JSON file."""
    candidates = [
        s.project_root / f"legitimate_prompts_{domain}.json",
        s.project_root / "app" / "data" / f"legitimate_prompts_{domain}.json",
        s.project_root / "app" / "config" / "domains" / domain / "legitimate_prompts.json",
    ]
    for path in candidates:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(
        f"Legitimate prompts not found for domain '{domain}'. "
        f"Tried: {[str(p) for p in candidates]}"
    )


def compute_statistics(ratios: List[float]) -> Dict[str, float]:
    valid = sorted(r for r in ratios if r is not None)
    if not valid:
        return {}
    n = len(valid)
    return {
        "min":    valid[0],
        "max":    valid[-1],
        "mean":   sum(valid) / n,
        "median": valid[n // 2],
        "p5":     valid[max(0, int(n * 0.05))],
        "p25":    valid[int(n * 0.25)],
    }


def retrieve_context_direct(collection, query: str, k: int = 3) -> str:
    """
    Replicate the same retrieval that rag.py performs, without sensitivity
    filter (calibration runs against the full corpus).
    """
    try:
        results = collection.query(
            query_texts=[query],
            n_results=k,
            include=["documents"],
        )
        docs = results.get("documents", [[]])[0] or []
        return "\n\n".join(docs)
    except Exception as e:
        print(f"  [!] ChromaDB query failed: {e}")
        return ""


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate C17 (Context-Grounded Response Validation) threshold"
    )
    parser.add_argument(
        "--domain",
        required=True,
        choices=["regulatory_technical", "academic_institutional"],
    )
    parser.add_argument(
        "--target",
        default="unprotected",
        choices=["unprotected", "protected"],
        help="Scenario to query (default: unprotected — no Shield interference)",
    )
    parser.add_argument("--output", default=None)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    s = get_settings()

    # Load prompts
    print(f"\n[*] Loading legitimate prompts for domain: {args.domain}")
    prompts = load_legitimate_prompts(args.domain, s)
    print(f"    Prompts loaded: {len(prompts)}")

    # Connect to ChromaDB directly for context retrieval
    print(f"\n[*] Connecting to ChromaDB at {s.chroma_db_path}")
    chroma_client = chromadb.PersistentClient(path=str(s.chroma_db_path))
    collection = chroma_client.get_or_create_collection(name=args.domain)
    print(f"    Collection '{args.domain}' has {collection.count()} documents")

    # Build generate URL
    generate_url = s.target_generate_url(args.target)
    health_url = s.target_health_url(args.target)
    print(f"\n[*] Target: {args.target} → {generate_url}")

    # Health check
    try:
        resp = httpx.get(health_url, timeout=5.0)
        if resp.status_code != 200:
            print(f"[!] Health check failed: {resp.status_code}")
            sys.exit(1)
        print(f"    Health: OK")
    except Exception as e:
        print(f"[!] Target unreachable: {e}")
        sys.exit(1)

    # Run prompts and collect grounding ratios
    print(f"\n[*] Running {len(prompts)} prompts and measuring grounding ratios...")
    results = []
    errors = 0

    for i, prompt_obj in enumerate(prompts, 1):
        prompt_text = prompt_obj["prompt"] if isinstance(prompt_obj, dict) else prompt_obj
        prompt_id = prompt_obj.get("id", f"p{i:03d}") if isinstance(prompt_obj, dict) else f"p{i:03d}"

        try:
            # Retrieve context directly from ChromaDB
            context_text = retrieve_context_direct(collection, prompt_text, k=3)

            # Query the RAG endpoint for the model response
            resp = httpx.post(
                generate_url,
                json={"prompt": prompt_text},
                timeout=args.timeout,
            )
            data = resp.json()
            response_text = str(data.get("response", ""))

            ratio = compute_grounding_ratio(response_text, context_text)
            results.append({
                "id":           prompt_id,
                "prompt":       prompt_text[:100],
                "ratio":        ratio,
                "response_len": len(response_text),
                "context_len":  len(context_text),
                "status":       "ok",
            })
            print(f"    [{i:02d}/{len(prompts)}] ratio={ratio:.3f}  {prompt_text[:60]}")

        except Exception as e:
            errors += 1
            print(f"    [{i:02d}/{len(prompts)}] ERROR: {e}")
            results.append({
                "id": prompt_id, "prompt": prompt_text[:100],
                "ratio": None, "response_len": 0,
                "context_len": 0, "status": f"error: {e}",
            })

        time.sleep(0.1)

    # Statistics
    ratios = [r["ratio"] for r in results if r["ratio"] is not None]
    print(f"\n[*] Computing statistics ({len(ratios)} valid / {errors} errors)...")
    stats = compute_statistics(ratios)

    print(f"\n    Grounding ratio distribution:")
    for k, v in stats.items():
        print(f"      {k:8} = {v:.4f}")

    threshold = round(stats.get("p5", 0.15), 4)
    print(f"\n[+] SUGGESTED THRESHOLD (p5): {threshold}")
    print(f"    Meaning: only 5% of legitimate responses fall below this ratio.")

    # Write CSV
    output_file = args.output or f"calibration_c17_{args.domain}.csv"
    print(f"\n[*] Writing detailed results to {output_file}")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "prompt", "ratio", "response_len", "context_len", "status"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    # Summary
    print(f"\n{'='*70}")
    print(f"C17 CALIBRATION SUMMARY — {args.domain.upper()}")
    print(f"{'='*70}")
    print(f"Prompts run:  {len(prompts)}  |  Valid: {len(ratios)}  |  Errors: {errors}")
    print(f"Ratio stats:  min={stats.get('min','N/A'):.4f}  p5={stats.get('p5','N/A'):.4f}  median={stats.get('median','N/A'):.4f}  max={stats.get('max','N/A'):.4f}")
    print(f"\n>>> RECOMMENDED THRESHOLD: {threshold}")
    print(f"\nSet in .env.{args.domain}:")
    print(f"    C17_GROUNDING_THRESHOLD={threshold}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()