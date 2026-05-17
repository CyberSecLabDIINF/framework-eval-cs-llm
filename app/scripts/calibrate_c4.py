#!/usr/bin/env python3
"""
C4 Calibration Script: Domain Relevance Validation

Determines the optimal DOMAIN_DISTANCE_THRESHOLD by measuring semantic distance
between ChromaDB embeddings and calibration queries (on-domain vs off-domain).

Usage:
    python app/scripts/calibrate_c4.py --domain regulatory_technical
    python app/scripts/calibrate_c4.py --domain academic_institutional --output results.csv
"""

import json
import sys
import argparse
import csv
from pathlib import Path
from typing import List, Dict, Tuple

import chromadb

# Add app/src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from settings import get_settings


def load_calibration_queries(domain: str, config_dir: Path) -> Dict[str, List[str]]:
    """Load on-domain and off-domain calibration queries from JSON."""
    calib_path = config_dir / "domains" / domain / "calibration_queries.json"
    
    if not calib_path.exists():
        raise FileNotFoundError(f"Calibration queries not found: {calib_path}")
    
    with calib_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def measure_distances(
    collection,
    queries: List[str],
    category: str,
) -> List[Dict[str, any]]:
    """Measure semantic distances for a list of queries."""
    results = []
    
    for query in queries:
        try:
            chroma_results = collection.query(
                query_texts=[query],
                n_results=1,
                include=["distances"],
            )
            distance = chroma_results["distances"][0][0]
            results.append({
                "category": category,
                "query": query,
                "distance": distance,
            })
        except Exception as e:
            print(f"Error processing query '{query[:50]}': {e}")
            results.append({
                "category": category,
                "query": query,
                "distance": None,
            })
    
    return results


def compute_statistics(distances: List[float]) -> Dict[str, float]:
    """Compute summary statistics for distances."""
    valid = [d for d in distances if d is not None]
    if not valid:
        return {}
    
    valid.sort()
    return {
        "min": min(valid),
        "max": max(valid),
        "mean": sum(valid) / len(valid),
        "median": valid[len(valid) // 2],
        "p95": valid[int(len(valid) * 0.95)],
    }


def suggest_threshold(on_domain_distances: List[float], off_domain_distances: List[float]) -> float:
    """
    Suggest an optimal threshold as the midpoint between on-domain max and off-domain min.
    Conservative approach: prefer false positives (rejecting on-domain queries) over false negatives.
    """
    on_valid = [d for d in on_domain_distances if d is not None]
    off_valid = [d for d in off_domain_distances if d is not None]
    
    if not on_valid or not off_valid:
        return 1.0  # Default fallback
    
    on_max = max(on_valid)
    off_min = min(off_valid)
    
    # Suggested threshold: midpoint between max on-domain and min off-domain
    suggested = (on_max + off_min) / 2
    
    return round(suggested, 4)


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate C4 (Domain Relevance Validation) threshold"
    )
    parser.add_argument(
        "--domain",
        required=True,
        choices=["regulatory_technical", "academic_institutional"],
        help="Domain to calibrate",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV file for detailed results (default: calibration_<domain>.csv)",
    )
    
    args = parser.parse_args()
    
    s = get_settings()
    
    # Load calibration queries
    print(f"\n[*] Loading calibration queries for domain: {args.domain}")
    calib_data = load_calibration_queries(args.domain, s.config_dir)
    on_domain_queries = calib_data["on_domain"]
    off_domain_queries = calib_data["off_domain"]
    print(f"    ON-DOMAIN: {len(on_domain_queries)} queries")
    print(f"    OFF-DOMAIN: {len(off_domain_queries)} queries")
    
    # Connect to ChromaDB
    print(f"\n[*] Connecting to ChromaDB at {s.chroma_db_path}")
    chroma_client = chromadb.PersistentClient(path=str(s.chroma_db_path))
    collection = chroma_client.get_or_create_collection(name=args.domain)
    print(f"    Collection '{args.domain}' has {collection.count()} documents")
    
    # Measure distances
    print(f"\n[*] Measuring semantic distances...")
    print(f"    Processing ON-DOMAIN queries...")
    on_results = measure_distances(collection, on_domain_queries, "on_domain")
    
    print(f"    Processing OFF-DOMAIN queries...")
    off_results = measure_distances(collection, off_domain_queries, "off_domain")
    
    all_results = on_results + off_results
    
    # Extract distances
    on_distances = [r["distance"] for r in on_results]
    off_distances = [r["distance"] for r in off_results]
    
    # Compute statistics
    print(f"\n[*] Computing statistics...")
    on_stats = compute_statistics(on_distances)
    off_stats = compute_statistics(off_distances)
    
    print(f"\n    ON-DOMAIN distances:")
    for key, val in on_stats.items():
        print(f"      {key:8} = {val:.4f}")
    
    print(f"\n    OFF-DOMAIN distances:")
    for key, val in off_stats.items():
        print(f"      {key:8} = {val:.4f}")
    
    # Suggest threshold
    suggested_threshold = suggest_threshold(on_distances, off_distances)
    print(f"\n[+] SUGGESTED THRESHOLD: {suggested_threshold}")
    print(f"    (Midpoint between on-domain max and off-domain min)")
    
    # Write detailed results to CSV
    output_file = args.output or f"calibration_{args.domain}.csv"
    print(f"\n[*] Writing detailed results to {output_file}")
    
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "query", "distance"])
        writer.writeheader()
        for row in all_results:
            writer.writerow(row)
    
    # Summary
    print(f"\n{'='*70}")
    print(f"CALIBRATION SUMMARY FOR {args.domain.upper()}")
    print(f"{'='*70}")
    print(f"ON-DOMAIN queries:  min={on_stats.get('min', 'N/A'):.4f} max={on_stats.get('max', 'N/A'):.4f} mean={on_stats.get('mean', 'N/A'):.4f}")
    print(f"OFF-DOMAIN queries: min={off_stats.get('min', 'N/A'):.4f} max={off_stats.get('max', 'N/A'):.4f} mean={off_stats.get('mean', 'N/A'):.4f}")
    print(f"\n>>> RECOMMENDED THRESHOLD: {suggested_threshold}")
    print(f"\nSet in .env.{args.domain}:")
    print(f"    DOMAIN_DISTANCE_THRESHOLD={suggested_threshold}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()