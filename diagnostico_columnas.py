"""
Diagnostico rapido: muestra los valores unicos de las columnas relevantes
(scenario, domain, scanner_triggered, block_reason, was_blocked) sin asumir
nada sobre su formato, para poder armar el filtro correcto despues.

Uso:
    python3 diagnostico_columnas.py artifacts/consolidated_academic_institutional_protected.csv
"""

import csv
import sys
from collections import Counter

COLUMNS_OF_INTEREST = [
    "scenario",
    "domain",
    "was_blocked",
    "scanner_triggered",
    "block_reason",
    "run_id",
]


def main(path: str) -> None:
    value_counts = {col: Counter() for col in COLUMNS_OF_INTEREST}
    total_rows = 0

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        missing = [c for c in COLUMNS_OF_INTEREST if c not in fieldnames]
        if missing:
            print(f"ADVERTENCIA: columnas no encontradas en el CSV: {missing}")

        for row in reader:
            total_rows += 1
            for col in COLUMNS_OF_INTEREST:
                if col in row:
                    value_counts[col][row[col]] += 1

    print(f"Archivo: {path}")
    print(f"Filas totales: {total_rows}\n")

    for col in COLUMNS_OF_INTEREST:
        counts = value_counts[col]
        if not counts:
            continue
        print(f"--- Columna: {col} ({len(counts)} valores distintos) ---")
        # Si hay pocos valores distintos, los mostramos todos con su conteo.
        # Si hay muchos (ej. texto libre en block_reason), mostramos solo los 15 mas frecuentes.
        for value, n in counts.most_common(15):
            display_value = value if value != "" else "(vacio)"
            print(f"  {display_value!r}: {n}")
        if len(counts) > 15:
            print(f"  ... y {len(counts) - 15} valores distintos mas")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 diagnostico_columnas.py /ruta/al/csv_consolidado.csv")
        sys.exit(1)
    main(sys.argv[1])
