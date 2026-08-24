"""
Traza el numero de bloqueos del escaner 'Sensitive' por dominio en Escenario B,
para verificar la cifra citada en el parrafo de cap5 (226 regulatorio / 3.939 academico)
contra el CSV consolidado real.

Uso:
    python3 trace_sensitive_por_dominio.py /ruta/al/csv_consolidado.csv

Si tu CSV consolidado NO trae una columna 'scanner' o 'block_reason' por fila
(por ejemplo si el conteo de escaneres sale de un JSONL de decisiones separado,
no del CSV de Garak), este script no va a servir tal cual -- avisame y lo adapto
a esa fuente.
"""

import csv
import sys
from collections import Counter


def main(path: str) -> None:
    counts_by_domain = Counter()
    run_ids_seen = Counter()
    total_rows = 0
    scenario_b_rows = 0
    scanner_field_candidates = ["scanner", "block_reason", "input_scanner", "output_scanner"]

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []

        # Detecta que columna de escaner existe realmente en este CSV
        scanner_field = next((c for c in scanner_field_candidates if c in fieldnames), None)

        if scanner_field is None:
            print("ADVERTENCIA: no se encontro ninguna columna de escaner esperada.")
            print(f"Columnas disponibles: {fieldnames}")
            print("Este CSV probablemente no es la fuente correcta para este conteo.")
            print("Revisa si el dato viene de un JSONL de decisiones de la capa defensiva en su lugar.")
            return

        print(f"Usando columna de escaner: '{scanner_field}'")
        print(f"Columnas totales detectadas: {fieldnames}\n")

        for row in reader:
            total_rows += 1
            if row.get("scenario") != "B":
                continue
            scenario_b_rows += 1

            if row.get("run_id"):
                run_ids_seen[row["run_id"]] += 1

            scanner_value = row.get(scanner_field, "")
            if scanner_value and "sensitive" in scanner_value.lower():
                domain = row.get("domain", "UNKNOWN_DOMAIN")
                counts_by_domain[domain] += 1

    print(f"Filas totales en el CSV: {total_rows}")
    print(f"Filas de Escenario B: {scenario_b_rows}")
    print(f"run_id distintos vistos en Escenario B: {len(run_ids_seen)}")
    if len(run_ids_seen) > 1:
        print("  -> ADVERTENCIA: mas de un run_id presente. Verifica que no estes mezclando corridas.")
        for rid, n in run_ids_seen.most_common():
            print(f"     {rid}: {n} filas")
    print()
    print("Bloqueos de 'Sensitive' por dominio (Escenario B):")
    for domain, n in counts_by_domain.most_common():
        print(f"  {domain}: {n}")

    print()
    print("Comparar contra lo citado en el parrafo de cap5: 226 (regulatorio) / 3.939 (academico)")
    print("Comparar tambien contra lo que aparece en tab:scanners_dist del apendice.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 trace_sensitive_por_dominio.py /ruta/al/csv_consolidado.csv")
        sys.exit(1)
    main(sys.argv[1])
