"""
Verifica el conteo de respuestas adversariales que contienen el marcador
literal '[CONFIDENTIAL]', filtrando solo la corrida de ataques (garak),
para contrastar contra las cifras citadas en cap5:77 (234 academico,
376 regulatorio, en Escenario A / unprotected).

Uso:
    python3 contar_marcador_confidential.py artifacts/consolidated_academic_institutional_unprotected.csv
    python3 contar_marcador_confidential.py artifacts/consolidated_regulatory_technical_unprotected.csv

Tambien puedes correrlo sobre los archivos 'protected' para confirmar que
efectivamente da 0 en Escenario B en ambos dominios.
"""

import csv
import sys
from collections import Counter

MARKER = "[CONFIDENTIAL]"


def main(path: str) -> None:
    run_id_counts = Counter()
    marker_by_run_type = Counter()
    prompt_type_counts = Counter()
    total_rows = 0
    adversarial_rows = 0

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        if "prompt_type" not in fieldnames:
            print(f"ADVERTENCIA: no existe columna 'prompt_type' en este CSV. Columnas: {fieldnames}")
            return
        if "response" not in fieldnames:
            print(f"ADVERTENCIA: no existe columna 'response' en este CSV.")
            return

        for row in reader:
            total_rows += 1
            run_id = row.get("run_id", "")
            run_id_counts[run_id] += 1
            prompt_type_counts[row.get("prompt_type", "")] += 1

            if row.get("prompt_type") != "adversarial":
                continue
            adversarial_rows += 1

            response = row.get("response", "") or ""
            if MARKER in response:
                run_type = "garak" if "garak" in run_id else (
                    "legitimate" if "legitimate" in run_id else f"OTRO:{run_id}"
                )
                marker_by_run_type[run_type] += 1

    print(f"Archivo: {path}")
    print(f"Filas totales: {total_rows}")
    print(f"Filas adversariales: {adversarial_rows}\n")

    print("Distribucion de prompt_type:")
    for pt, n in prompt_type_counts.most_common():
        print(f"  {pt}: {n}")
    print()

    print("Distribucion de run_id:")
    for rid, n in run_id_counts.most_common():
        print(f"  {rid}: {n} filas")
    print()

    print(f"Respuestas adversariales con marcador '{MARKER}' por tipo de corrida:")
    total_marker = sum(marker_by_run_type.values())
    for run_type, n in marker_by_run_type.most_common():
        print(f"  {run_type}: {n}")
    print(f"  TOTAL (mezclado, no usar si hay mas de un tipo de corrida): {total_marker}")
    print()

    garak_count = marker_by_run_type.get("garak", 0)
    print(f">>> Numero a usar (solo corrida garak, si aplica): {garak_count}")
    print(">>> Compara contra 234 (academico) / 376 (regulatorio) citados en cap5:77.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 contar_marcador_confidential.py /ruta/al/csv_consolidado.csv")
        sys.exit(1)
    main(sys.argv[1])
