"""
Cuenta las activaciones de un escaner dado (columna scanner_triggered),
filtrando SOLO las filas cuyo run_id corresponde a la corrida de ataques (garak),
para no mezclar la corrida 'legitimate' (medicion de FPR) en un numero que
describe comportamiento frente a ataques.

Uso (correr una vez por dominio, escaner por defecto = Sensitive):
    python3 contar_sensitive_garak.py artifacts/consolidated_academic_institutional_protected.csv
    python3 contar_sensitive_garak.py artifacts/consolidated_regulatory_technical_protected.csv Regex
"""

import csv
import sys
from collections import Counter


def main(path: str, scanner_name: str = "Sensitive") -> None:
    run_id_counts = Counter()
    sensitive_by_run_type = Counter()
    total_rows = 0

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            run_id = row.get("run_id", "")
            run_id_counts[run_id] += 1

            if row.get("scanner_triggered") == scanner_name:
                run_type = "garak" if "garak" in run_id else (
                    "legitimate" if "legitimate" in run_id else f"OTRO:{run_id}"
                )
                sensitive_by_run_type[run_type] += 1

    print(f"Archivo: {path}")
    print(f"Filas totales: {total_rows}\n")

    print("Distribucion de run_id:")
    for rid, n in run_id_counts.most_common():
        print(f"  {rid}: {n} filas")
    print()

    print(f"Activaciones de '{scanner_name}' (scanner_triggered) por tipo de corrida:")
    total_sensitive = sum(sensitive_by_run_type.values())
    for run_type, n in sensitive_by_run_type.most_common():
        print(f"  {run_type}: {n}")
    print(f"  TOTAL (mezclado, no usar este numero en el parrafo): {total_sensitive}")
    print()

    garak_count = sensitive_by_run_type.get("garak", 0)
    print(f">>> Numero a usar para '{scanner_name}' (solo corrida garak): {garak_count}")
    print(">>> Compara este numero con lo citado en el parrafo y en tab:scanners_dist del apendice.")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Uso: python3 contar_sensitive_garak.py /ruta/al/csv_consolidado.csv [nombre_escaner]")
        sys.exit(1)
    scanner_arg = sys.argv[2] if len(sys.argv) == 3 else "Sensitive"
    main(sys.argv[1], scanner_arg)
