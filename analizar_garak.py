import json
import os
from collections import defaultdict

# 1. Rutas de archivos y directorios
SUITES_JSON_PATH = 'app/config/global/owasp_suites.json'
GARAK_DIR = 'artifacts/runs/20260624_131252_regulatory_technical_protected_garak/garak'

# 2. Cargar los probes dinámicamente desde el archivo de configuración
if not os.path.exists(SUITES_JSON_PATH):
    print(f"Error: No se encontró el archivo de suites en: {SUITES_JSON_PATH}")
    exit(1)

try:
    with open(SUITES_JSON_PATH, 'r', encoding='utf-8') as f:
        probes_mapping = json.load(f)
except json.JSONDecodeError as e:
    print(f"Error al parsear el archivo JSON {SUITES_JSON_PATH}: {e}")
    exit(1)

# Invertir el mapeo para buscar rápido a qué categoría pertenece un archivo
# Ejemplo: 'goodside.Tag' -> 'LLM07'
probe_to_category = {p: cat for cat, list_p in probes_mapping.items() for p in list_p}

# Estructura para almacenar resultados finales
resultados = defaultdict(lambda: defaultdict(lambda: {"passed": 0, "total": 0}))

if not os.path.exists(GARAK_DIR):
    print(f"Error: No se encuentra el directorio de reportes: {GARAK_DIR}")
    exit(1)

# 3. Escanear y procesar todos los archivos JSONL relevantes
all_files = os.listdir(GARAK_DIR)

for filename in all_files:
    if not filename.endswith('.report.jsonl'):
        continue
        
    # Identificar qué probe es mirando el nombre del archivo
    matched_probe = None
    for probe in probe_to_category.keys():
        if probe in filename:
            matched_probe = probe
            break
            
    if not matched_probe:
        continue # Ignorar archivos de Garak que no estén mapeados en tu JSON
        
    category = probe_to_category[matched_probe]
    filepath = os.path.join(GARAK_DIR, filename)
    
    # Leer el reporte línea por línea
    with open(filepath, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            # Acumular los datos de las líneas de evaluación ('eval')
            if obj.get('entry_type') == 'eval':
                resultados[category][matched_probe]['passed'] += obj.get('passed', 0)
                resultados[category][matched_probe]['total'] += obj.get('total', 0)

# 4. Imprimir Reporte Consolidado en Consola
print("\n" + "="*75)
print(f"{'CATEGORÍA':<10} | {'PROBE':<45} | {'DEFENDIDO':<14}")
print("="*75)

for cat in sorted(probes_mapping.keys()):
    print(f"[{cat}]")
    for probe in probes_mapping[cat]:
        data = resultados[cat].get(probe)
        if data and data['total'] > 0:
            passed = data['passed']
            total = data['total']
            porcentaje = (passed / total) * 100
            status_str = f"{passed}/{total} ({porcentaje:.1f}%)"
            print(f"  └──      | {probe:<45} | {status_str:<14}")
        else:
            print(f"  └──      | {probe:<45} | NO ENCONTRADO")
    print("-"*75)
