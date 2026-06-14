# Manual de ejecución — Valentina Paz Campos Olguín
# Tesis: Marco LLM-Sec — Evaluación de ciberseguridad en plataformas RAG
# USACH DIINF — Profesor guía: Juan Ignacio Iturbe Araya

---

## Decisiones de diseño declaradas

| Parámetro | Valor | Justificación |
|---|---|---|
| `generations` (Garak) | 5 (default) | Con temperatura 0.8, las 5 generaciones por prompt capturan varianza estocástica real del modelo. Declarado explícitamente como decisión de diseño. |
| Repeticiones externas (Garak) | 5 | Verifican estabilidad de infraestructura entre runs. |
| Repeticiones prompts legítimos | 5 | Simetría metodológica con Garak. |
| Temperatura (Llama 3 8B) | 0.8 (default Ollama) | Default intrínseco del modelo. |
| Total intentos por escenario/dominio | 56.425 ataques + 700 legítimos | 11 probes × prompts × 5 gen × 5 reps + 70 prompts × 5 reps × 2 dominios |
| `SENSITIVITY_LEVEL` | `high` (ambos dominios) | Permite recuperar fragmentos de cualquier nivel de sensibilidad durante el experimento. |
| `QUERY_COHERENCE_THRESHOLD` | 1.35 (regulatory) / 1.1723 (academic) | Calibrado con 70 queries legítimas vs 35 incoherentes por dominio. FP: 3 (4.3%) y 2 (2.9%). |
| `C17_GROUNDING_THRESHOLD` | 0.0556 (regulatory) / 0.0714 (academic) | Calibrado como p5 del grounding ratio en 70 respuestas legítimas. |
| Detector primario (encoding probes) | `encoding.DecodeMatch` | Más estricto que `DecodeApprox`. Se descarta `DecodeApprox` para evitar doble conteo en TFA. Total correcto: 6400 intentos por probe, no 12800. |

---

## Dominios

| Variable | Valor |
|---|---|
| Dominio 1 | `regulatory_technical` |
| Dominio 2 | `academic_institutional` |

Los comandos usan `<DOMAIN>` como placeholder. Reemplazar por el dominio correspondiente.

---

## Paso 0 — Verificar prerrequisitos (una vez)

```bash
docker compose version
# Debe responder: Docker Compose version v5.x.x

nvidia-smi
# Debe mostrar la RTX 3070 sin error
```

---

## Paso 1 — Bootstrap (una sola vez por máquina)

> Requiere conexión a internet. No repetir entre dominios ni escenarios.

### 1.1 Modelo LLM (Ollama)

```bash
docker compose --profile bootstrap up -d ollama_bootstrap
docker exec -it ollama_bootstrap ollama pull llama3:8b
docker exec -it ollama_bootstrap ollama list
docker compose --profile bootstrap down
```

### 1.2 Modelo de embeddings (ChromaDB ONNX)

```bash
docker compose --env-file .env.regulatory_technical --profile bootstrap up --attach chroma_bootstrap
# Esperar mensaje: chroma onnx ok
```

---

## Paso 2 — Levantar servicios base

```bash
docker compose --env-file .env.<DOMAIN> --profile lab up -d
```

### 2.1 Verificar que los servicios estén healthy

```bash
docker compose --env-file .env.<DOMAIN> ps
# rag_api y shield_api deben mostrar (healthy)
```

### 2.2 Verificar el sistema completo

```bash
curl http://localhost:8001/health
# Respuesta esperada: {"status":"ok","upstream_ok":true,...}
```

### 2.3 Verificar controles activos (solo Escenario B)

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
# Valores esperados:
#   "corpus_hashes_loaded": 477  (regulatory) o 342 (academic)
#   "allowed_sensitivity": ["low", "medium", "high"]
#   "coherence_threshold": 1.35  (regulatory) o 1.1723 (academic)
#   "c12_recon_max_tokens": 80
#   "c12_recon_repeat_ratio": 0.6
#   "c17_grounding_threshold": 0.0556  (regulatory) o 0.0714 (academic)

docker logs tesis_rag | grep "C9:"
# Esperado: C9: corpus baseline built — 477 document hashes stored

cat ~/framework-eval-cs-llm/artifacts/corpus_version_registry.csv
# Debe mostrar al menos una fila con action=ingest y corpus_hash
```

---

## Paso 3 — Smoke test

> Dura aproximadamente 5-10 minutos. Si pasa sin errores, el experimento completo está listo.

### 3.1 Ingestar corpus

```bash
docker compose --env-file .env.<DOMAIN> run --rm rag_api \
  python3 -m cli ingest --source <DOMAIN> --reset
```

### 3.2 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify --collection <DOMAIN>
# Todos los fragmentos CONFIDENTIAL deben pasar los dos pasos de verificación
```

### 3.3 Calibrar umbrales (solo primera vez por dominio)

```bash
# C11 — coherencia semántica de queries
docker exec tesis_rag python app/scripts/calibrate_c11.py --domain <DOMAIN>
grep QUERY_COHERENCE_THRESHOLD .env.<DOMAIN>

# C17 — grounding de respuestas
docker exec tesis_rag python app/scripts/calibrate_c17.py \
  --domain <DOMAIN> --target unprotected
grep C17_GROUNDING_THRESHOLD .env.<DOMAIN>
```

### 3.4 Ejecutar una probe con una repetición

```bash
# Escenario A
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack garak \
  --target unprotected \
  --suite LLM07 \
  --probe goodside.Tag \
  --repetitions 1

# Escenario B
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack garak \
  --target protected \
  --suite LLM07 \
  --probe goodside.Tag \
  --repetitions 1
```

### 3.5 Verificar artefactos generados

```bash
ls ~/framework-eval-cs-llm/artifacts/runs/
# Debe aparecer un directorio con timestamp reciente

ls ~/framework-eval-cs-llm/artifacts/runs/*/garak/*.report.jsonl
cat ~/framework-eval-cs-llm/artifacts/runs/*/logs/app.log
```

### 3.6 Ejecutar prompts legítimos

```bash
# Escenario A
docker exec tesis_rag python3 -m cli attack legitimate \
  --target unprotected --repetitions 1

# Escenario B
docker exec tesis_shield python3 -m cli attack legitimate \
  --target protected --repetitions 1
```

### 3.7 Verificar CSV consolidado

```bash
python3 -c "
import csv, glob
files = glob.glob('artifacts/consolidated_<DOMAIN>_unprotected.csv')
if not files:
    print('❌ CSV no encontrado')
else:
    rows = list(csv.DictReader(open(files[0])))
    print(f'✅ Filas: {len(rows)}')
    print(f'   Columnas: {list(rows[0].keys())}')
    print(f'   Tipos de prompt: {set(r[\"prompt_type\"] for r in rows)}')
"
```

### 3.8 Parchear garak_passed

```bash
python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, 'app/src')
from eval.consolidator import patch_garak_passed

n = patch_garak_passed(
    csv_path=Path('artifacts/consolidated_<DOMAIN>_unprotected.csv'),
    garak_dir=Path('artifacts/runs/<RUN_DIR>/garak')
)
print(f'Filas parcheadas: {n}')
"
```

### 3.9 Limpiar artefactos del smoke test

```bash
docker compose --env-file .env.<DOMAIN> down

rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv

echo "✅ Smoke test OK. Artefactos eliminados. Listo para el experimento real."
```

> ⚠️ No eliminar `artifacts/calibration/` — contiene evidencia experimental de los umbrales calibrados.

---

## Paso 4 — Escenario A (sin LLM Guard)

> Se ejecuta el mismo flujo para ambos dominios. Solo cambia el `--env-file` y el nombre del dominio.

### 4.1 Levantar stack

```bash
docker compose --env-file .env.<DOMAIN> --profile lab up -d
docker compose --env-file .env.<DOMAIN> ps
# rag_api y shield_api deben mostrar (healthy)
```

### 4.2 Verificar GPU

```bash
nvidia-smi
docker exec ollama_core ollama ps
# Debe mostrar: llama3:8b ... 100% GPU
```

### 4.3 Ingestar corpus y verificar ground truth

```bash
docker compose --env-file .env.<DOMAIN> run --rm rag_api \
  python3 -m cli ingest --source <DOMAIN> --reset

docker exec tesis_rag python3 -m cli ingest verify --collection <DOMAIN>
```

### 4.4 Verificar salud del target

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack health --target unprotected
```

### 4.5 Ejecutar ataques Garak

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks up garak_runner
```

### 4.6 Monitorear en tiempo real

```bash
# En otra terminal (tmux attach -t tesis)
docker compose --env-file .env.<DOMAIN> logs -f garak_runner
```

### 4.7 Ejecutar prompts legítimos

```bash
docker exec tesis_rag python3 -m cli attack legitimate --target unprotected
```

### 4.8 Parchear garak_passed

```bash
python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, 'app/src')
from eval.consolidator import patch_garak_passed

n = patch_garak_passed(
    csv_path=Path('artifacts/consolidated_<DOMAIN>_unprotected.csv'),
    garak_dir=Path('artifacts/runs/<RUN_DIR>/garak')
)
print(f'Filas parcheadas: {n}')
"
```

### 4.9 Cambiar al siguiente dominio

```bash
docker compose --env-file .env.<DOMAIN_ANTERIOR> down
# Repetir desde 4.1 con el siguiente dominio
```

---

## Paso 5 — Escenario B (con LLM Guard activo)

> Mismo flujo que el Escenario A. Cambia `unprotected` → `protected` y se agrega la calibración.

Antes de iniciar, verificar los env files:

```bash
grep GARAK_TARGET .env.regulatory_technical
grep GARAK_TARGET .env.academic_institutional
# Ambos deben mostrar: GARAK_TARGET=protected

grep ENABLE_OUTPUT_GUARD .env.regulatory_technical
grep ENABLE_OUTPUT_GUARD .env.academic_institutional
# Ambos deben mostrar: ENABLE_OUTPUT_GUARD=1
```

### 5.1 Levantar stack

```bash
docker compose --env-file .env.<DOMAIN> --profile lab up -d
docker compose --env-file .env.<DOMAIN> ps
```

### 5.2 Verificar GPU

```bash
nvidia-smi
docker exec ollama_core ollama ps
```

### 5.3 Ingestar corpus y verificar ground truth

```bash
docker compose --env-file .env.<DOMAIN> run --rm rag_api \
  python3 -m cli ingest --source <DOMAIN> --reset

docker exec tesis_rag python3 -m cli ingest verify --collection <DOMAIN>
```

### 5.4 Calibrar umbrales para Escenario B

```bash
docker exec tesis_rag python app/scripts/calibrate_c11.py --domain <DOMAIN>
grep QUERY_COHERENCE_THRESHOLD .env.<DOMAIN>

docker exec tesis_rag python app/scripts/calibrate_c17.py \
  --domain <DOMAIN> --target protected
grep C17_GROUNDING_THRESHOLD .env.<DOMAIN>
```

### 5.5 Verificar controles activos

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
docker logs tesis_rag | grep "C9:"
```

### 5.6 Verificar salud del target

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack health --target protected
```

### 5.7 Ejecutar ataques Garak

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks up garak_runner
```

### 5.8 Monitorear en tiempo real

```bash
docker compose --env-file .env.<DOMAIN> logs -f garak_runner
```

### 5.9 Ejecutar prompts legítimos

```bash
docker exec tesis_shield python3 -m cli attack legitimate --target protected
```

### 5.10 Parchear garak_passed

```bash
python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, 'app/src')
from eval.consolidator import patch_garak_passed

n = patch_garak_passed(
    csv_path=Path('artifacts/consolidated_<DOMAIN>_protected.csv'),
    garak_dir=Path('artifacts/runs/<RUN_DIR>/garak')
)
print(f'Filas parcheadas: {n}')
"
```

### 5.11 Cambiar al siguiente dominio

```bash
docker compose --env-file .env.<DOMAIN_ANTERIOR> down
# Repetir desde 5.1 con el siguiente dominio
```

---

## Paso 6 — Procesamiento de resultados

> Ejecutar en el notebook local una vez completados los 4 runs:
> A×regulatory_technical, A×academic_institutional, B×regulatory_technical, B×academic_institutional.

### 6.1 Activar entorno virtual

```bash
cd ~/framework-eval-cs-llm
source .venv/bin/activate
```

### 6.2 Métricas básicas (TFA y LAS)

```bash
python3 app/src/eval/process_results.py --artifacts artifacts/
```

### 6.3 Análisis profundo (matriz de confusión, detectores, distribuciones)

```bash
python3 app/src/eval/process_results.py --artifacts artifacts/ --deep
```

### 6.4 Generar figuras

```bash
python3 app/src/eval/process_results.py --artifacts artifacts/ --deep --plots
# Figuras guardadas en artifacts/figures/
```

### 6.5 Filtrar por dominio específico

```bash
python3 app/src/eval/process_results.py \
  --artifacts artifacts/ \
  --domains regulatory_technical \
  --deep --plots
```

### 6.6 Verificar coherencia JSONL vs app.log

```bash
python3 app/src/eval/verify_coherence.py \
  artifacts/runs/<RUN_DIR>
```

### 6.7 Verificar integridad de los CSVs consolidados

```bash
# Filas por archivo
for f in artifacts/consolidated_*.csv; do
  echo "$(wc -l < $f) filas — $(basename $f)"
done

# Distribución de garak_passed
python3 -c "
import csv
from collections import Counter
for domain in ['regulatory_technical', 'academic_institutional']:
    for scenario in ['unprotected', 'protected']:
        path = f'artifacts/consolidated_{domain}_{scenario}.csv'
        try:
            with open(path) as f:
                c = Counter(r['garak_passed'] for r in csv.DictReader(f)
                            if r['prompt_type'] == 'adversarial')
            print(f'{domain} {scenario}: {dict(c)}')
        except FileNotFoundError:
            print(f'{domain} {scenario}: not found')
"
```

---

## Backfill de scores de escáneres

> Ejecutar **una sola vez** sobre los CSVs consolidados generados **antes**
> del fix de `_raw_score_from_risk()` en `api/shield.py`. Antes de ese fix,
> `input_scanner_score` y `output_scanner_score` se guardaban como "risk
> score" relativo al umbral (`calculate_risk_score()`, rango `[-1, 1]`), no
> como probabilidad cruda del clasificador (`[0, 1]`).

```bash
python3 app/src/eval/process_results.py --backfill-scores
```

Busca todos los archivos `artifacts/consolidated_*.csv`, aplica
`backfill_raw_scores()` (inversa de `calculate_risk_score()`, con
`pi_threshold=0.92` y `sens_threshold=0.50`) sobre las columnas
`input_scanner_score` y `output_scanner_score`, y sobreescribe cada archivo
in-place. Para cada archivo imprime min/max/mean de ambas columnas antes y
después de la conversión.

> **Importante**: no volver a ejecutar este comando sobre CSVs generados
> **después** del fix — esos runs ya escriben probabilidades crudas
> directamente, y aplicar `--backfill-scores` sobre ellos invertiría los
> valores incorrectamente.

---

## Paso 7 — Limpieza de artefactos

> Secciones independientes. Ejecutar solo la que corresponda.

### 7.1 Bajar servicios

```bash
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.academic_institutional down
```

### 7.2 Limpiar solo resultados de un run específico

```bash
rm -rf ~/framework-eval-cs-llm/artifacts/runs/<RUN_DIR>
```

### 7.3 Limpiar todos los runs y CSVs (mantiene calibración)

```bash
rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv
rm -rf ~/framework-eval-cs-llm/artifacts/figures/*

# Verificar
find ~/framework-eval-cs-llm/artifacts -type f | sort
```

### 7.4 Limpiar ChromaDB (fuerza re-ingesta)

```bash
rm -rf ~/framework-eval-cs-llm/chroma_db/*
rm -rf ~/framework-eval-cs-llm/chroma_cache/*
# Requiere re-ingestar corpus en Paso 4.3 o 5.3
```

### 7.5 Reset total (borra TODO incluyendo modelo Ollama)

> ⚠️ Requiere ejecutar bootstrap completo desde Paso 1.

```bash
# 1. Detener contenedores
docker stop tesis_shield tesis_rag ollama_core 2>/dev/null || true
docker rm   tesis_shield tesis_rag ollama_core 2>/dev/null || true

# 2. Limpiar Docker completo
docker system prune -a --volumes -f

# 3. Eliminar artefactos locales
sudo rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
sudo rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
sudo rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv
sudo rm -f  ~/framework-eval-cs-llm/artifacts/llm_guard.log
sudo rm -rf ~/framework-eval-cs-llm/ollama_data/*
sudo rm -rf ~/framework-eval-cs-llm/llm_guard_cache/*
sudo rm -rf ~/framework-eval-cs-llm/chroma_cache/*
sudo rm -rf ~/framework-eval-cs-llm/chroma_db/*
sudo rm -rf ~/framework-eval-cs-llm/garak_runs/*

# 4. Verificar
docker ps -a
docker images
docker volume ls
find ~/framework-eval-cs-llm/artifacts -type f | sort
```

---

## Diagnóstico y comandos auxiliares

### Estado general del sistema

```bash
docker ps
docker ps -a
docker compose --env-file .env.<DOMAIN> ps
docker stats --no-stream
```

---

### Problemas con los servicios

**Servicio no llega a healthy:**

```bash
docker compose --env-file .env.<DOMAIN> logs rag_api
docker compose --env-file .env.<DOMAIN> logs shield_api
docker logs tesis_rag   --tail 50 --timestamps
docker logs tesis_shield --tail 50 --timestamps

# Reiniciar sin bajar el stack
docker compose --env-file .env.<DOMAIN> restart rag_api
docker compose --env-file .env.<DOMAIN> restart shield_api
```

**Verificar health manualmente:**

```bash
curl http://localhost:8000/health   # RAG API
curl http://localhost:8001/health   # Shield API

# Desde dentro del contenedor
docker exec tesis_rag    curl http://localhost:8000/health
docker exec tesis_shield curl http://localhost:8001/health
```

---

### Problemas con Ollama

```bash
docker exec ollama_core ollama list
# Debe mostrar llama3:8b

docker exec tesis_rag curl http://ollama_core:11434/api/tags
# El hostname siempre es ollama_core, nunca 127.0.0.1
```

**Verificar GPU:**

```bash
nvidia-smi
docker exec ollama_core ollama ps
# Debe mostrar: llama3:8b ... 100% GPU
# Si muestra 0% GPU: verificar NVIDIA_VISIBLE_DEVICES=all en docker-compose.yml
```

---

### Problemas con ChromaDB

```bash
# Verificar colección ingresada
docker exec tesis_rag python3 -m cli ingest verify --collection <DOMAIN>

# Contar chunks
docker exec tesis_rag python3 -c "
import chromadb
client = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
col = client.get_collection('<DOMAIN>')
print('chunks:', col.count())
"

# Verificar metadata de sensibilidad (C8)
docker exec tesis_rag python3 -c "
import chromadb
from collections import Counter
client = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
col = client.get_collection('<DOMAIN>')
result = col.get(include=['metadatas'])
c = Counter(m.get('sensitivity', 'unknown') for m in result['metadatas'])
for level, count in sorted(c.items()):
    print(f'{level}: {count} chunks ({count/sum(c.values())*100:.1f}%)')
"
# Si muestran SIN SENSITIVITY, re-ingestar con --reset
```

**RAG unhealthy — ChromaDB perdió referencia a la colección:**

```bash
docker restart tesis_rag
# Esperar ~30 segundos y verificar

docker compose --env-file .env.<DOMAIN> ps
# Si sigue unhealthy, re-ingestar y reiniciar:
docker compose --env-file .env.<DOMAIN> run --rm rag_api \
  python3 -m cli ingest --source <DOMAIN> --reset
docker restart tesis_rag
```

---

### Problemas con Garak

**Ver dominio activo en el contenedor:**

```bash
docker exec tesis_rag env | grep DATASET_TAG
docker exec tesis_rag env | grep GARAK_TARGET
# El contenedor usa el dominio con que fue levantado.
# Para cambiar de dominio: bajar y levantar con el env-file correcto.
```

**Reanudar un run interrumpido:**

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack continue-run \
  /root/proyecto_tesis/artifacts/runs/<RUN_DIR> \
  --target unprotected
# Los paths deben ser absolutos dentro del contenedor.
```

**Reejecutar solo una probe:**

```bash
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm \
  garak_runner attack garak --target unprotected \
  --suite LLM01 --probe promptinject.HijackKillHumans
```

**Ver reportes HTML en local:**

```bash
scp "pc-u:~/framework-eval-cs-llm/artifacts/runs/<RUN_DIR>/garak/*.report.html" ~/Desktop/
```

---

### Actualización de componentes

`--build` reconstruye la imagen Docker. Solo es necesario si cambió el
`Dockerfile` o `requirements.txt`:

```bash
docker compose --env-file .env.<DOMAIN> --profile lab down
docker compose --env-file .env.<DOMAIN> --profile lab up -d --build
```

**Para cambios de código Python en `app/src/`** (sin tocar `Dockerfile` ni
`requirements.txt`), **no** uses `--build`. `tesis_rag` y `tesis_shield`
corren `uvicorn` con `--reload --reload-dir app/src`, que vigila el bind
mount `./app/src`: la próxima petición HTTP ya usa el código actualizado,
sin reiniciar nada.

Si después de editar un archivo el cambio no se refleja (por ejemplo,
quedó un error de import a mitad de carga del módulo), reinicia solo esos
dos servicios sin rebuild:

```bash
bash llmsec.sh reload
# equivalente a: docker compose restart tesis_rag tesis_shield
```

---

### tmux — Sesión persistente en pc-u

```bash
ssh pc-u
tmux new -s tesis          # crear sesión
tmux attach -t tesis       # reconectarse
tmux ls                    # ver sesiones activas

# Scroll dentro de tmux:
# Ctrl+b luego [ (en teclado latinoamericano: Ctrl+b luego Alt+8)
# Moverse con flechas o PgUp/PgDn — salir con q o Escape
# El buffer tiene límite (~2000 líneas); los datos reales están en los archivos de reporte.
```

---

### Verificar integridad de los CSVs

```bash
# Esquema y primeras filas
python3 -c "
import csv
with open('artifacts/consolidated_<DOMAIN>_unprotected.csv') as f:
    reader = csv.reader(f)
    for i, row in enumerate(reader):
        if i < 3: print(row)
"

# Filas por tipo de prompt
python3 -c "
import csv
from collections import Counter
with open('artifacts/consolidated_<DOMAIN>_unprotected.csv') as f:
    c = Counter(row['prompt_type'] for row in csv.DictReader(f))
print(c)
"

# Bloqueos por control (Escenario B)
python3 -c "
import csv
from collections import Counter
with open('artifacts/consolidated_<DOMAIN>_protected.csv') as f:
    c = Counter(row['block_reason'] for row in csv.DictReader(f)
                if row['was_blocked'] == 'True')
for reason, count in sorted(c.items(), key=lambda x: -x[1]):
    print(f'{count:5d}  {reason}')
"
```

---

### Otros comandos útiles

```bash
# Ver configuración efectiva del stack
docker compose --env-file .env.<DOMAIN> --profile attacks run --rm garak_runner where

# Espacio en disco
df -h
du -sh ~/framework-eval-cs-llm/artifacts/

# Logs de LLM Guard (bloqueos por scanner)
docker logs tesis_shield | grep "scanner"

# Logs de controles en tiempo real
docker logs tesis_rag -f | grep -E "C9:|C11:|C12:|C17:"

# Registro de versiones del corpus (C62)
cat ~/framework-eval-cs-llm/artifacts/corpus_version_registry.csv

# Instalar dependencias para análisis local
pip install pandas scipy matplotlib
```