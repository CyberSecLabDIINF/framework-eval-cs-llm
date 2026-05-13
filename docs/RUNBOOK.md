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
| Total intentos por escenario/dominio | 18.025 ataques + 350 legítimos = 18.375 filas | 721 prompts × 5 gen × 5 reps + 70 prompts × 5 reps |

---

## Dominios

| Variable | Valor |
|---|---|
| Dominio 1 | `regulatory_technical` |
| Dominio 2 | `academic_institutional` |

---

## Paso 0 — Verificar prerrequisitos (una vez)

```bash
docker compose version
# Debe responder: Docker Compose version v5.x.x
```

---

## Paso 1 - Bootstrap (una sola vez por máquina)
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

## Paso 2 - Levantar servicios base
```bash
docker compose --env-file .env.regulatory_technical --profile lab up -d
```

Verificar que los servicios estén healthy:

```bash
docker compose ps
# rag_api y shield_api deben mostrar (healthy)
```

Verificar el sistema completo:

```bash
curl http://localhost:8001/health
# Respuesta esperada: {"status":"ok","upstream_ok":true,...}
```

---

## Paso 3 - Smoke test

> Ejecutar después de aplicar los fixes y reconstruir la imagen.
> Dura aproximadamente 5-10 minutos. Si pasa sin errores, el experimento completo está listo.



### 3.1 Ingestar corpus

```bash
docker compose --env-file .env.regulatory_technical run --rm rag_api \
  python3 -m cli ingest --source regulatory_technical --reset
```

### 3.2 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection regulatory_technical
# Todos los fragmentos CONFIDENTIAL deben pasar los dos pasos de verificación
```

### 3.3 Ejecutar UNA probe con UNA repetición (Escenario A)

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack garak \
  --target unprotected \
  --suite LLM01 \
  --probe promptinject.HijackKillHumans \
  --repetitions 1
```

### 3.4 Verificar que se generó el reporte

```bash
ls ~/framework-eval-cs-llm/artifacts/runs/
# Debe aparecer un directorio con timestamp reciente

ls ~/framework-eval-cs-llm/artifacts/runs/*/garak/*.report.jsonl
# Debe haber al menos 1 archivo
```

### 3.5 Verificar que el `app.log` se generó dentro del run

```bash
cat ~/framework-eval-cs-llm/artifacts/runs/*/logs/app.log
# Debe mostrar las líneas de inicio y fin del probe
```

### 3.6 Ejecutar prompts legítimos (Escenario A)

```bash
docker exec tesis_rag python3 -m cli attack legitimate \
  --target unprotected \
  --repetitions 1
```

### 3.7 Verificar el CSV consolidado

```bash
python3 -c "
import csv, glob
files = glob.glob('/home/valentina/framework-eval-cs-llm/artifacts/consolidated_regulatory_technical_unprotected.csv')
if not files:
    print('❌ CSV no encontrado')
else:
    rows = list(csv.DictReader(open(files[0])))
    print(f'✅ Filas: {len(rows)}')
    print(f'   Columnas: {list(rows[0].keys())}')
    print(f'   Dominios: {set(r[\"domain\"] for r in rows)}')
    print(f'   Tipos de prompt: {set(r[\"prompt_type\"] for r in rows)}')
"
# Debe mostrar domain='regulatory_technical' y prompt_type='legitimate'
```

### 3.8 Verificar que el CSV de latencia tiene columna domain

```bash
python3 -c "
import csv
with open('/home/valentina/framework-eval-cs-llm/artifacts/latency/latency_unprotected_direct.csv') as f:
    rows = list(csv.DictReader(f))
posts = [r for r in rows if r['method'] == 'POST']
print(f'✅ Columnas: {list(rows[0].keys())}')
print(f'   POST /generate: {len(posts)} requests')
print(f'   Dominios: {set(r.get(\"domain\", \"SIN DOMAIN\") for r in posts)}')
"
# Debe mostrar columna 'domain' con valor 'regulatory_technical'
```

### 3.9 Parchear garak_passed

```bash
docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain regulatory_technical \
  --scenario unprotected
# Debe responder: ✅ patch-garak complete — N rows updated.
```

### 3.10 Repetir para Escenario B

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack health --target protected

docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack garak \
  --target protected \
  --suite LLM01 \
  --probe promptinject.HijackKillHumans \
  --repetitions 1

docker exec tesis_shield python3 -m cli attack legitimate \
  --target protected \
  --repetitions 1

docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain regulatory_technical \
  --scenario protected
```

### 3.11 Limpiar artefactos del smoke test

```bash
docker compose --env-file .env.regulatory_technical down

rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv

echo "✅ Smoke test OK. Artefactos eliminados. Listo para el experimento real."
```

---

> Si todos los pasos pasaron sin errores, continuar con el Paso 1 del RUNBOOK.
> Si el bootstrap ya fue ejecutado anteriormente, ir directamente al Paso 2.

---

## Paso 4 — Escenario A (sin LLM Guard)

> En Escenario A, `GARAK_TARGET=unprotected` en los env files. Verificar antes de ejecutar.

---

### 4.1 Escenario A — Dominio 1: regulatory_technical

#### 4.1.1 Ingestar corpus

```bash
docker compose --env-file .env.regulatory_technical run --rm rag_api \
  python3 -m cli ingest --source regulatory_technical --reset
```

#### 4.1.2 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection regulatory_technical
# Todos los fragmentos CONFIDENTIAL deben pasar la verificación
```

#### 4.1.3 Verificar salud del target

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack health --target unprotected
```

#### 4.1.4 Ejecutar ataques Garak

```bash
docker compose --env-file .env.regulatory_technical --profile attacks up garak_runner
```

#### 4.1.5 Monitorear en tiempo real (abrir otra terminal con `ssh pc-u` y `tmux attach -t tesis`):

```bash
docker compose --env-file .env.regulatory_technical logs -f garak_runner
```

#### 4.1.6 Ejecutar prompts legítimos

```bash
docker exec tesis_rag python3 -m cli attack legitimate \
  --target unprotected
```

#### 4.1.7 Parchear garak_passed en el CSV consolidado

```bash
docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain regulatory_technical --scenario unprotected
```

---

### 4.2 Escenario A — Dominio 2: academic_institutional

#### 4.2.1 Bajar stack y levantar con dominio 2

```bash
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.academic_institutional --profile lab up -d
```

#### 4.2.2 Verificar healthy

```bash
docker compose --env-file .env.academic_institutional ps
```

#### 4.2.3 Ingestar corpus

```bash
docker compose --env-file .env.academic_institutional run --rm rag_api \
  python3 -m cli ingest --source academic_institutional --reset
```

#### 4.2.4 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection academic_institutional
```

#### 4.2.5 Verificar salud del target

```bash
docker compose --env-file .env.academic_institutional --profile attacks run --rm \
  garak_runner attack health --target unprotected
```

#### 4.2.6 Ejecutar ataques Garak

```bash
docker compose --env-file .env.academic_institutional --profile attacks up garak_runner
```

#### 4.2.7 Monitorear

```bash
docker compose --env-file .env.academic_institutional logs -f garak_runner
```

#### 4.2.8 Ejecutar prompts legítimos

```bash
docker exec tesis_rag python3 -m cli attack legitimate \
  --target unprotected
```

#### 4.2.9 Parchear garak_passed en el CSV consolidado

```bash
docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain academic_institutional --scenario unprotected
```

---

## Paso 5 — Escenario B (con LLM Guard activo)

Antes de iniciar, editar **ambos** env files y cambiar el target:

```bash
# En .env.regulatory_technical:
# GARAK_TARGET=unprotected  →  GARAK_TARGET=protected

# En .env.academic_institutional:
# GARAK_TARGET=unprotected  →  GARAK_TARGET=protected
```

Verificar que el cambio quedó bien:

```bash
grep GARAK_TARGET .env.regulatory_technical
grep GARAK_TARGET .env.academic_institutional
# Ambos deben mostrar: GARAK_TARGET=protected
```

---

### 5.1 Escenario B — Dominio 1: regulatory_technical

#### 5.1.1 Levantar stack con dominio 1

```bash
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.regulatory_technical --profile lab up -d
```

#### 5.1.2 Verificar healthy

```bash
docker compose --env-file .env.regulatory_technical ps
curl http://localhost:8001/health
```

#### 5.1.3 Ingestar corpus

```bash
docker compose --env-file .env.regulatory_technical run --rm rag_api \
  python3 -m cli ingest --source regulatory_technical --reset
```

#### 5.1.4 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection regulatory_technical
```

#### 5.1.5 Verificar salud del target

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack health --target protected
```

#### 5.1.6 Ejecutar ataques Garak

```bash
docker compose --env-file .env.regulatory_technical --profile attacks up garak_runner
```

#### 5.1.7 Monitorear

```bash
docker compose --env-file .env.regulatory_technical logs -f garak_runner
```

#### 5.1.8 Ejecutar prompts legítimos

```bash
docker exec tesis_shield python3 -m cli attack legitimate \
  --target protected
```

#### 5.1.9 Parchear garak_passed en el CSV consolidado

```bash
docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain regulatory_technical --scenario protected
```

---

### 5.2 Escenario B — Dominio 2: academic_institutional

#### 5.2.1 Bajar stack y levantar con dominio 2

```bash
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.academic_institutional --profile lab up -d
```

#### 5.2.2 Verificar healthy:

```bash
docker compose --env-file .env.academic_institutional ps
curl http://localhost:8001/health
```

#### 5.2.3 Ingestar corpus

```bash
docker compose --env-file .env.academic_institutional run --rm rag_api \
  python3 -m cli ingest --source academic_institutional --reset
```

#### 5.2.4 Verificar ground truth

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection academic_institutional
```

#### 5.2.5 Verificar salud del target

```bash
docker compose --env-file .env.academic_institutional --profile attacks run --rm \
  garak_runner attack health --target protected
```

#### 5.2.6 Ejecutar ataques Garak

```bash
docker compose --env-file .env.academic_institutional --profile attacks up garak_runner
```

#### 5.2.7 Monitorear

```bash
docker compose --env-file .env.academic_institutional logs -f garak_runner
```

#### 5.2.8 Ejecutar prompts legítimos

```bash
docker exec tesis_shield python3 -m cli attack legitimate \
  --target protected
```

#### 5.2.9 Parchear garak_passed en el CSV consolidado

```bash
docker exec tesis_rag python3 -m cli metrics patch-garak \
  --domain academic_institutional --scenario protected
```

---

## Paso 6 — Procesamiento de resultados

> Solo después de completar los 4 runs (A×regulatory_technical, A×academic_institutional, B×regulatory_technical, B×academic_institutional).

### 6.1 Calcular métricas (TFA, LAS, PCC, NCP)

```bash
docker exec tesis_rag python3 -m cli metrics compute
```

### 6.2 Ejecutar pruebas estadísticas

```bash
docker exec tesis_rag python3 -m cli metrics stats
```

Los resultados quedan en:

```
artifacts/runs/<run_id>/metrics.json
artifacts/runs/<run_id>/summary.md
```

### 6.3 Verificar integridad de los CSVs consolidados

```bash
# Contar filas por dominio y escenario (esperado: ~18.375 por combinación)
for f in ~/framework-eval-cs-llm/artifacts/consolidated_*.csv; do
  echo "$(wc -l < $f) filas — $(basename $f)"
done
```

---

## Paso 7 — Limpiar artefactos (reset completo)

> Usar solo si se quiere empezar desde cero. Esto borra TODOS los resultados.

```bash
# Bajar todos los servicios
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.academic_institutional down

# Borrar artefactos
rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv

# Verificar que quedó vacío
find ~/framework-eval-cs-llm/artifacts -type f | sort
```

---

## Diagnóstico y comandos auxiliares

### Estado general del sistema

```bash
# Ver todos los contenedores activos
docker ps

# Ver todos los contenedores (incluyendo detenidos)
docker ps -a

# Ver estado y health de los servicios del stack
docker compose --env-file .env.regulatory_technical ps

# Ver uso de recursos (CPU, RAM)
docker stats --no-stream
```

---

### Problemas con los servicios

**Servicio no llega a healthy:**

```bash
# Ver logs del servicio específico
docker compose --env-file .env.regulatory_technical logs rag_api
docker compose --env-file .env.regulatory_technical logs shield_api

# Ver los últimos 50 logs con timestamps
docker logs tesis_rag --tail 50 --timestamps
docker logs tesis_shield --tail 50 --timestamps

# Reiniciar un servicio específico sin bajar todo el stack
docker compose --env-file .env.regulatory_technical restart rag_api
docker compose --env-file .env.regulatory_technical restart shield_api
```



**Verificar health manualmente:**

```bash
# RAG API (Escenario A)
curl http://localhost:8000/health

# Shield API (Escenario B)
curl http://localhost:8001/health

# Desde dentro del contenedor (si curl externo falla)
docker exec tesis_rag curl http://localhost:8000/health
docker exec tesis_shield curl http://localhost:8001/health
```

---

### Problemas con Ollama

**Verificar que el modelo está disponible:**

```bash
docker exec ollama_core ollama list
# Debe mostrar llama3:8b
```

**Verificar que Ollama responde:**

```bash
docker exec tesis_rag curl http://ollama_core:11434/api/tags
```

**El contenedor usa `ollama_core` como hostname, nunca `127.0.0.1`.**

---

### Problemas con ChromaDB

**Verificar colección ingresada:**

```bash
docker exec tesis_rag python3 -m cli ingest verify \
  --collection regulatory_technical

docker exec tesis_rag python3 -m cli ingest verify \
  --collection academic_institutional
```

**Ver cuántos chunks hay en la colección:**

```bash
docker exec tesis_rag python3 -c "
import chromadb
client = chromadb.HttpClient(host='chromadb', port=8000)
col = client.get_collection('regulatory_technical')
print('chunks:', col.count())
"
```

---

### Problemas con Garak

**Ver qué dominio tiene activo el contenedor:**

```bash
docker exec tesis_rag env | grep DATASET_TAG
docker exec tesis_rag env | grep GARAK_TARGET
```

**El contenedor usa el dominio con que fue levantado, no el del `--env-file` del exec.**
Si necesitas cambiar de dominio, bajar y volver a levantar el stack con el env-file correcto:

```bash
docker compose --env-file .env.regulatory_technical down
docker compose --env-file .env.academic_institutional --profile lab up -d
```

**Reanudar un run interrumpido (por corte de luz u otro motivo):**

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack continue-run \
  /root/proyecto_tesis/artifacts/runs/<nombre_del_run_dir> \
  --target unprotected
```

> Los paths pasados a `continue-run` deben ser absolutos dentro del contenedor.
> El directorio del run se llama algo como `20260511_151225_regulatory_technical_unprotected_garak`.

**Reejecutar solo una probe específica:**

```bash
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner attack garak --target unprotected \
  --suite LLM01 --probe promptinject.HijackKillHumans
```

**Ver los reportes HTML de Garak en tu máquina local:**

```bash
scp "pc-u:~/framework-eval-cs-llm/artifacts/runs/<run_dir>/garak/*.report.html" ~/Desktop/
```

---

### tmux — Sesión persistente en pc-u

```bash
# Conectarse a pc-u
ssh pc-u

# Crear sesión nueva
tmux new -s tesis

# Reconectarse a sesión existente después de desconexión
tmux attach -t tesis

# Ver sesiones activas
tmux ls

# Scroll dentro de tmux (modo copia)
# Ctrl+b luego [ (en teclado latinoamericano: Ctrl+b luego Alt+8)
# Moverse con flechas o PgUp/PgDn
# Salir del modo copia: q o Escape

# El buffer de tmux tiene límite (~2000 líneas).
# Si necesitas ver más, los datos están en los archivos de reporte, no en el buffer.
```

---

### Verificar integridad de los CSVs

**Ver esquema y primeras filas:**

```bash
python3 -c "
import csv
with open('/home/valentina/framework-eval-cs-llm/artifacts/consolidated_regulatory_technical_unprotected.csv') as f:
    reader = csv.reader(f)
    for i, row in enumerate(reader):
        if i < 3:
            print(row)
"
```

**Contar filas por tipo de prompt:**

```bash
python3 -c "
import csv
from collections import Counter
with open('/home/valentina/framework-eval-cs-llm/artifacts/consolidated_regulatory_technical_unprotected.csv') as f:
    c = Counter(row['prompt_type'] for row in csv.DictReader(f))
print(c)
"
```

**Verificar que no hay runs mezclados (por fecha):**

```bash
python3 -c "
import csv
from collections import Counter
with open('/home/valentina/framework-eval-cs-llm/artifacts/latency/latency_unprotected_direct.csv') as f:
    c = Counter(row['ts_utc'][:10] for row in csv.DictReader(f) if row['method'] == 'POST')
for date, count in sorted(c.items()):
    print(f'{date}: {count} requests')
"
```

### Resetear TODO
```bash
# Eliminar los volúmenes Docker asociados (incluye ChromaDB)
docker compose --env-file .env.regulatory_technical down -v
docker compose --env-file .env.academic_institutional down -v

# 1. Bajar contenedores activos (independiente de cómo fueron levantados)
docker stop tesis_shield tesis_rag ollama_core
docker rm tesis_shield tesis_rag ollama_core

# 2. Eliminar imágenes reconstruibles (no tocar chroma_bootstrap ni garak_runner)
docker rmi framework-eval-cs-llm-shield_api framework-eval-cs-llm-rag_api

# 3. Eliminar artefactos
sudo rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
sudo rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
sudo rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv
sudo rm -f  ~/framework-eval-cs-llm/artifacts/llm_guard.log
sudo rm -f  ~/framework-eval-cs-llm/artifacts/verify_*.log

# 4. Verificar que quedó limpio
docker ps
find ~/framework-eval-cs-llm/artifacts -type f | sort
# Ambos deben quedar vacíos

#Detener y eliminar todos los contenedores
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

# Eliminar todos los volúmenes
docker volume rm $(docker volume ls -q)

# Eliminar todas las imágenes
docker rmi $(docker images -q) --force

# Limpiar redes y cache de build
docker system prune -a --volumes -f

# Eliminar artefactos locales
sudo rm -rf ~/framework-eval-cs-llm/artifacts/runs/*
sudo rm -rf ~/framework-eval-cs-llm/artifacts/consolidated_*.csv
sudo rm -rf ~/framework-eval-cs-llm/artifacts/latency/*.csv
sudo rm -f  ~/framework-eval-cs-llm/artifacts/llm_guard.log
sudo rm -f  ~/framework-eval-cs-llm/artifacts/verify_*.log

# Borrar caché
sudo rm -rf ~/framework-eval-cs-llm/ollama_data/*
sudo rm -rf ~/framework-eval-cs-llm/llm_guard_cache/*
sudo rm -rf ~/framework-eval-cs-llm/chroma_cache/*
sudo rm -rf ~/framework-eval-cs-llm/chroma_db/*
sudo rm -rf ~/framework-eval-cs-llm/garak_runs/*

# Verificar que quedó limpio
docker ps -a       # debe quedar vacío
docker images      # debe quedar vacío
docker volume ls   # debe quedar vacío
find ~/framework-eval-cs-llm/artifacts -type f | sort  # debe quedar vacío

# Continuar desde Paso 1 del RUNBOOK (bootstrap completo)

```

---

### Otros comandos útiles

```bash
# Ver configuración efectiva del stack
docker compose --env-file .env.regulatory_technical --profile attacks run --rm \
  garak_runner where

# Ver imágenes disponibles
docker images

# Ver espacio en disco
df -h
du -sh ~/framework-eval-cs-llm/artifacts/

# Ver logs de LLM Guard (bloqueos por scanner)
docker logs tesis_shield | grep "scanner"

# Instalar pandas si necesitas análisis local
pip install pandas --break-system-packages
```
