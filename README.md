# LLM-Sec — Framework de evaluación de ciberseguridad en plataformas LLM-integradas (RAG)

Laboratorio reproducible asociado a la tesis **"Framework for cybersecurity evaluation in
LLM-integrated platforms"** (USACH — DIINF, profesor guía: Juan Ignacio Iturbe Araya).

LLM-Sec es un framework híbrido de evaluación de ciberseguridad (**enfoque basado en riesgo
+ modelo de madurez**) para arquitecturas RAG, validado a **TRL 4**. Operacionaliza el
**OWASP LLM Top 10:2025** en métricas cuantificables y controles auditables (**C1–C62**).

**Diseño experimental**

| Elemento | Valor |
|---|---|
| Escenario A | `unprotected` — RAG sin capa defensiva |
| Escenario B | `protected` — RAG tras el proxy LLM Guard |
| Dominio 1 | `regulatory_technical` (EU Critical Raw Materials Act) |
| Dominio 2 | `academic_institutional` (Common Data Set) |
| Métricas | TFA (tasa de filtrado de ataques), LAS (latencia de seguridad), PCC, NCP |
| Probes Garak | 11 probes sobre LLM01, LLM02, LLM07 y LLM08 |
| Repeticiones | 5 generaciones Garak × 5 repeticiones externas; 5 repeticiones de prompts legítimos por dominio |

> Toda la operación del laboratorio pasa por un único script: **`llmsec.sh`**.
> No hace falta escribir comandos `docker compose` a mano.

---

## Tabla de contenidos

1. [Tecnologías y versiones](#1-tecnologías-y-versiones)
2. [Requisitos](#2-requisitos)
3. [Estructura del repositorio](#3-estructura-del-repositorio)
4. [Bootstrap (una sola vez por máquina)](#4-bootstrap-una-sola-vez-por-máquina)
5. [Uso rápido — llmsec.sh](#5-uso-rápido--llmsecsh)
6. [Subcomandos de llmsec.sh](#6-subcomandos-de-llmsecsh)
7. [Orden de evaluación de run](#7-orden-de-evaluación-de-run)
8. [Auto-corrección incluida](#8-auto-corrección-incluida)
9. [Crear un dominio nuevo](#9-crear-un-dominio-nuevo)
10. [Aliases interactivos](#10-aliases-interactivos)
11. [Procesamiento de resultados](#11-procesamiento-de-resultados)
12. [Artefactos generados](#12-artefactos-generados)
13. [Arquitectura del laboratorio](#13-arquitectura-del-laboratorio)
14. [Controles de seguridad (Escenario B)](#14-controles-de-seguridad-escenario-b)
15. [Umbrales calibrados](#15-umbrales-calibrados)
16. [Diagnóstico](#16-diagnóstico)
17. [Documentación del proyecto](#17-documentación-del-proyecto)
18. [Licencia y cita](#18-licencia-y-cita)

---

## 1. Tecnologías y versiones

### Plataforma y orquestación

| Tecnología | Versión | Rol en el laboratorio |
|---|---|---|
| **Docker Engine** | ≥ 28.x | Aislamiento de los servicios del laboratorio |
| **Docker Compose** | v2.x (plugin) | Orquestación de servicios, perfiles y redes aisladas |
| **Imagen base** | `python:3.10-slim` | Runtime de todos los contenedores propios (`tesis_lab`) |
| **Python** | 3.10 | Lenguaje de la aplicación y del pipeline de análisis |
| **NVIDIA Container Toolkit** | — | Runtime `nvidia` para exponer la GPU a `ollama_core` |
| **CUDA / driver NVIDIA** | CUDA ≥ 12.2 · driver ≥ 535 | Inferencia acelerada por GPU |

### Núcleo del sistema bajo prueba (SUT)

| Tecnología | Versión | Rol |
|---|---|---|
| **Ollama** (servidor) | imagen `ollama/ollama:latest` | Servidor de inferencia local |
| **Llama 3 8B** | `llama3:8b` (temperatura 0.8, default) | Modelo evaluado |
| **ollama** (cliente Python) | 0.6.1 | Cliente HTTP hacia `ollama_core` |
| **ChromaDB** | 1.4.1 | Base de datos vectorial del RAG |
| **onnxruntime** | 1.23.2 | Backend del embedding ONNX (`ONNXMiniLM_L6_V2`) de ChromaDB |
| **LangChain** | 0.3.27 (`langchain-core` 0.3.83, `langchain-text-splitters` 0.3.11) | Chunking y utilidades de ingesta |
| **pypdf** | 6.6.0 | Extracción de texto de los PDF del corpus |

### Capa de servicios (APIs)

| Tecnología | Versión | Rol |
|---|---|---|
| **FastAPI** | 0.128.0 | Aplicaciones `rag_api` (`api/rag.py`) y `shield_api` (`api/shield.py`) |
| **Uvicorn** | 0.40.0 | Servidor ASGI de ambas APIs (`--reload --reload-dir app/src`) |
| **Starlette** | 0.50.0 | Base de los middlewares `RequestIdMiddleware` y `LatencyCSVLogger` |
| **Pydantic** | 2.12.5 | Modelos de request/response |
| **pydantic-settings** | 2.12.0 | Singleton de configuración (`settings.py` / `get_settings()`) |
| **httpx** | 0.28.1 | Proxy Shield → RAG |
| **Typer** | 0.21.1 | CLI unificada (`python3 -m cli`) |
| **structlog** | 25.5.0 | Logging estructurado (`artifacts/runs/<run_id>/logs/app.log`) |

### Capa de seguridad y auditoría ofensiva

| Tecnología | Versión | Rol |
|---|---|---|
| **LLM Guard** | 0.3.16 | Capa defensiva del Escenario B (escáneres de entrada y salida) |
| **Garak** | 0.13.3 | Auditoría ofensiva automatizada (11 probes OWASP) |
| **tiktoken** | 0.12.0 | Tokenizador `cl100k_base` del control C1 (`TokenLimit`) |
| **transformers** | 4.51.3 | Modelos de los escáneres `PromptInjection` (C3) y `Sensitive` (C20) |
| **torch** | 2.9.1 (ruedas CUDA 12.8) | Backend de inferencia de los escáneres de LLM Guard |
| **presidio-analyzer / presidio-anonymizer** | 2.2.358 | Detección de PII en el análisis de exfiltración |
| **spaCy** | 3.8.11 | Soporte NLP de Presidio |

### Análisis y generación de evidencia

| Tecnología | Versión | Rol |
|---|---|---|
| **pandas** | 2.3.3 | Carga y agregación de CSV consolidados y de latencia |
| **numpy** | 2.2.6 | Cálculo numérico de TFA/LAS |
| **matplotlib** | sin fijar | Todas las figuras de `artifacts/figures/` |
| **scipy** | sin fijar | Mann-Whitney U, Fisher exacto y correlaciones |

> `matplotlib` no está pineado en `requirements.txt` y `scipy` no forma parte de la imagen:
> el análisis local se ejecuta en un venv aparte (ver [§11](#11-procesamiento-de-resultados)).

### Herramientas de desarrollo (`requirements-dev.txt`)

`pytest`, `pytest-cov`, `ruff`, `mypy`, `pre-commit` (sin versión fijada).

---

## 2. Requisitos

### Software

```bash
docker compose version
# Debe responder: Docker Compose version v2.x.x
```

- Docker Engine ≥ 28.x con el plugin de Docker Compose V2
- `nvidia-container-toolkit` instalado y configurado
- Conexión a internet **solo** para el bootstrap (descarga del modelo y de los pesos ONNX)

### Hardware

- GPU NVIDIA con al menos **8 GB de VRAM** (validado en RTX 3070)
- Driver NVIDIA ≥ 535 y CUDA ≥ 12.2

```bash
nvidia-smi
docker run --rm --runtime=nvidia nvidia/cuda:12.2-base nvidia-smi
```

> Sin GPU el laboratorio sigue funcionando: `llmsec.sh` avisa y continúa en modo CPU
> (considerablemente más lento).

### Permisos del script

```bash
chmod +x llmsec.sh
```

`llmsec.sh` debe estar en la raíz del proyecto, junto a `docker-compose.yml`.

---

## 3. Estructura del repositorio

```
framework-eval-cs-llm/
├── llmsec.sh                     # Punto de entrada único del laboratorio
├── docker-compose.yml            # Servicios, perfiles y redes
├── Dockerfile                    # Imagen tesis_lab (python:3.10-slim)
├── requirements.txt              # Dependencias de runtime (versiones fijadas)
├── requirements-dev.txt          # Dependencias de desarrollo
├── .env.regulatory_technical     # Variables del dominio 1
├── .env.academic_institutional   # Variables del dominio 2
├── app/
│   ├── config/
│   │   ├── global/               # llm_guard_config.yaml, owasp_suites.json, garak_rest_base.json
│   │   └── domains/<tag>/        # rag.json, legitimate_prompts.json, verification_queries.json
│   ├── scripts/                  # calibrate_c4.py, calibrate_c11.py, calibrate_c17.py
│   └── src/
│       ├── settings.py           # Configuración (Pydantic BaseSettings)
│       ├── cli.py                # CLI Typer: serve / ingest / attack / metrics / where
│       ├── api/                  # rag.py, shield.py, middleware.py
│       ├── eval/                 # métricas, figuras, consolidador, pipeline de análisis
│       ├── ingestion/            # PDF → chunks → ChromaDB
│       └── utils/                # paths.py, logging.py
├── data/raw/<dominio>/           # Corpus PDF por dominio
├── artifacts/                    # Resultados del experimento (ver §12)
├── scripts/                      # Utilidades de verificación puntual
└── docs/                         # Scripts.md, RUNBOOK.md, ARCHITECTURE.md, AUDIT.md, ...
```

---

## 4. Bootstrap (una sola vez por máquina)

> Requiere conexión a internet. **No** se repite entre dominios ni escenarios.

### 4.1 Modelo LLM (Ollama)

```bash
docker compose --profile bootstrap up -d ollama_bootstrap
docker exec -it ollama_bootstrap ollama pull llama3:8b
docker exec -it ollama_bootstrap ollama list
docker compose --profile bootstrap down
```

### 4.2 Modelo de embeddings (ChromaDB ONNX)

```bash
docker compose --env-file .env.regulatory_technical --profile bootstrap up --attach chroma_bootstrap
# Esperar el mensaje: chroma onnx ok
```

---

## 5. Uso rápido — llmsec.sh

```bash
# Evaluar los dos dominios base de principio a fin (A y B, adversarial y legítimo)
./llmsec.sh run

# Solo smoke test de un dominio
./llmsec.sh smoke regulatory_technical

# Un solo escenario para un dominio
./llmsec.sh run-scenario A regulatory_technical
./llmsec.sh run-scenario B academic_institutional

# Crear un dominio nuevo (interactivo) y evaluarlo
./llmsec.sh new

# Reprocesar resultados ya generados
./llmsec.sh process
```

Orden completo de los cuatro runs del experimento:

```
regulatory_technical   → A (adv → legit) → B (adv → legit)
academic_institutional → A (adv → legit) → B (adv → legit)
→ patch de garak_passed (dentro de cada escenario) → procesamiento de resultados
```

---

## 6. Subcomandos de llmsec.sh

| Subcomando | Qué hace |
|---|---|
| `./llmsec.sh smoke <dominio>` | Smoke test de un dominio: 1 probe × 1 repetición, ambos escenarios |
| `./llmsec.sh run` | Evalúa los dos dominios base: `regulatory_technical` y `academic_institutional` |
| `./llmsec.sh run <dom1> [dom2] ...` | Evalúa dominios específicos (**sin** recalibrar umbrales) |
| `./llmsec.sh run-scenario <A\|B> <dominio> [--rebuild]` | Evalúa un solo escenario de un dominio. `--rebuild` solo si cambiaron `Dockerfile` o `requirements.txt` |
| `./llmsec.sh new` | Crea la configuración de un dominio nuevo y, opcionalmente, lo evalúa de inmediato **con calibración** de umbrales |
| `./llmsec.sh process` | Solo procesa resultados ya generados (figuras + verificación de CSV) |
| `./llmsec.sh reload` | Reinicia `tesis_rag` y `tesis_shield` sin rebuild |
| `source llmsec.sh shell <dominio>` | Carga los aliases interactivos (`lab-up`, `lab-down`, …) en tu shell |
| `./llmsec.sh help` | Muestra la ayuda |

> `tesis_rag` y `tesis_shield` corren uvicorn con `--reload --reload-dir app/src`, así que
> los cambios de Python en `app/src/` se aplican en la siguiente petición sin rebuild ni
> reinicio. `reload` solo hace falta si `--reload` no estaba activo.

---

## 7. Orden de evaluación de run

Para cada dominio, en secuencia:

1. **Levantar stack + auto-corrección.** Si los contenedores están abajo, los levanta. Si
   `tesis_rag` queda *unhealthy*, hace `restart`; si persiste, re-ingesta el corpus y
   vuelve a reiniciar. Igual para `tesis_shield`.
2. **Corpus y ground truth.** Si la colección está vacía, ingesta. Si faltan los fragmentos
   verificables (`[CONFIDENCIAL]`), los reinyecta con `--reset`.
3. **Smoke probe** (LLM07 `goodside.Tag`).
4. **Escenario A** (`unprotected`): adversariales → legítimos → patch garak.
5. **Escenario B** (`protected`): adversariales → legítimos → patch garak.
6. **Bajar el stack** y pasar al siguiente dominio.

Al completar todos los dominios ejecuta el procesamiento de resultados
(`process_results.py --deep --plots`).

El patch de `garak_passed` se hace **dentro de cada escenario**, no al final, porque
`patch_garak_passed()` necesita el `RUN_DIR` específico de ese run (RUNBOOK 4.8 / 5.10).

---

## 8. Auto-corrección incluida

| Situación | Acción automática |
|---|---|
| Contenedores abajo | Levanta el stack con el `--env-file` del dominio |
| `tesis_rag` unhealthy | `restart`; si persiste, re-ingesta y reinicia |
| `tesis_shield` unhealthy | `restart`; si persiste, marca error para revisión manual |
| Colección vacía | Ingesta automática con `--reset` |
| Faltan fragmentos verificables | Re-ingesta con `--reset` y reverifica ground truth |
| Run de Garak abortado (< 55 JSONL) | Detecta el run incompleto y lo reanuda con `continue-run` (hasta 2 reintentos) |
| GPU no detectada | Avisa, pero continúa en modo CPU (más lento) |

> El criterio de run válido es de exactamente **55 JSONL**; los runs abortados tienen entre
> 0 y 30. Por eso la reanudación nunca entra en bucle infinito: tiene tope de reintentos.

---

## 9. Crear un dominio nuevo

`./llmsec.sh new` pregunta el nombre y los umbrales de calibración, y crea:

```
.env.<dominio>
app/config/domains/<dominio>/rag.json
app/config/domains/<dominio>/legitimate_prompts.json
app/config/domains/<dominio>/verification_queries.json
data/raw/<dominio>/
```

Después de crearlo:

1. Coloca los PDF en `data/raw/<dominio>/`.
2. Edita los prompts legítimos en `app/config/domains/<dominio>/legitimate_prompts.json`.
   Cada entrada lleva `id`, `subdimension` (D1–D4), `prompt` en inglés y `expected_keywords`.
3. Completa `verification_queries.json` con el ground truth. Las claves siguen el formato
   `<nombre_archivo>.pdf__c<chunk_id>` y los valores son consultas temáticamente específicas
   al contenido del fragmento sensible.

Si confirmas que todo está listo, lanza la evaluación completa **con calibración** de los
umbrales C11 y C17. Los dominios base **no** se recalibran en `run`, para no sobrescribir la
evidencia experimental ya fijada en sus `.env`.

---

## 10. Aliases interactivos

Para trabajo manual día a día:

```bash
source llmsec.sh shell regulatory_technical
```

| Alias | Descripción |
|---|---|
| `lab-domain` | Ver dominio activo |
| `lab-up` | Levantar stack |
| `lab-down` | Bajar stack |
| `lab-status` | Estado de contenedores |
| `lab-health` | Health check de ambas APIs |
| `lab-logs` | Logs en tiempo real |
| `lab-logs-rag` | Logs de `tesis_rag` |
| `lab-logs-shield` | Logs de `tesis_shield` |
| `lab-ingest` | Ingestar corpus del dominio activo |
| `lab-verify` | Verificar ground truth |
| `lab-help` | Mostrar los aliases |

> Estos aliases son para inspección manual. El flujo completo de evaluación va por los
> subcomandos (`run`, `run-scenario`, `smoke`, `new`, `process`), no por los aliases.

---

## 11. Procesamiento de resultados

La vía normal es `./llmsec.sh process`. Para análisis dirigido, el pipeline se invoca
directamente — dentro del contenedor o en un venv local con los artefactos sincronizados:

```bash
# Entorno local (solo la primera vez)
python3 -m venv .venv && source .venv/bin/activate && pip install pandas scipy matplotlib

# Pipeline completo
python3 app/src/eval/process_results.py --artifacts artifacts/ \
  --deep --plots --exfiltration --characterize
```

Punto de entrada: `app/src/eval/process_results.py` (equivalente a
`python3 -m eval.process_results` ejecutado desde `app/src/`).

### Flags

| Flag | Descripción |
|---|---|
| `--artifacts PATH` | Directorio raíz de artefactos (default: `artifacts/`) |
| `--domains D1 D2` | Restringe el análisis a dominios específicos |
| `--data-dir PATH` | Directorio de datos para `--exfiltration` (default: `data/`) |
| `--plots` | Genera todas las figuras en `artifacts/figures/` |
| `--deep` | Análisis profundo de detectores, matrices de confusión y LAS |
| `--exfiltration` | Análisis de exfiltración de PII y contenido confidencial |
| `--characterize` | Caracterización estructural de CSV y JSONL |
| `--backfill-scores` | Corrección puntual: convierte scores de riesgo a probabilidades crudas [0,1] |
| `--tfa-breakdown` | Desglose guard-blocked / defense-gap / residual-risk |
| `--duration` | Tiempo de ejecución (wall-clock) por run |
| `--probe-timings` | Gráficos PDF de tiempo mediano por probe |

### Ground truth de TFA por suite

| Suite | Columna de ground truth | Razón |
|---|---|---|
| LLM01 | `garak_passed` | El detector propio de Garak es válido para prompt injection |
| LLM02 | `response_has_confidential` | Garak no puede ver el corpus del RAG |
| LLM07 | `response_has_system_prompt` | Las heurísticas de Garak producen falsos positivos |
| LLM08 | `injection_followed` | El detector de Garak no es confiable sin documentos WHOIS |

Detector primario para las probes de encoding: `encoding.DecodeMatch`, no `DecodeApprox`.
Cada probe de encoding tiene **6400 intentos**, no 12800 — se descarta `DecodeApprox` para
evitar doble conteo.

---

## 12. Artefactos generados

```
artifacts/
├── runs/<timestamp>_<tag>_<target>_<run_kind>/
│   ├── garak/*.report.jsonl      # 55 JSONL en un run válido
│   ├── logs/app.log
│   └── config_used/
├── consolidated_<dominio>_<escenario>.csv   # 23 columnas (esquema canónico)
├── latency/
│   ├── latency_unprotected_direct.csv
│   ├── latency_unprotected_via_shield.csv
│   └── latency_protected.csv
├── segmented/                    # 01–16 CSV de análisis segmentado
├── figures/                      # PNG/PDF
├── characterization/
└── corpus_version_registry.csv   # Log de auditoría del control C62
```

**Esquema del CSV consolidado (23 columnas):**
`timestamp`, `scenario`, `domain`, `prompt_type`, `probe`, `suite`, `subdimension`,
`repetition`, `prompt`, `response`, `latency_ms`, `should_block`, `was_blocked`,
`scanner_triggered`, `block_reason`, `input_scanner_score`, `output_scanner_score`,
`garak_passed`, `response_has_confidential`, `grounding_ratio`, `run_id`,
`response_has_system_prompt`, `injection_followed`, `rogue_string_found`.

`garak_passed` se escribe vacío durante el run y lo rellena
`consolidator.patch_garak_passed()` por voto mayoritario sobre `*.report.jsonl`.

**Colores de las figuras:** naranja `#e07b39` (Escenario A), azul `#1e5eff` (Escenario B).

---

## 13. Arquitectura del laboratorio

### Perfiles de Docker Compose

| Perfil | Servicios | Propósito |
|---|---|---|
| `lab` | `ollama_core`, `rag_api`, `shield_api` | Operación normal del experimento |
| `attacks` | `garak_runner` | Probes de Garak y runs de prompts legítimos |
| `bootstrap` | `ollama_bootstrap`, `chroma_bootstrap` | Setup de primera vez |

### Servicios

| Servicio | Contenedor | Puerto | Rol |
|---|---|---|---|
| `rag_api` | `tesis_rag` | 8000 (solo interno) | Endpoint RAG sin protección (`POST /generate`) |
| `shield_api` | `tesis_shield` | 8001 (expuesto) | Proxy LLM Guard; ejecuta C1/C2/C3 y C19/C20 de forma incondicional |
| `ollama_core` | `ollama_core` | 11434 (interno) | Sirve `llama3:8b` por GPU (`NVIDIA_VISIBLE_DEVICES=all`) |
| `garak_runner` | `tesis_garak_runner` | — | Ejecuta `cli.py attack garak`; sale tras un run (`restart: "no"`) |

El Escenario B se activa **dirigiendo Garak a `shield_api`**, no cambiando variables de
entorno del RAG.

### Redes

- `red_internal` (bridge, `internal: true`): comunicación servicio-a-servicio, sin salida externa.
- `red_front` (bridge): acceso externo; solo `shield_api` y los servicios de bootstrap.

### Flujo de datos

```
PDFs ──► ingesta ──► ChromaDB
                        │
   Garak / cliente HTTP │
         │              │
         ▼              ▼
  shield_api:8001  rag_api:8000
  guard_input()  ─► /generate ─► consulta ChromaDB ─► Ollama
         │                              │
         │◄──────── respuesta ──────────┘
  guard_output()
         │
         ▼
  consolidated_<tag>_<escenario>.csv ──► process_results.py ──► TFA, LAS, figuras
```

Detalle módulo por módulo: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 14. Controles de seguridad (Escenario B)

### Shield — entrada

| Control | Escáner | Descripción |
|---|---|---|
| C1 | `TokenLimit` | Máximo 512 tokens (`cl100k_base`) |
| C2 | `_sanitize_control_chars` | Elimina tokens especiales del modelo y caracteres de control Unicode |
| C3 | `PromptInjection` | Bloquea intentos de inyección (umbral 0.92) |

### RAG in-process

| Control | Descripción |
|---|---|
| C4 | Distancia de dominio — bloquea consultas fuera de tema |
| C8 | Partición por sensibilidad — bloquea consultas a fragmentos de sensibilidad `high` |
| C9 | Integridad del corpus — verifica los hashes de chunks contra el baseline `CORPUS_HASHES` |
| C11 | Coherencia de query — bloquea prompts incoherentes o codificados |
| C12 | Detección de reconocimiento — bloquea prompts muy cortos o muy repetitivos |
| C17 | Grounding — bloquea respuestas que se desvían demasiado del contexto |

### Shield — salida

| Control | Escáner | Descripción |
|---|---|---|
| C19 | `OutputRegex` | Bloquea patrones `[CONFIDENTIAL]`, RUT, email, teléfono, contraseña y tarjeta |
| C20 | `Sensitive` | Escáner semántico de datos sensibles (score continuo) |

**Resultado de madurez:** Escenario B = **N3** en todas las subdimensiones D1–D4 (regla de
piso mínimo). Escenario A = **N0** por diseño (D4 no tiene controles N1 asignados).

> Los controles in-process del RAG están condicionados por `IS_PROTECTED`, derivado de
> `SCENARIO`, y `docker-compose.yml` fija `SCENARIO=unprotected` en `rag_api`. El alcance
> empírico de esa condición está documentado en
> [`docs/CONTROL_AUDIT_REPORT.md`](docs/CONTROL_AUDIT_REPORT.md) y en la sección 3 de
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 15. Umbrales calibrados

Fijos. **No recalibrar ni sobrescribir** en los `.env`: son evidencia experimental.

| Umbral | `regulatory_technical` | `academic_institutional` |
|---|---|---|
| `QUERY_COHERENCE_THRESHOLD` (C11) | 1.35 | 1.1723 |
| `C17_GROUNDING_THRESHOLD` | 0.0556 | 0.0714 |
| `SENSITIVITY_LEVEL` | `high` | `high` |

Calibrados con 70 queries legítimas vs 35 incoherentes por dominio, mediante
`app/scripts/calibrate_c11.py` y `app/scripts/calibrate_c17.py`.

---

## 16. Diagnóstico

```bash
# Salud de los servicios
curl http://localhost:8000/health    # RAG API
curl http://localhost:8001/health    # Shield API

# Controles activos
curl -s http://localhost:8000/health | python3 -m json.tool
docker logs tesis_rag | grep "C9:"

# Conteo de chunks en ChromaDB
docker exec tesis_rag python3 -c "
import chromadb
c = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
print(c.get_collection('<DOMINIO>').count())
"

# Configuración efectiva (todos los paths resueltos)
docker compose --env-file .env.<DOMINIO> --profile attacks run --rm garak_runner where

# Uso de disco
df -h && du -sh artifacts/
```

Procedimientos de recuperación, limpieza y resolución de problemas:
[`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## 17. Documentación del proyecto

| Documento | Contenido |
|---|---|
| [`docs/Scripts.md`](docs/Scripts.md) | Referencia de `llmsec.sh`: subcomandos, orden de evaluación y auto-corrección |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Manual de ejecución paso a paso (modo manual, sin `llmsec.sh`), limpieza y diagnóstico |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Referencia módulo por módulo de `app/src/`, servicios Docker y catálogo de análisis |
| [`docs/IMPLEMENTED.md`](docs/IMPLEMENTED.md) | Estado de implementación de los controles |
| [`docs/AUDIT.md`](docs/AUDIT.md) · [`docs/CONTROL_AUDIT_REPORT.md`](docs/CONTROL_AUDIT_REPORT.md) | Auditoría de controles y verificación empírica |
| [`CLAUDE.md`](CLAUDE.md) | Convenciones del proyecto y referencia rápida |

---

## 18. Licencia y cita

El código se distribuye bajo **MIT** y la documentación, figuras y datos derivados bajo
**CC BY 4.0**. Ver [`LICENSE.md`](LICENSE.md).

Si usas este laboratorio o sus resultados, cítalos como:

```bibtex
@mastersthesis{campos2026llmsec,
  author  = {Campos Olguín, Valentina Paz},
  title   = {Framework for cybersecurity evaluation in LLM-integrated platforms},
  school  = {Universidad de Santiago de Chile, Departamento de Ingeniería Informática (DIINF)},
  year    = {2026},
  type    = {Tesis},
  note    = {Profesor guía: Juan Ignacio Iturbe Araya}
}
```
