# Scripts del laboratorio — LLM-Sec

Coloca los tres archivos en la raíz del proyecto, junto a `docker-compose.yml`.

---

## Uso rápido

```bash
# 1. Activar dominio y cargar comandos
source lab.sh regulatory_technical

# 2. Crear configuración para un nuevo dominio
bash new-domain.sh

# 3. Ejecutar smoke test automatizado
bash smoke-test.sh regulatory_technical
```

---

## lab.sh — Aliases del laboratorio

Carga funciones en tu shell para reemplazar los comandos largos de Docker Compose.

```bash
source lab.sh <dominio>
```

Recuerda el último dominio usado. La segunda vez puedes omitirlo:

```bash
source lab.sh
```

### Comandos disponibles tras hacer source

| Comando | Descripción |
|---|---|
| `lab-help` | Mostrar todos los comandos |
| `lab-domain` | Ver dominio activo |
| `lab-up` | Levantar stack y esperar healthy |
| `lab-down` | Bajar stack |
| `lab-status` | Estado de contenedores |
| `lab-health` | Health check de ambas APIs |
| `lab-logs` | Logs en tiempo real |
| `lab-logs-rag` | Logs de tesis_rag |
| `lab-logs-shield` | Logs de tesis_shield |
| `lab-ingest` | Ingestar corpus del dominio activo |
| `lab-verify` | Verificar ground truth |
| `lab-attack-a` | Ataque completo Escenario A |
| `lab-attack-b` | Ataque completo Escenario B |
| `lab-legit-a` | Prompts legítimos Escenario A |
| `lab-legit-b` | Prompts legítimos Escenario B |
| `lab-patch-a` | Parchear garak_passed Escenario A |
| `lab-patch-b` | Parchear garak_passed Escenario B |
| `lab-new-domain` | Crear configuración para nuevo dominio |
| `lab-smoke` | Ejecutar smoke test automatizado |

---

## new-domain.sh — Crear nuevo dominio

Pregunta el nombre del dominio y crea automáticamente todos los archivos necesarios.

```bash
bash new-domain.sh
```

### Qué crea

```
.env.<dominio>
app/config/domains/<dominio>/rag.json
app/config/domains/<dominio>/legitimate_prompts.json
app/config/domains/<dominio>/verification_queries.json
data/raw/<dominio>/
```

### Después de ejecutarlo

1. Coloca tus documentos PDF en `data/raw/<dominio>/`
2. Edita los prompts legítimos en `app/config/domains/<dominio>/legitimate_prompts.json`
3. Activa el dominio: `source lab.sh <dominio>`

---

## smoke-test.sh — Smoke test automatizado

Ejecuta los 8 pasos de verificación del laboratorio en secuencia, con auto-corrección de errores comunes.

```bash
bash smoke-test.sh <dominio>
```

### Pasos que ejecuta

| Paso | Descripción | Auto-corrección |
|---|---|---|
| 1 | Prerrequisitos (Docker, GPU, archivos) | — |
| 2 | Stack Docker Compose healthy | Restart y re-ingestión si unhealthy |
| 3 | Ingestión y ground truth | Ingesta automática si corpus vacío |
| 4 | Probe × 1 repetición Escenario A | — |
| 5 | Prompts legítimos Escenario A | — |
| 6 | Patch garak_passed | — |
| 7 | Probe × 1 repetición Escenario B | — |
| 8 | Limpieza de artefactos (opcional) | — |

Al finalizar muestra un resumen con pasos OK, fallidos y auto-correcciones aplicadas.