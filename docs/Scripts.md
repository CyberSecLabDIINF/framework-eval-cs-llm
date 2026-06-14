# Scripts del laboratorio — LLM-Sec

Todo quedó consolidado en un único archivo: **`llmsec.sh`**. Reemplaza a los
antiguos `lab.sh`, `new-domain.sh` y `smoke-test.sh`.

Coloca `llmsec.sh` en la raíz del proyecto, junto a `docker-compose.yml`, y dale
permisos de ejecución:

```bash
chmod +x llmsec.sh
```

Los comandos están basados en `RUNBOOK.md`.

---

## Subcomandos

| Subcomando | Qué hace |
|---|---|
| `./llmsec.sh smoke <dominio>` | Solo smoke test de un dominio (1 probe × 1 repetición, ambos escenarios) |
| `./llmsec.sh run` | Evalúa los dos dominios base: `regulatory_technical` y `academic_institutional` |
| `./llmsec.sh run <dom1> [dom2] ...` | Evalúa dominios específicos (sin recalibrar umbrales) |
| `./llmsec.sh new` | Crea la configuración de un dominio nuevo y, opcionalmente, lo evalúa de inmediato con calibración de umbrales |
| `./llmsec.sh process` | Solo procesa resultados ya generados (figuras + verificación de CSV) |
| `source llmsec.sh shell <dominio>` | Carga los aliases interactivos (`lab-up`, `lab-down`, etc.) en tu shell |
| `./llmsec.sh help` | Muestra la ayuda |

---

## Uso rápido

```bash
# Evaluar los dos dominios base de principio a fin
./llmsec.sh run

# Solo smoke test de un dominio
./llmsec.sh smoke regulatory_technical

# Crear un dominio nuevo (interactivo) y evaluarlo
./llmsec.sh new

# Reprocesar resultados ya generados
./llmsec.sh process
```

---

## Orden de evaluación de `run`

Para cada dominio, en secuencia:

1. **Levantar stack + auto-corrección.** Si los contenedores están abajo, los
   levanta. Si `tesis_rag` queda *unhealthy*, hace `restart`; si persiste,
   re-ingesta el corpus y vuelve a reiniciar. Igual para `tesis_shield`.
2. **Corpus y ground truth.** Si la colección está vacía, ingesta. Si faltan los
   fragmentos verificables (`[CONFIDENCIAL]`), los reinyecta con `--reset`.
3. **Smoke probe** (LLM07 `goodside.Tag`).
4. **Escenario A** (`unprotected`): adversariales → legítimos → patch garak.
5. **Escenario B** (`protected`): adversariales → legítimos → patch garak.
6. **Bajar el stack** y pasar al siguiente dominio.

Al completar todos los dominios, ejecuta el **procesamiento de resultados**
(`process_results.py --deep --plots`).

El patch de `garak_passed` se hace **dentro de cada escenario**, no al final,
porque `patch_garak_passed` necesita el `RUN_DIR` específico de ese run
(RUNBOOK 4.8 / 5.10).

Orden completo de los cuatro runs:

```
regulatory_technical   → A (adv → legit) → B (adv → legit)
academic_institutional → A (adv → legit) → B (adv → legit)
→ patch (en cada escenario) → procesamiento de resultados
```

---

## Auto-corrección incluida

| Situación | Acción automática |
|---|---|
| Contenedores abajo | Levanta el stack con el `--env-file` del dominio |
| `tesis_rag` unhealthy | `restart`; si persiste, re-ingesta y reinicia |
| `tesis_shield` unhealthy | `restart`; si persiste, marca error para revisión |
| Colección vacía | Ingesta automática con `--reset` |
| Faltan fragmentos verificables | Re-ingesta con `--reset` y reverifica ground truth |
| Run de Garak abortado (< 55 JSONL) | Detecta el run incompleto y lo reanuda con `continue-run` (hasta 2 reintentos) |
| GPU no detectada | Avisa, pero continúa (modo CPU, más lento) |

> El criterio de run válido es de exactamente **55 JSONL**; runs abortados tienen
> entre 0 y 30. Por eso la reanudación nunca entra en bucle infinito: tiene un
> tope de reintentos.

---

## `./llmsec.sh new` — Crear un dominio nuevo

Pregunta el nombre y los umbrales de calibración, y crea:

```
.env.<dominio>
app/config/domains/<dominio>/rag.json
app/config/domains/<dominio>/legitimate_prompts.json
app/config/domains/<dominio>/verification_queries.json
data/raw/<dominio>/
```

Después de crearlo:

1. Coloca los PDF en `data/raw/<dominio>/`
2. Edita los prompts legítimos en `app/config/domains/<dominio>/legitimate_prompts.json`
3. Completa `verification_queries.json` con el ground truth

Si confirmas que todo está listo, lanza la evaluación completa **con
calibración** de umbrales (C11 y C17). Los dominios base **no** se recalibran en
`run` para no sobrescribir la evidencia experimental ya fijada en sus `.env`.

---

## `source llmsec.sh shell <dominio>` — Aliases interactivos

Para trabajo manual día a día, carga atajos en tu shell:

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

> Estos aliases son para inspección manual. El flujo completo de evaluación va
> por los subcomandos (`run`, `smoke`, `new`, `process`), no por los aliases.
