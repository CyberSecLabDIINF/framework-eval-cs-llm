# AUDIT.md — Auditoría de código del marco LLM-Sec

**Metodología:** lectura directa de código (Fase 1), contraste contra las definiciones canónicas de controles suministradas (Fase 2), y contraste contra `docs/IMPLEMENTED.md` (Fase 3). Donde fue posible, las conclusiones se validaron adicionalmente contra `git log -p`, contra los CSV consolidados reales en `artifacts/`, y contra `controles_llmsec.csv`. No se modificó ningún archivo.

---

## 1. Resumen ejecutivo

- **`docs/IMPLEMENTED.md` es, en lo sustancial, correcto y consistente con el código.** Las 62 filas revisadas (los ~26 controles Config/Exp hasta N3 relevantes para el laboratorio) tienen artefacto de código real, verificable, en el archivo y función citados.
- **Se encontró una discrepancia bloqueante real, pero NO es la que sugiere `IMPLEMENTED.md`: es la que sugiere la tesis.** El umbral de `PromptInjection` (C3) efectivamente aplicado durante la recolección de datos fue **0.92**, no 0.75. La cifra 0.75 proviene de una confusión de indexación entre dos secciones del mismo YAML (ver §3). Esto está confirmado no solo por lectura de código sino por los datos reales en `artifacts/consolidated_*_protected.csv`.
- **C20 es N3, no N2** — coincide con `IMPLEMENTED.md` y con la definición canónica del marco. No hay discrepancia aquí.
- **El conteo "26 controles únicos, 33-34 aplicaciones" de la tesis es correcto**, y el rango 33-34 (en vez de un número fijo) tiene una causa identificable: la asignación multi-subdimensión de C17/C14 difiere entre `controles_llmsec.csv` y `docs/IMPLEMENTED.md` (ver §5).
- **C24 (monitoreo de reconocimiento entre sesiones) no existe en el código.** Confirmado por búsqueda exhaustiva. `IMPLEMENTED.md` lo marca correctamente como `🔲 Fuera de alcance experimental`.
- Se encontró además una discrepancia **no solicitada explícitamente pero relevante**: `CLAUDE.md` documenta `C17_GROUNDING_THRESHOLD` para `academic_institutional` como `0.0714`, pero el valor real en `.env.academic_institutional` es `0.0625`. Ver §6.

**Discrepancias bloqueantes:** 1 (el umbral real de C3, que invalida el "punto operativo desplegado τ_in = 0.75" reportado en la tesis).
**Discrepancias menores/documentales:** 3 (CLAUDE.md vs .env; controles_llmsec.csv vs IMPLEMENTED.md en la asignación de C14/C17; comentario obsoleto "index 1" en el YAML).

---

## 2. Tabla maestra

| Control | Marco dice | Código hace (archivo:función) | IMPLEMENTED.md dice | ¿Coincide? |
|---|---|---|---|---|
| C1 | Limitar longitud máx. del prompt en unidad de ventana de contexto | `app/config/global/llm_guard_config.yaml:13-16` (`token_limit.limit: 512`, `encoding_name: cl100k_base`) → instanciado en `shield.py:guard_input()` L206-212 como `TokenLimit(limit=512, encoding_name="cl100k_base")` | Igual, cita el YAML | ✅ Sí |
| C2 | Eliminar tokens especiales, bytes nulos, control Unicode **antes** de cualquier análisis | `shield.py:_sanitize_control_chars()` L128-145; llamada como primera línea de `guard_input()` L198 (antes de TokenLimit/PromptInjection) y primera línea de `guard_output()` L271 (antes de Sensitive/Regex) | Cita `_sanitize_control_chars()` | ✅ Sí, orden correcto verificado |
| C3 | Bloquear inputs de inyección según score vs umbral configurado | `shield.py:guard_input()` L214-220, `PromptInjection(threshold=pi_threshold, ...)`, `pi_threshold = pi_cfg.get("threshold", 0.92)` L202, lee `input_scanners.prompt_injection.threshold` del YAML (valor real: **0.92**, ver §3) | Cita `threshold: 0.92` | ✅ Sí en el valor citado; **la tesis (no IMPLEMENTED.md) reporta 0.75, que es incorrecto** |
| C4 | Bloquear consultas cuya distancia semántica mínima al corpus supere umbral | `rag.py:is_on_domain()` L247-264, compara contra `DOMAIN_DISTANCE_THRESHOLD` (env var, default 1.0; real: 0.9855/1.2943 según dominio) | Cita `is_on_domain()` | ✅ Sí |
| C5 | Extraer solo el texto generado, sin el system prompt | `rag.py:generate()` L540 `out = response.get("response", "")` | Cita la misma línea | ✅ Sí; corre en ambos escenarios (no gateado por `IS_PROTECTED`) |
| C8 | Clasificar sensibilidad al indexar y restringir recuperación a niveles autorizados | `ingestion/generic_dir.py:_classify_sensitivity()` L16-22 (asigna high/medium/low al metadato al ingestar); `rag.py:retrieve_context()` L220-221 (`where_filter` con `ALLOWED_SENSITIVITY`, **solo si `IS_PROTECTED`**) | Cita ambos | ✅ Sí; **solo Escenario B** — en A, `where_filter=None` |
| C9 | Verificar integridad de fragmentos recuperados contra baseline | `rag.py:_build_corpus_hashes()` L168-189 (baseline al arranque); `rag.py:validate_corpus_integrity()` L367-390, invocada en `generate()` L518-519 **después de** `retrieve_context()` y **antes de** construir el prompt (L529) | Cita `validate_corpus_integrity()` | ✅ Sí, orden correcto; solo si `IS_PROTECTED` |
| C11 | Bloquear consultas cuya distancia mínima a fragmentos supere umbral de coherencia | `rag.py:is_coherent_query()` L266-285, compara contra `QUERY_COHERENCE_THRESHOLD` (env var; calibrado 1.35 / 1.1723) | Cita `is_coherent_query()` | ✅ Sí; solo si `IS_PROTECTED` |
| C12 | Detectar y bloquear reconocimiento/enumeración sistemática del corpus | `rag.py:is_safe_from_reconnaissance()` L287-318 — detector léxico (regex) + estructural (longitud + ratio de repetición); **opera por request individual, no across-session** | Cita `is_safe_from_reconnaissance()` | ✅ Sí (y correctamente NO confundido con C24) |
| C14 | Excluir metadatos en la etapa de recuperación | `rag.py:retrieve_context()` L225 `include=["documents", "ids"]` (sin `"metadatas"`) | Cita la misma línea, la ubica **solo en D2** | ⚠️ Ver §5 — `controles_llmsec.csv` la etiqueta D2,D3; `IMPLEMENTED.md`/prompt canónico la etiquetan D2 solamente. Código en sí correcto. |
| C17 | Bloquear respuestas cuyo solapamiento con contexto caiga bajo umbral de fundamentación | `rag.py:is_grounded_response()` L320-365, compara `ratio` contra `_C17_GROUNDING_THRESHOLD` (env var; calibrado 0.0556 / **0.0625**, no 0.0714 — ver §6) | Cita `is_grounded_response()`, la lista en D2 **y** D3 | ✅ Sí; corresponde al marco canónico "D2/D3-N2" del enunciado |
| C18 | Eliminar control chars/tokens especiales de la salida **antes** de escáneres de contenido | `shield.py:guard_output()` L271 `text = _sanitize_control_chars(text)`, ejecutado **antes** del loop de escáneres (L301) | Cita `guard_output()` | ✅ Sí, orden verificado explícitamente en código |
| C19 | Bloquear respuestas por **patrones deterministas** (regex) | `shield.py:guard_output()` L288-295, `OutputRegex(patterns=..., match_type="search")` — alias de `llm_guard.output_scanners.Regex`; `scanner_triggered` se escribe como literal `"Regex"` (nombre de clase real, no el alias) | Cita escáner `OutputRegex` / `output_scanners.regex` en YAML | ✅ Sí — confirma mapeo determinista=Regex |
| C20 | Detectar y puntuar mediante **análisis semántico** contenido sensible no capturado por patrones | `shield.py:guard_output()` L279-286, `Sensitive(threshold=sens_threshold, ...)`; `scanner_triggered` literal `"Sensitive"`, score continuo persistido en `output_scanner_score` | Cita escáner `Sensitive`, N3 | ✅ Sí — N3 confirmado (no N2), mapeo semántico=Sensitive correcto |
| C23 | Registrar decisión de bloqueo identificando el componente que la originó | `consolidator.py:log_request()` L212 columna `scanner_triggered`; poblada en `shield.py` L403/451/470 con literales `TokenLimit`/`PromptInjection`/`Sensitive`/`Regex`/`None` | Cita `log_request()` / `scanner_triggered` | ✅ Sí |
| C24 | Monitorear patrones de consulta anómalos **entre múltiples sesiones** | **No existe.** Búsqueda exhaustiva (`grep -rniE "session\|anomal\|cross-session"` en `app/src`) no encuentra ninguna funcionalidad de correlación entre sesiones/usuarios; `is_safe_from_reconnaissance()` (C12) es estrictamente per-request | `🔲 Fuera de alcance experimental` | ✅ Sí — confirmado, no refutado |
| C25 | Registrar latencia y metadatos de cada solicitud | `middleware.py:LatencyCSVLogger` L36-175, CSV con `ts_utc, scenario, domain, method, path, status_code, latency_ms, request_id, garak_tag, prompt_len, response_len, run_id` | Cita `LatencyCSVLogger` | ✅ Sí |
| C31 | Registrar motivo de bloqueo estructurado | `consolidator.py:log_request()` columna `block_reason`; poblada en `shield.py` L404/452/455 como `input_<scanner>`/`output_<scanner>`; en `rag.py:_blocked_response()` L399 con literales (`domain_validation_failed`, etc.) | Cita `log_request()` / `block_reason` | ✅ Sí |
| C32 | Verificar hash criptográfico de que el system prompt no fue modificado | `rag.py:SYSTEM_PROMPT_HASH` L92-94 (baseline al arranque); `rag.py:validate_system_prompt_integrity()` L236-245, invocada primero en el pipeline `generate()` L482 | Cita `validate_system_prompt_integrity()` | ✅ Sí; solo si `IS_PROTECTED` |
| C62 | Registro versionado y persistente de cada evento de indexación | `cli.py:_record_corpus_version()` L164-203, escribe a `artifacts/corpus_version_registry.csv`, invocada en `ingest_callback()` L246-254 tras cada ingest | Cita `_record_corpus_version()` | ✅ Sí; corre en ambos escenarios (no depende de `IS_PROTECTED`, es acción de ingesta, no de runtime) |

**No solicitados explícitamente pero verificados de paso (mencionados en `IMPLEMENTED.md` D1/D2 N1 y consistentes con el código):** C6 (delimitadores `Context:`/`Question:` en `rag.py:generate()` L529-537), C7/C10/C13 (`n_results=k=3` hardcodeado en `retrieve_context()` L198, no configurable vía `rag.json` pese a lo que sugiere la tabla de `rag.json` en CLAUDE.md — nota menor), C15 (inyección de `SYSTEM_ROLE`/`RESTRICTIONS` desde `rag.json`), C16 (Shield como servicio proxy independiente en `docker-compose.yml`), C21 (config vía variables de entorno en `docker-compose.yml`).

---

## 3. Umbral real usado en el experimento

**Conclusión: el umbral de PromptInjection (C3) efectivamente vigente durante la recolección de datos fue τ_in = 0.92. La cifra τ_in = 0.75 reportada en la tesis no corresponde al valor que bloqueó tráfico real.**

Evidencia, en orden de fuerza creciente:

1. **Lectura de código.** `shield.py:guard_input()` L200-202:
   ```python
   pi_cfg = _input_cfg.get("prompt_injection", {})
   pi_threshold = pi_cfg.get("threshold", 0.92)
   ```
   Esto lee **literalmente** la clave `input_scanners.prompt_injection.threshold` del YAML — no consulta en ningún punto `sensitivity_analysis.active_threshold_index` ni `sensitivity_analysis.prompt_injection_thresholds`. Esas dos claves solo son leídas por `eval/threshold_sensitivity.py:load_thresholds()` (línea 81), un script de análisis **post-hoc** que nunca se importa ni se invoca desde `shield.py` o `rag.py`.

2. **Historia de git del YAML** (`git log -p -- app/config/global/llm_guard_config.yaml`):
   - **16 may** (commit `068a31fc`): se agrega `threshold: 0.92 # active threshold (default, index 1)` y, por separado, `prompt_injection_thresholds: [0.75, 0.92, 0.97]` con `active_threshold_index: 1`. En ese momento **el comentario era correcto**: `[0.75, 0.92, 0.97][1] == 0.92`.
   - **3 jul** (commit `88e964bb`): el arreglo `prompt_injection_thresholds` cambia a `[0.50, 0.75, 0.92]`, pero `active_threshold_index` **no se toca** (sigue en `1`). Desde este commit, `[0.50, 0.75, 0.92][1] == 0.75` — el índice ya no apunta al mismo valor que el `threshold:` literal (que tampoco se tocó, sigue en `0.92`). El comentario "index 1" queda obsoleto pero no se corrige.
   - **7 jul** (commit `12651f05`, "feat: gráficos de controles" — el commit más reciente en `main` antes de esta auditoría): el arreglo se expande a `[0.10, 0.25, 0.50, 0.75, 0.92, 0.99]` y `active_threshold_index` pasa a `3`. `[0.10, 0.25, 0.50, 0.75, 0.92, 0.99][3] == 0.75`. El literal `threshold: 0.92` **nunca cambió en toda la historia del archivo** (confirmado con `grep -n "threshold: 0" <diff completo>`: solo hay una línea `+    threshold: 0.92` en todo el historial, la del 16 de mayo).
   
   Es decir: la sección `sensitivity_analysis` fue evolucionando para fines del script de análisis de sensibilidad (probablemente para que la grilla de barrido incluyera y "marcara como activo" el valor 0.75 que se quería reportar), mientras que el escáner que realmente bloqueaba tráfico en `shield.py` seguía leyendo el `threshold: 0.92` original, sin relación con esos cambios.

3. **Evidencia empírica en los datos reales del experimento.** Se inspeccionaron `artifacts/consolidated_regulatory_technical_protected.csv` (ventana temporal 2026-06-24 → 2026-07-03) y `artifacts/consolidated_academic_institutional_protected.csv` (2026-07-03 → 2026-07-05) — ambas corridas ocurrieron **antes** del commit del 7 de julio que tocó por última vez `active_threshold_index`, y en todo caso el literal `threshold: 0.92` es constante en todo el rango temporal relevante:
   ```
   PromptInjection-blocked input_scanner_score: min=0.9275  max=1.0000  (n=27195, regulatory)
   PromptInjection-blocked input_scanner_score: min=0.9275  max=1.0000  (n=27245, academic)
   ```
   Si el umbral realmente vigente hubiera sido 0.75, se esperarían bloqueos de `PromptInjection` con scores en el rango [0.75, 0.92) — **no existe ni una sola fila así en ninguno de los dos CSV**. El score mínimo observado en filas bloqueadas es 0.9275, consistente únicamente con un umbral efectivo de 0.92 (el score debe superar estrictamente el umbral para bloquear, per la lógica de LLM Guard).

   Como control cruzado, se verificó también el escáner de salida `Sensitive` (C20): `scanner_triggered == "Sensitive"` tiene `output_scanner_score` mínimo = 0.5000 en ambos dominios, consistente con el `threshold: 0.5` literal del YAML — y en este caso **sí coincide** con `sensitive_thresholds[3] == 0.50` del estado actual del YAML, por pura coincidencia numérica (no porque el código lea ese índice).

**Implicación:** el análisis de sensibilidad de umbrales reportado en la tesis, si asume que el punto "activo" (el que generó los datos reales) es τ_in=0.75, está mal anclado. El punto activo real es τ_in=0.92, τ_out=0.50. Cualquier conclusión que compare "el comportamiento con τ_in=0.75" contra "el comportamiento observado" está comparando dos cosas distintas sin saberlo, porque los datos observados fueron generados con τ_in=0.92.

---

## 4. Mapeo escáner → control verificado en código

| Escáner LLM Guard (nombre de clase real) | Instanciado en | Control | Naturaleza | Valor de umbral / config | Score persistido |
|---|---|---|---|---|---|
| `TokenLimit` | `shield.py:guard_input()` L207-212 | C1 | Binario (no produce score útil; sentinel -1.0) | `limit=512`, `encoding_name=cl100k_base` — YAML | — (no participa de `input_scanner_score`) |
| `PromptInjection` | `shield.py:guard_input()` L216-219 | C3 | Score continuo [0,1] vs umbral | **0.92** (YAML literal, hardcoded desde mayo, ver §3) | `input_scanner_score` |
| `Sensitive` | `shield.py:guard_output()` L281-285 | C20 | Score continuo [0,1] vs umbral, **semántico** | 0.50 (YAML literal) | `output_scanner_score` |
| `Regex` (importado como alias `OutputRegex`) | `shield.py:guard_output()` L290-294 | C19 | Binario, **determinista** (6 patrones regex: `[CONFIDENTIAL]`, RUT, email, teléfono CL, contraseña, tarjeta) | patrones fijos en YAML `output_scanners.regex.patterns` | — (no produce score numérico) |

`scanner_triggered` en el CSV toma exactamente estos 4 valores literales (nombre de clase Python, no el alias de import): `TokenLimit`, `PromptInjection`, `Sensitive`, `Regex`, o cadena vacía si no hubo bloqueo. Verificado tanto en `shield.py` (`scanner.__class__.__name__`, L233/240/320/451) como en el consumo posterior de `eval/threshold_sensitivity.py` (`triggered.isin(["TokenLimit", "Regex"])`, línea 96) — el código de simulación post-hoc espera exactamente esos literales, confirmando que son estables y no un artefacto transitorio.

---

## 5. Conteo de controles verificables hasta N3

Fuente: `controles_llmsec.csv` (columna `Fuente_Evidencia` ∈ {Configuración, Experimental}, `Nivel` ∈ {N1,N2,N3}) cruzado con las tablas de determinación de nivel en `docs/IMPLEMENTED.md`.

**Controles únicos (26):**
C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15, C16, C17, C18, C19, C20, C21, C23, C25, C31, C32, C62

Esta cifra **coincide exactamente** con la afirmación de la tesis ("26 controles únicos").

**Aplicaciones por subdimensión** (según las tablas "Determinación del nivel verificado" de `IMPLEMENTED.md`, que son las que efectivamente se usan para calcular el nivel de cada D):

| Subdimensión | N1 | N2 | N3 | Total aplicaciones |
|---|---|---|---|---|
| D1 | C1, C2, C6, C13, C15, C16, C21 (7) | C3, C4, C5 (3) | C31, C32 (2) | **12** |
| D2 | C6, C7, C10, C13, C15, C16, C21 (7) | C8, C9, C11, C14, C17 (5) | C12, C62 (2) | **14** |
| D3 | C16 (1) | C17, C18, C19 (3) | C20 (1) | **5** |
| D4 | — | — | C23, C25 (2) | **2** |
| **Total** | | | | **33** |

**Origen exacto de la ambigüedad "33-34" de la tesis:** `controles_llmsec.csv` asigna a **C17** una única subdimensión (`D3`), mientras que `docs/IMPLEMENTED.md` y la definición canónica del marco entregada en este encargo ("C17 (D2/D3-N2, ...)") lo asignan a **dos** (`D2` y `D3`). De forma simétrica, `controles_llmsec.csv` asigna a **C14** dos subdimensiones (`D2,D3`) mientras que `IMPLEMENTED.md` y la definición canónica del marco lo asignan solo a `D2`. Estas dos discrepancias se cancelan en el conteo actual de `IMPLEMENTED.md` (C17 cuenta doble, C14 cuenta simple → total 33), pero si se aplicara la asignación de `controles_llmsec.csv` de forma estricta para ambos controles simultáneamente (C17 simple, C14 doble), el total sería 34. **Es exactamente esta discrepancia entre las dos fuentes de verdad documental (`controles_llmsec.csv` vs. las tablas de `IMPLEMENTED.md`/marco canónico) la que produce el rango "33-34" que reporta la tesis** — no es una imprecisión arbitraria, tiene una causa rastreable y puntual: la asignación de subdimensión de C14/C17 no está fijada de forma unívoca en la documentación del propio marco.

---

## 6. Discrepancias que invalidan o matizan afirmaciones de la tesis

1. **(Bloqueante) τ_in = 0.75 reportado como "punto operativo desplegado".** Ver §3. El valor real que generó los datos experimentales fue 0.92. Esto no invalida los datos del experimento en sí (fueron generados con un umbral consistente y documentable: 0.92), pero sí invalida cualquier narrativa en la tesis que describa el comportamiento del sistema, la sensibilidad, o el trade-off TFA/FPR **asumiendo que el punto activo era 0.75**.

2. **(Menor, no solicitada pero relevante) `C17_GROUNDING_THRESHOLD` para `academic_institutional`.** `CLAUDE.md` (dentro de este mismo repositorio, sección "Calibrated Thresholds") documenta el valor como `0.0714`. El valor real en `.env.academic_institutional` es `0.0625`. El valor para `regulatory_technical` (`0.0556`) sí coincide. Como `CLAUDE.md` se autodescribe como "fixed experimental evidence... do not overwrite", esta discrepancia entre la documentación operativa del repo y el `.env` real usado en runtime debería resolverse — no se puede asumir cuál de los dos es el valor que efectivamente corrió sin más contexto, pero el `.env` es la fuente que el sistema realmente lee en runtime (`rag.py` línea 146: `os.getenv("C17_GROUNDING_THRESHOLD", "0.05")`), por lo que **0.0625 es el valor autoritativo**, no 0.0714.

3. **(Menor) `n_results`/`k` hardcodeado, no proviene de `rag.json`.** `rag.py:generate()` línea 515 llama `retrieve_context(query.prompt, k=3)` con `k=3` como literal en el código, no leído de `app/config/domains/<tag>/rag.json`. `IMPLEMENTED.md` describe C7/C10/C13 correctamente citando `retrieve_context()` sin afirmar que el valor viene de `rag.json`, así que no hay discrepancia con `IMPLEMENTED.md`; pero `CLAUDE.md` sí sugiere en su tabla de "Key Configuration Files" que `rag.json` controla `n_results` (`"Domain RAG config (collection_name, system_role, restrictions, n_results, domain_keywords)"`), cuando en realidad ninguno de los dos `rag.json` inspeccionados (`regulatory_technical`, `academic_institutional`) contiene las claves `n_results` ni `domain_keywords` — solo `collection_name`, `system_role`, `restrictions`, `ollama_host`, `model_name`. Esto es una discrepancia entre `CLAUDE.md` y el código/config real, no una falla de `IMPLEMENTED.md`.

4. **(No es discrepancia, confirmación) C24.** La tesis y `IMPLEMENTED.md` coinciden en que no está implementado. Confirmado por búsqueda exhaustiva de código.

5. **(No es discrepancia, confirmación) Nivel de C20 = N3.** Confirmado contra `controles_llmsec.csv`, `IMPLEMENTED.md` y la definición canónica del marco entregada en el encargo. No hay ambigüedad de N2 vs N3 en ningún documento ni en el código.

---

## 7. Recomendaciones

**Sobre la tesis (documento de tesis, no este repositorio):**
- Corregir toda afirmación de que τ_in = 0.75 fue el punto operativo desplegado. El valor correcto, respaldado por código y por los datos crudos del experimento, es τ_in = 0.92. Si existe una versión del análisis de sensibilidad que reporta resultados "en el punto activo", debe revisarse cuál punto se usó realmente para generar cada tabla/gráfico, porque el YAML que alimenta ese script (`threshold_sensitivity.py`) etiquetaba como "activo" un punto (0.75) que nunca bloqueó tráfico real.
- Revisar si algún gráfico o tabla de sensibilidad fue generado usando `eval/threshold_sensitivity.py` con el YAML en su estado del 7 de julio (`active_threshold_index: 3` → 0.75 marcado "activo"); si es así, la etiqueta "active" en `sensitivity_summary.csv` está mal puesta y debe corregirse a τ_in=0.92 antes de reportar cualquier conclusión basada en esa columna `notes`.

**Sobre `app/config/global/llm_guard_config.yaml` (código/config de este repositorio):**
- El comentario `# active threshold (default, index 1)` junto a `threshold: 0.92` (línea 20) está obsoleto desde el commit del 3 de julio; ya no hay relación entre ese comentario y `active_threshold_index`. Corregirlo o eliminarlo para evitar que se repita esta confusión.
- Considerar que `sensitivity_analysis.active_threshold_index` sea derivado automáticamente (o al menos validado) contra `input_scanners.prompt_injection.threshold` / `output_scanners.sensitive.threshold`, en vez de mantenerse como dos fuentes de verdad independientes que pueden divergir silenciosamente, como ocurrió aquí.

**Sobre `CLAUDE.md` (este repositorio):**
- Corregir `C17_GROUNDING_THRESHOLD` de `academic_institutional` en la tabla "Calibrated Thresholds": de `0.0714` a `0.0625` (valor real en `.env.academic_institutional`).
- Corregir la descripción de `app/config/domains/<tag>/rag.json` en la tabla "Key Configuration Files": eliminar `n_results` y `domain_keywords` de la lista de claves, ya que no existen en ninguno de los dos archivos `rag.json` del repositorio; `n_results`/`k` está hardcodeado en `rag.py:generate()`.

**Sobre `docs/IMPLEMENTED.md`:**
- No requiere correcciones sustantivas de fondo detectadas en esta auditoría — es la fuente documental más alineada con el código de las tres revisadas (código, `CLAUDE.md`, tesis).
- Considerar anotar explícitamente, en la fila de C17 (y opcionalmente C14), que la asignación de subdimensión difiere entre `controles_llmsec.csv` (fuente de datos tabular) y las tablas D2/D3 de este mismo documento, para que el rango "33-34 aplicaciones" de la tesis tenga una nota de trazabilidad en vez de quedar como una cifra sin explicación aparente.

**Sobre `controles_llmsec.csv`:**
- Es un CSV de una sola columna `Subdimension` por control; no puede representar de forma nativa que C17 pertenece a dos subdimensiones sin la notación `"D2,D3"` que sí usa para C6/C13/C14/C15/C16/C21. Alinear la fila de C17 (actualmente `D3` solamente) con la definición canónica del marco (`D2/D3`) usada tanto por `IMPLEMENTED.md` como por el enunciado de este encargo, y revisar si C14 debería ser `D2` solamente (como dice el marco canónico) en vez de `D2,D3` (como dice hoy el CSV).
