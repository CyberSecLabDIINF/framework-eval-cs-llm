# Informe de auditoría de controles LLM-Sec

Este informe documenta el resultado de la auditoría de `docs/IMPLEMENTED.md`
y `docs/ARCHITECTURE.md` contra la fuente de verdad del marco LLM-Sec
(Apéndice A, resumen de controles por nivel, y Apéndice C, fichas técnicas
de control), y contra el estado real del código del repositorio. No
modifica código ni configuración; es exclusivamente un artefacto de
documentación.

---

## 1. Tabla de los 26 controles `✅ Verificado`

Cuatro columnas: valor según el marco (Apéndice A/C), valor que tenía
`docs/IMPLEMENTED.md` antes de esta auditoría, resultado de la verificación
directa contra el código de este repositorio, y la referencia cruzada de la
Tabla G.1/G.2/G.3 de la tesis aportada por el usuario. Cuando el usuario no
aportó una fila G.1-G.3 para un control, la celda se marca explícitamente
como no provista.

### N1

| Control | Marco (Nivel/Tipo/Evidencia) | IMPLEMENTED.md antes de la auditoría | Código verificado | Tabla G.1/G.2/G.3 (tesis) |
|---|---|---|---|---|
| C1 | N1, Preventivo, Configuración | Igual (Fuente completa) | Confirmado: `app/config/global/llm_guard_config.yaml` → `input_scanners.token_limit.limit: 512`, `encoding_name: cl100k_base` | Config, `llm_guard_config.yaml`, `token_limit.limit=512` |
| C2 | N1, Correctivo, Experimental | Igual (Fuente completa) | Confirmado: `_sanitize_control_chars()` en `app/src/api/shield.py`, invocada sin condicional dentro de `guard_input()`. Pero solo se ejecuta si la solicitud pasa por `shield_api`; en Escenario A, Garak ataca `rag_api` directamente y `shield_api` nunca se invoca, por lo que C2 no opera en Escenario A pese a ser N1 (ver hallazgo 4.2) | Experimental, `shield.py`, `_sanitize_control_chars()` |
| C6 | N1, Preventivo, Configuración | Fuente incompleta (`LLM01:2025` únicamente en la tabla D1; corregida a `LLM01:2025, LLM02:2025`) | Confirmado: plantilla `Context:`/`Question:` en `generate()` de `app/src/api/rag.py` | Config, `rag.py`, plantilla `Context:`/`Question:` en `generate()` |
| C7 | N1, Preventivo, Configuración | Igual (Fuente completa) | Confirmado: campo `restrictions` en `app/config/domains/<tag>/rag.json` | Config, `rag.json`, campo `restrictions` |
| C10 | N1, Preventivo, Configuración | Igual (Fuente completa) | Confirmado: `retrieve_context(query, k=3)` en `rag.py`, `n_results=k` pasado a ChromaDB | Config, `rag.py`, `n_results=3` |
| C13 | N1, Preventivo, Configuración | Fuente incompleta en D1 y D2 (corregida a `LLM01:2025, LLM02:2025` en ambas) | Confirmado: mismo mecanismo que C10 (`k`/`n_results`) | Config, `rag.py`, `n_results=3` |
| C15 | N1, Preventivo, Configuración | Fuente incompleta en D1 y D2 (corregida) | Confirmado: `SYSTEM_ROLE`/`RESTRICTIONS` de `rag.json` inyectados en `generate()` | Config, `rag.json`, `system_role` y `restrictions` |
| C16 | N1, Preventivo, Configuración | Fuente incompleta en las tres apariciones (D1 solo tenía dos fuentes; corregida a `LLM01:2025, LLM02:2025, LLM07:2025` en D1/D2/D3) | Confirmado: `docker-compose.yml` define `shield_api` (contenedor `tesis_shield`) como servicio independiente que hace de proxy hacia `rag_api`; LLM Guard es una librería Python importada dentro de `shield_api`, no un servicio propio | Config, `docker-compose.yml`, `shield_api` como proxy independiente |
| C21 | N1, Preventivo, Configuración | Fuente incompleta en D1 y D2 (corregida) | Confirmado: bloques `environment:` de `rag_api`/`shield_api` en `docker-compose.yml`, sin valores hardcodeados en el código fuente | Config, `docker-compose.yml`, variables de entorno sin hardcode |

### N2

| Control | Marco (Nivel/Tipo/Evidencia) | IMPLEMENTED.md antes de la auditoría | Código verificado | Tabla G.1/G.2/G.3 (tesis) |
|---|---|---|---|---|
| C3 | N2, Preventivo, Experimental | Igual (Fuente completa) | Confirmado: scanner `PromptInjection` (`threshold: 0.92`) en `guard_input()` de `shield.py` | Exp, `shield.py`, `PromptInjection` en `guard_input()` |
| C4 | N2, Preventivo, Experimental | Igual (Fuente completa) | Confirmado: `is_on_domain()`/`DOMAIN_DISTANCE_THRESHOLD` en `rag.py`, pero gateado por `if IS_PROTECTED:`, que evalúa `False` de forma permanente bajo el `docker-compose.yml` actual (ver hallazgo 4.1) | Exp, `rag.py`, `is_on_domain()` con `DOMAIN_DISTANCE_THRESHOLD` |
| C5 | N2, Detectivo, Experimental | Fuente incompleta (`LLM01:2025` únicamente; corregida a `LLM01:2025, LLM07:2025`) | Confirmado: `generate()` en `rag.py` solo extrae `response.get("response", "")`, nunca `SYSTEM_ROLE`/`RESTRICTIONS` | Exp, `rag.py`, `generate()` sin exponer system prompt |
| C8 | N2, Preventivo, Configuración | Fuente incompleta (corregida a `LLM02:2025, LLM08:2025`) | Confirmado en dos partes: (1) `_classify_sensitivity()` en `app/src/ingestion/generic_dir.py` etiqueta cada fragmento al ingestarlo, de forma incondicional (independiente de escenario); (2) el `where_filter` que restringe la recuperación según `ALLOWED_SENSITIVITY` en `retrieve_context()` de `rag.py` está condicionado por `IS_PROTECTED`, que evalúa `False` de forma permanente bajo el `docker-compose.yml` actual (ver hallazgo 4.1). Se confirmó además que no quedan referencias a `ENABLE_LLM_GUARD`/`ENABLE_OUTPUT_GUARD` en ningún archivo del repositorio | Config, `generic_dir.py`/`_classify_sensitivity()` + `where_filter` |
| C9 | N2, Preventivo/Detectivo, Experimental | Fuente incompleta (corregida) | Confirmado: `validate_corpus_integrity()` en `rag.py` contra `CORPUS_HASHES`, gateado por `IS_PROTECTED` (ver hallazgo 4.1) | Exp, `rag.py`, `validate_corpus_integrity()` con `CORPUS_HASHES` SHA-256 |
| C11 | N2, Preventivo, Experimental | Fuente incompleta (corregida) | Confirmado: `is_coherent_query()`/`QUERY_COHERENCE_THRESHOLD` en `rag.py`, gateado por `IS_PROTECTED` (ver hallazgo 4.1) | Exp, `rag.py`, `is_coherent_query()` con `QUERY_COHERENCE_THRESHOLD` |
| C14 | N2, **Preventivo** (Apéndice A dice Correctivo; contradicción resuelta a favor de la ficha C.3.6), Experimental, exclusivo de D2 | **Corregido**: la tabla D2 tenía Tipo `Cor`, corregido a `Prev`; la fila duplicada en la tabla D3 (heredada de la inconsistencia de Apéndice A, que lista C14 en D2 y D3) fue eliminada, siguiendo el argumento explícito de la ficha C.3.6 | Confirmado: `retrieve_context()` en `rag.py` pasa `include=["documents","ids"]` a ChromaDB, excluyendo metadatos | Exp, `rag.py`, `include=["documents","ids"]` |
| C17 | N2, Preventivo/Detectivo, Experimental | Fuente incompleta en D2 y D3 (corregida a `LLM02:2025, LLM07:2025`) | Confirmado: `is_grounded_response()`/`C17_GROUNDING_THRESHOLD` en `rag.py`; la rama de bloqueo está gateada por `IS_PROTECTED` (ver hallazgo 4.1) | Exp, `rag.py`, `is_grounded_response()` con `C17_GROUNDING_THRESHOLD` |
| C18 | N2, Correctivo, Experimental | Fuente incompleta (corregida a `LLM01:2025, LLM07:2025`) | Confirmado: `_sanitize_control_chars()` reutilizada dentro de `guard_output()` en `shield.py` | Exp, `shield.py`, `_sanitize_control_chars()` en `guard_output()` |
| C19 | N2, Detectivo/Correctivo, Experimental | Fuente incompleta (corregida a `LLM02:2025, LLM07:2025`) | Confirmado: scanner `OutputRegex` en `guard_output()` de `shield.py`, patrones en `llm_guard_config.yaml` → `output_scanners.regex` | Exp, `shield.py`, `OutputRegex` en `guard_output()` |

### N3

| Control | Marco (Nivel/Tipo/Evidencia) | IMPLEMENTED.md antes de la auditoría | Código verificado | Tabla G.1/G.2/G.3 (tesis) |
|---|---|---|---|---|
| C12 | N3, Detectivo, Experimental | Fuente incompleta (corregida a `LLM02:2025, LLM08:2025`) | Confirmado: `is_safe_from_reconnaissance()` en `rag.py`, gateado por `IS_PROTECTED` (ver hallazgo 4.1) | No provista por el usuario |
| C20 | N3, Detectivo, Experimental | Fuente incompleta en D3 (corregida a `LLM02:2025, LLM07:2025`) | Confirmado: scanner semántico `Sensitive` en `guard_output()` de `shield.py`, umbral en `llm_guard_config.yaml` → `output_scanners.sensitive` | No provista por el usuario |
| C23 | N3, Detectivo, Experimental | Fuente incompleta (`LLM08:2025` únicamente; corregida a las cuatro suites `LLM01/02/07/08:2025`) | Confirmado parcialmente: `shield.py` → `log_request()` sí escribe `scanner_triggered` para bloqueos originados en Shield. `rag.py` → `_blocked_response()` no escribe `scanner_triggered` para bloqueos originados en el RAG (solo `block_reason`); es una brecha de completitud de código, actualmente sin efecto observable porque, bajo el hallazgo 4.1, esos bloqueos del RAG nunca ocurren en las corridas registradas (ver hallazgo 4.3) | No provista por el usuario |
| C25 | N3, Detectivo, Experimental | Fuente incompleta (corregida) | Confirmado: `LatencyCSVLogger` en `app/src/api/middleware.py`, registra un CSV por solicitud de forma incondicional | No provista por el usuario |
| C31 | N3, Detectivo, Experimental | Igual (Fuente completa) | Confirmado parcialmente: mismo hallazgo que C23. `shield.py` sí produce `block_reason` con el formato `input_<scanner>`/`output_<scanner>`; los `block_reason` que emite `rag.py` (p. ej. `domain_validation_failed`, `query_coherence_failed`) no siguen ese formato, aunque son igualmente estructurados y consistentes entre sí (ver hallazgo 4.3) | No provista por el usuario |
| C32 | N3, Preventivo, Configuración | Fuente incompleta (`LLM01:2025` únicamente; corregida a `LLM01:2025, LLM07:2025`) | Confirmado con matiz: `validate_system_prompt_integrity()` en `rag.py` compara un hash SHA-256 calculado una vez al cargar el módulo (`SYSTEM_PROMPT_HASH`) contra un hash recalculado en cada solicitud a partir de las mismas variables en memoria (`SYSTEM_ROLE`/`RESTRICTIONS`). El valor de referencia reside en el proceso (memoria), no en el mismo archivo que el prompt (`rag.json`), lo que satisface estrictamente el requisito de la ficha; sin embargo, el recargador `uvicorn --reload` recalcula ambos valores juntos ante cualquier cambio de configuración, debilitando la garantía de "no modificado desde el arranque" (ver hallazgo 4.4). Además, la verificación está gateada por `IS_PROTECTED` (ver hallazgo 4.1) | No provista por el usuario |
| C62 | N3, Detectivo, Configuración | Fuente incompleta (corregida a `LLM02:2025, LLM08:2025`) | Confirmado: `_record_corpus_version()` en `app/src/cli.py` escribe `artifacts/corpus_version_registry.csv`, independiente de ChromaDB y persistente entre ejecuciones | No provista por el usuario |

---

## 2. Discrepancias corregidas en esta auditoría

1. **Contradicciones Apéndice A vs ficha Apéndice C (Tipo).** El marco es
   internamente inconsistente en cuatro controles; `IMPLEMENTED.md` ya
   adoptaba, antes de esta auditoría, el valor de la ficha C en tres de
   ellos y fue corregido en el cuarto durante esta revisión:
   - **C02**: Apéndice A = Preventivo, ficha C.2.2 = Correctivo. Ya
     resuelto a favor de la ficha C antes de esta auditoría (conocido de
     antemano por el usuario).
   - **C03**: Apéndice A = Detectivo, ficha C.2.3 = Preventivo. Ya resuelto
     a favor de la ficha C antes de esta auditoría.
   - **C05**: Apéndice A = Preventivo, ficha C.2.5 = Detectivo. Ya resuelto
     a favor de la ficha C antes de esta auditoría.
   - **C14**: Apéndice A = Correctivo (en las tablas de D2 y D3), ficha
     C.3.6 = Preventivo, exclusivo de D2 (la propia ficha argumenta
     explícitamente la reclasificación). **Corregido en esta auditoría**:
     Tipo cambiado de Correctivo a Preventivo en la tabla D2, y la fila
     duplicada de C14 en la tabla D3 fue eliminada.
2. **Descripciones `_Pendiente (Tablas 3.28-3.34)_`.** Reemplazadas en las
   61 filas restantes (todas salvo C24) por la descripción abreviada del
   Apéndice A del marco.
3. **Campo `Fuente` incompleto.** Se completó la lista de suites OWASP en
   28 filas donde `IMPLEMENTED.md` citaba solo un subconjunto de la Fuente
   canónica del control (incluye las tres correcciones adicionales
   encontradas al validar sistemáticamente la tabla completa contra el
   canon: C5, C16 en su aparición de D1, y C32).
4. **Regla de "nivel verificado".** La regla previa exigía que "al menos
   uno" de los controles Configuración/Experimental de un nivel estuviera
   `✅ Verificado`. Esto contradice el paso 4 de la guía de evaluación del
   marco (capítulo 6.1: *"el nivel de cada subdimensión es el mayor nivel
   cuyos controles están completamente implementados, respetando la
   progresión acumulativa"*). Corregida a exigir que **todos** los
   controles Configuración/Experimental de un nivel, y de todos los
   niveles inferiores de la subdimensión, estén `✅ Verificado`. Bajo la
   regla corregida, el resultado numérico **no cambia**: D1 = D2 = D3 = D4
   = **N3** para Escenario B, y **N0** para Escenario A (D4 no tiene
   controles de nivel N1 asignados por diseño del marco), porque en los
   datos actuales cada nivel de cada subdimensión es o bien completamente
   `✅ Verificado`, o bien vacío de controles Configuración/Experimental.
5. **Nota sobre completitud y cita de fuente canónica.** Reemplazada la
   cita de "Tablas 3.28-3.34 de la tesis" por Apéndice A + Apéndice C del
   marco LLM-Sec como fuente de verdad, incluyendo la regla de que, ante
   discrepancia de Tipo entre Apéndice A y una ficha C, prevalece la
   ficha C y la discrepancia se documenta en este informe.
6. **C24 (advertencia de completitud).** El bloque de advertencia que
   pedía reclasificar C24 "antes de tomar como definitivo" el resultado de
   D4 fue reemplazado por una nota de resolución: esta auditoría confirmó
   que no existe artefacto alguno en el repositorio que implemente C24,
   bajo ningún nombre o ubicación, por lo que C24 queda intencionalmente
   fuera del alcance experimental TRL4 y constituye la brecha prioritaria
   para el tránsito de N3 a N4, consistente con el plan de remediación de
   la tesis.
7. **`docs/ARCHITECTURE.md`.** El esquema de columnas documentado para el
   CSV consolidado (`eval/consolidator.py`) estaba desactualizado: listaba
   19 columnas y omitía `grounding_ratio`, `response_has_system_prompt`,
   `injection_followed` y `rogue_string_found`. Corregido a las 23 columnas
   reales de `COLUMNS` en el código. Se agregó también una sección breve
   sobre `llmsec.sh` como capa de orquestación (no documentada
   previamente) y dos scripts de `app/src/eval/` no documentados
   (`backfill_scenario_a.py`, `fix_scanner_scores.py`).

---

## 3. Discrepancias que no pueden corregirse desde este repositorio

Estas residen en el documento del marco o en la tesis; su corrección
excede el alcance de esta auditoría (solo documentación del repositorio) y
requieren una decisión del usuario sobre el texto fuente correspondiente.

1. **C14 y la lista de "controles transversales" del Apéndice C.1.** El
   Apéndice C.1 enumera explícitamente siete controles transversales (C06,
   C13, C15, C16, C17, C21, C30), sin incluir a C14. Sin embargo, el
   Apéndice A lista a C14 en las tablas de **dos** subdimensiones (D2 y
   D3), lo que lo vuelve de facto transversal según esa misma tabla. El
   marco es inconsistente en su propia definición de "transversal". Esta
   auditoría adoptó la posición de la ficha C.3.6 (C14 es exclusivo de D2,
   no transversal), pero la lista de siete controles del Apéndice C.1 y la
   tabla D3 del Apéndice A siguen sin conciliarse en el documento del
   marco. Requiere corrección en el documento del marco, no en este
   repositorio.
2. **C24 y la discrepancia entre Apéndice B y Apéndice C.** El Apéndice B
   (mapeo normativo) atribuye a C24 las cuatro suites LLM01/02/07/08:2025;
   la ficha C.5.7 solo declara LLM02:2025 y LLM08:2025 como Fuente. Esta
   auditoría documentó la discrepancia en la fila de C24 de
   `IMPLEMENTED.md`, pero no puede resolverla: requiere decidir cuál de
   los dos apéndices del marco es la fuente correcta, lo cual excede el
   alcance de una auditoría de documentación del repositorio.
3. **Alcance de la Tabla G.1/G.2/G.3 de la tesis.** El usuario aportó
   referencias cruzadas de la tesis para 19 de los 26 controles
   `✅ Verificado` (C1 a C21 en su mayoría). Para los 7 restantes (C12,
   C20, C23, C25, C31, C32, C62) no se proporcionaron datos de la tabla
   G.1/G.2/G.3, por lo que la columna correspondiente en la sección 1 se
   marca "No provista por el usuario". Si la tesis sí documenta estos
   controles en dichas tablas, esa comparación queda pendiente y debe
   hacerla el usuario directamente sobre el texto de la tesis.

---

## 4. Hallazgos críticos de código/configuración (fuera del alcance de "solo documentación")

Estos hallazgos no pueden resolverse editando `IMPLEMENTED.md` o
`ARCHITECTURE.md` porque requieren cambios en `docker-compose.yml` o en
código de `app/src/`, ambos fuera del alcance explícito de esta tarea. Se
reportan aquí para que el usuario decida cómo proceder; **no se modificó
ningún estado `✅ Verificado` a partir de estos hallazgos**, ya que
constituyen una decisión de alcance mayor que corresponde al equipo del
laboratorio, no a una auditoría de documentación.

### 4.1. `IS_PROTECTED` evalúa `False` de forma permanente en todas las corridas registradas

`docker-compose.yml` define el servicio `rag_api` con `SCENARIO=unprotected`
como valor literal, no interpolado, y esta es la única definición de
`rag_api` en el repositorio: se usa sin cambios tanto para Escenario A como
para Escenario B. `shield_api` (con `SCENARIO=protected`) siempre reenvía
sus solicitudes a ese mismo contenedor `rag_api`. El selector
`GARAK_TARGET`, consumido únicamente por `garak_runner`, decide si Garak
ataca `rag_api` directamente o a través de `shield_api`, pero nunca
modifica la variable `SCENARIO` del contenedor `rag_api`.

En consecuencia, `IS_PROTECTED = SCENARIO == "protected"` en
`app/src/api/rag.py` se evalúa como `False` de forma permanente, incluso
en corridas etiquetadas como Escenario B. Todos los bloques
`if IS_PROTECTED:` de `generate()` (que gatillan C32, C4, C11, C12, C9 y el
bloqueo de C17) y el `where_filter` de C8 en `retrieve_context()` quedan
sin ejecutar su rama de bloqueo/filtrado en ninguna corrida registrada.

**Confirmación empírica:** se analizaron los cuatro CSV consolidados en
`artifacts/` (`consolidated_*_protected.csv` y
`consolidated_*_unprotected.csv`) con `pandas`. El conteo de valores de
`block_reason` en los CSV protegidos muestra únicamente
`input_promptinjection`, `output_sensitive`, `input_tokenlimit` y
`output_regex` (los cuatro bloqueos que dependen de `shield_api`); no
aparece ninguna ocurrencia de `domain_validation_failed`,
`query_coherence_failed`, `corpus_reconnaissance_detected`,
`corpus_integrity_failed`, `response_not_grounded` ni
`system_prompt_integrity_failed` en ninguno de los cuatro archivos.

**Implicancia para los resultados reportados.** El nivel D2 = N3
(Escenario B) y el estado `✅ Verificado` de C4, C8, C9, C11, C12, C17 y
C32 certifican la existencia y correctitud del artefacto de código (que
esta auditoría confirmó), pero no su activación efectiva durante el
experimento. Cualquier cifra de la tesis que atribuya a estos seis
controles una reducción medida de la tasa de ataques exitosos (TFA) en
Escenario B debe reinterpretarse: esa reducción, si existe, no puede
provenir de estos controles bajo la configuración de despliegue actual.

### 4.2. C2 no opera en Escenario A pese a ser N1

`_sanitize_control_chars()` (C2) no tiene ningún condicional interno en
`shield.py`; se ejecuta siempre que una solicitud pasa por `guard_input()`.
Sin embargo, en Escenario A, Garak ataca `rag_api` directamente y
`shield_api` nunca se invoca, por lo que C2 (como C1, C3, C18, C19 y C20)
simplemente no se ejecuta en ese escenario. Esto contradice la premisa,
usada en varias partes del marco y de la tesis, de que "los controles N1
operan en ambos escenarios": para C2 específicamente, eso es falso, porque
su ejecución depende de qué endpoint recibe la solicitud, no de una
condición interna al control.

### 4.3. C23/C31: cobertura de logging incompleta en `rag.py`

`shield.py` escribe `scanner_triggered` y `block_reason` con el formato
`input_<scanner>`/`output_<scanner>` en cada bloqueo. `rag.py` solo escribe
`block_reason` (con nombres descriptivos propios, no el formato
`input_<scanner>`/`output_<scanner>`) y nunca escribe `scanner_triggered`
en sus propios bloqueos (`_blocked_response()`). Es una brecha real de
completitud de código respecto de C23/C31 tal como los describe el marco,
aunque, bajo el hallazgo 4.1, actualmente no tiene efecto observable porque
esos bloqueos del RAG no ocurren en ninguna corrida registrada.

### 4.4. C32: matiz sobre la ubicación del valor de referencia

La ficha de C32 exige que el hash de referencia no resida en el mismo
artefacto que el prompt. `validate_system_prompt_integrity()` en `rag.py`
compara un hash calculado una vez al cargar el módulo (`SYSTEM_PROMPT_HASH`,
en memoria del proceso) contra un hash recalculado en cada solicitud a
partir de las mismas variables en memoria. Esto satisface la letra del
requisito (la referencia no está en `rag.json`), pero `uvicorn --reload`
recalcula ambos valores juntos ante cualquier cambio de configuración del
servicio, lo que debilita la garantía de "no modificado desde el arranque"
frente a un atacante que lograra modificar la configuración en tiempo de
ejecución. Además, la verificación está gateada por `IS_PROTECTED` (hallazgo
4.1).

---

## 5. Resumen

- Todos los `Nivel`/`Tipo`/`Evidencia`/`Fuente`/subdimensión de
  `IMPLEMENTED.md` fueron auditados y corregidos contra la tabla canónica
  del marco (Apéndice A + Apéndice C); no quedan discrepancias pendientes
  de corrección dentro del alcance del repositorio.
- La regla de "nivel verificado" fue corregida a la progresión acumulativa
  que exige el marco. El resultado numérico no cambia: **N3** en las
  cuatro subdimensiones para Escenario B, **N0** para Escenario A.
- Los 26 controles `✅ Verificado` fueron confirmados contra el código; no
  se encontró ningún artefacto declarado que no existiera.
- C24 fue confirmado como no implementado y documentado como brecha
  intencional fuera de alcance TRL4, no como advertencia abierta.
- El hallazgo más significativo de esta auditoría es 4.1: bajo el
  `docker-compose.yml` actual, seis de los controles `✅ Verificado`
  (C4, C8, C9, C11, C12, C17) y C32 nunca ejecutan su lógica de
  bloqueo/filtrado en ninguna corrida experimental registrada, en ningún
  escenario. Esto no se corrigió porque excede el alcance de "solo
  documentación"; se documenta aquí para que el usuario decida cómo
  proceder (ajustar `docker-compose.yml` y volver a correr el experimento,
  o reinterpretar los resultados ya reportados en la tesis a la luz de esta
  limitación).
