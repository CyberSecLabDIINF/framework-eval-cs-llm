# Controles del marco LLM-Sec implementados en el código

Este documento es el **instrumento de evaluación** del marco LLM-Sec
(C1...C62) aplicado a este laboratorio. A diferencia de un inventario, su
propósito es permitir determinar, para cada subdimensión (D1-D4), el **nivel
verificado** alcanzado por la implementación del laboratorio (Escenario B,
protegido), y el **nivel global** del sistema.

## Cómo usar este documento

1. **Una sección por subdimensión (D1-D5).** Cada sección contiene la tabla
   completa de controles que el marco asigna a esa subdimensión, con su
   `Nivel` (N1-N5), `Tipo` (Prev = Preventivo, Det = Detectivo, Cor =
   Correctivo, Gov = Gobernanza/organizacional, o combinaciones), `Evidencia`
   esperada según el marco (Configuración / Experimental / Declarativo),
   `Descripción`, `Fuente` normativa/framework, el `Estado en laboratorio` y
   el `Artefacto / Ubicación` concreto en este repositorio.
   - Un control que el marco asigna a más de una subdimensión (p. ej. C6,
     C13, C14, C15, C16, C17, C21) aparece **en cada tabla aplicable**, con
     los valores de `Nivel`/`Tipo`/`Evidencia` que el marco define para esa
     subdimensión específica (la `Fuente` puede variar entre apariciones).
2. **`Estado en laboratorio`** usa exactamente uno de estos cuatro valores:
   - `✅ Verificado — Configuración`: el control existe como artefacto de
     configuración o como estructura de código inspeccionable directamente
     (sin necesidad de ejecutar el experimento).
   - `✅ Verificado — Experimental`: el control está implementado en código y
     su efecto solo puede confirmarse ejecutando el experimento (ataques
     Garak / consultas de control).
   - `⚠️ Declarativo — auditoría documental`: el control, según el marco, es
     de naturaleza declarativa/organizacional y **no puede verificarse en
     código**; su cumplimiento se determina mediante auditoría documental o
     revisión de políticas/procesos.
   - `🔲 Fuera de alcance experimental`: el marco espera evidencia de
     `Configuración` o `Experimental` para este control, pero en esta
     revisión no se identificó un artefacto correspondiente en el
     repositorio; queda explícitamente fuera del alcance de este laboratorio.
3. **Sección "Determinación del nivel verificado"** aplica, para cada
   subdimensión D1-D4 y cada nivel `Nx`, la siguiente regla sobre el
   subconjunto de controles de ese nivel con `Evidencia` ∈
   {Configuración, Experimental} (los controles `Evidencia = Declarativo`
   se excluyen del cálculo y se verifican aparte, por auditoría documental,
   junto con D5):
   - (a) al menos un control Configuración/Experimental de nivel `Nx` tiene
     `Estado en laboratorio` = `✅ Verificado`; y
   - (b) ningún control Configuración/Experimental de nivel `≤ Nx` tiene
     `Estado en laboratorio` = `🔲 Fuera de alcance experimental`.

   El **nivel verificado en laboratorio** de la subdimensión es el `Nx` más
   alto que cumple (a) y (b). Los niveles cuyo subconjunto
   Configuración/Experimental es vacío (solo controles `⚠️`) no aportan ni
   bloquean por sí mismos: se evalúan exclusivamente por auditoría
   documental.
4. **Sección "Regla de piso mínimo"** combina los cuatro resultados anteriores
   en el nivel global del sistema.
5. **D5 (Gobernanza organizacional)** es **exclusivamente declarativa**: sus
   15 controles se verifican únicamente mediante auditoría documental y no
   participan de la regla de piso mínimo (que se calcula solo sobre D1-D4).

> **Nota sobre completitud:** las filas marcadas con
> `_Pendiente (Tablas 3.28-3.34)_` en la columna `Descripción`
> corresponden a controles para los que no se identificó un artefacto de
> código/configuración propio en este repositorio durante esta revisión. Su
> `Nivel`/`Tipo`/`Evidencia`/`Fuente`/subdimensión provienen del marco teórico
> de la tesis (Tablas 3.28-3.34) y deben completarse con la definición
> canónica para cerrar el instrumento.

---

## D1 — Protección de entrada (LLM01:2025)

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C1 | N1 | Prev | Configuración | Limita la longitud del prompt de entrada (en tokens) para mitigar payloads de inyección o desbordamiento antes de llegar al modelo. | LLM01:2025 | ✅ Verificado — Configuración | `app/config/global/llm_guard_config.yaml` → `input_scanners.token_limit` (`limit: 512`, `encoding_name: cl100k_base`) |
| C2 | N1 | Cor | Experimental | Elimina tokens especiales del modelo, bytes nulos y caracteres de control Unicode del texto de entrada antes de escanearlo. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `_sanitize_control_chars()` |
| C6 | N1 | Prev | Configuración | Estructura el prompt con delimitadores explícitos `Context:`/`Question:`, separando el contenido recuperado de la consulta del usuario. | LLM01:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()` (plantilla de prompt) |
| C13 | N1 | Prev | Configuración | Limita el volumen total de contexto inyectado en el prompt al restringir la recuperación a `k` fragmentos. | LLM01:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C15 | N1 | Prev | Configuración | Inyecta instrucciones de rol de sistema y restricciones configuradas externamente (`system_role`/`restrictions`) en cada prompt. | LLM01:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()`; `app/config/domains/*/rag.json` |
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de seguridad de entrada del componente generador. | LLM01:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C21 | N1 | Prev | Configuración | Externaliza toda la configuración de tiempo de ejecución (hosts, escenario, umbrales, rutas) como variables de entorno declaradas en la definición de cada servicio, sin valores hardcodeados en el código fuente. | LLM01:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → bloques `environment:` de `rag_api` / `shield_api` |
| C3 | N2 | Prev | Experimental | Bloquea prompts de entrada clasificados como intentos de inyección de instrucciones mediante el scanner PromptInjection. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_input()` (scanner `PromptInjection`, `threshold: 0.92`) |
| C4 | N2 | Prev | Experimental | Bloquea consultas cuya distancia semántica mínima al corpus supera el umbral configurado, rechazando preguntas fuera de dominio. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_on_domain()` / `DOMAIN_DISTANCE_THRESHOLD` |
| C5 | N2 | Det | Experimental | Solo el texto generado por el modelo se extrae y retorna al cliente; el system prompt (rol/restricciones) nunca se incluye en la respuesta. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `generate()` (`out = response.get("response", "")`) |
| C31 | N3 | Det | Experimental | Registra un motivo de bloqueo estructurado (`input_<scanner>`/`output_<scanner>`) para cada solicitud bloqueada. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/eval/consolidator.py`; `app/src/api/shield.py` → `log_request()` (`block_reason`) |
| C32 | N3 | Prev | Configuración | Verifica mediante hash SHA-256 que el system prompt y las restricciones no hayan sido modificados desde el arranque. | LLM01:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `validate_system_prompt_integrity()` |
| C33 | N4 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C34 | N4 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C35 | N5 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C36 | N5 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D2 — Control de contexto RAG (LLM02:2025)

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C6 | N1 | Prev | Configuración | Estructura el prompt con delimitadores explícitos `Context:`/`Question:`, separando el contenido recuperado de la consulta del usuario. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()` (plantilla de prompt) |
| C7 | N1 | Prev | Configuración | Define mediante una instrucción de sistema externa (`restrictions`) la regla de uso exclusivo del contexto recuperado, prohibiendo inventar información no presente en él. | LLM02:2025 | ✅ Verificado — Configuración | `app/config/domains/*/rag.json` → `restrictions` |
| C10 | N1 | Prev | Configuración | Limita la cantidad de fragmentos recuperados mediante el parámetro `n_results` (`k`) pasado a ChromaDB. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C13 | N1 | Prev | Configuración | Limita el volumen total de contexto inyectado en el prompt al restringir la recuperación a `k` fragmentos. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C15 | N1 | Prev | Configuración | Inyecta instrucciones de rol de sistema y restricciones configuradas externamente (`system_role`/`restrictions`) en cada prompt. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()`; `app/config/domains/*/rag.json` |
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de contexto del componente generador. | LLM02:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C21 | N1 | Prev | Configuración | Externaliza toda la configuración de tiempo de ejecución (hosts, escenario, umbrales, rutas) como variables de entorno declaradas en la definición de cada servicio, sin valores hardcodeados en el código fuente. | LLM02:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → bloques `environment:` de `rag_api` / `shield_api` |
| C30 | N1 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C8 | N2 | Prev | Configuración | Clasifica cada fragmento del corpus según su nivel de sensibilidad al ingestarlo (`_classify_sensitivity()`) y restringe la recuperación a los niveles permitidos según el escenario mediante `where_filter`/`ALLOWED_SENSITIVITY` en `retrieve_context()`. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/ingestion/generic_dir.py` → `_classify_sensitivity()`; `app/src/api/rag.py` → `retrieve_context()` |
| C9 | N2 | Prev/Det | Experimental | Verifica los hashes de los fragmentos recuperados contra una línea base (`CORPUS_HASHES`) antes de inyectarlos al contexto del LLM. | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `validate_corpus_integrity()` |
| C11 | N2 | Prev | Experimental | Bloquea consultas cuya distancia semántica mínima a cualquier fragmento del corpus supera el umbral de coherencia (`QUERY_COHERENCE_THRESHOLD`), rechazando queries incoherentes o codificadas. | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_coherent_query()` |
| C14 | N2 | Cor | Experimental | Excluye los metadatos de los documentos en la recuperación, de modo que solo el texto y los IDs de fragmento llegan al contexto del LLM. | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `retrieve_context()` (`include=["documents","ids"]`) |
| C17 | N2 | Prev/Det | Experimental | Bloquea respuestas cuyo solapamiento de tokens con el contexto recuperado cae por debajo del umbral de "grounding" (`C17_GROUNDING_THRESHOLD`). | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_grounded_response()` |
| C22 | N2 | Prev/Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C12 | N3 | Det | Experimental | Detecta y bloquea consultas indicativas de reconocimiento o enumeración sistemática del corpus. | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_safe_from_reconnaissance()` |
| C62 | N3 | Det | Configuración | Registra cada evento de ingesta del corpus (hash, cantidad de documentos, acción) en un registro de versiones persistente (CSV). | LLM02:2025 | ✅ Verificado — Configuración | `app/src/cli.py` → `_record_corpus_version()` |
| C37 | N4 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C38 | N4 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C39 | N5 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C40 | N5 | Prev | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D3 — Gestión de salida (LLM07:2025)

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de salida del componente generador. | LLM07:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C14 | N2 | Cor | Experimental | Excluye los metadatos de los documentos en la recuperación, de modo que solo el texto y los IDs de fragmento llegan al contexto del LLM. | LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `retrieve_context()` (`include=["documents","ids"]`) |
| C17 | N2 | Prev/Det | Experimental | Bloquea respuestas cuyo solapamiento de tokens con el contexto recuperado cae por debajo del umbral de "grounding" (`C17_GROUNDING_THRESHOLD`). | LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_grounded_response()` |
| C18 | N2 | Cor | Experimental | Elimina caracteres de control y tokens especiales de la salida del modelo antes de escanearla y retornarla. | LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (`_sanitize_control_chars(text)`) |
| C19 | N2 | Det/Cor | Experimental | Bloquea respuestas que coincidan con patrones regex deterministas (marcador `[CONFIDENTIAL]`, RUT chileno, email, teléfono, contraseña, tarjeta de crédito). | LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (scanner `OutputRegex`); `app/config/global/llm_guard_config.yaml` → `output_scanners.regex` |
| C20 | N3 | Det | Experimental | Puntúa y/o bloquea respuestas que contienen información sensible mediante el scanner semántico Sensitive (score continuo, participa del análisis de sensibilidad). | LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (scanner `Sensitive`); `app/config/global/llm_guard_config.yaml` → `output_scanners.sensitive` |
| C41 | N4 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C42 | N4 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C43 | N5 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C44 | N5 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D4 — Monitoreo y trazabilidad (LLM08:2025)

> Por diseño, el marco no asigna controles de **N1** a esta subdimensión (ver
> "Regla de piso mínimo").

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C26 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C27 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C28 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C23 | N3 | Det | Experimental | Registra en el CSV consolidado el nombre del scanner que originó el bloqueo de cada solicitud. | LLM08:2025 | ✅ Verificado — Experimental | `app/src/eval/consolidator.py`; `app/src/api/shield.py` → `log_request()` (`scanner_triggered`) |
| C25 | N3 | Det | Experimental | Registra latencia y metadatos de cada solicitud en un CSV para análisis post-experimento. | LLM08:2025 | ✅ Verificado — Experimental | `app/src/api/middleware.py` → `LatencyCSVLogger` |
| C29 | N3 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C24 | N4 | Det | Experimental | _Pendiente (Tablas 3.28-3.34)_ | LLM08:2025 | 🔲 Fuera de alcance experimental | — |
| C45 | N5 | Det | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |
| C46 | N5 | Cor | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D5 — Gobernanza organizacional

> Subdimensión **exclusivamente declarativa**: los 15 controles se verifican
> mediante auditoría documental (políticas, procesos, marcos regulatorios) y
> no participan de la "Regla de piso mínimo".

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C47 | N1 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C48 | N1 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C49 | N1 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C61 | N1 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C50 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C51 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C52 | N2 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C53 | N3 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C54 | N3 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C55 | N3 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C60 | N3 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C56 | N4 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C57 | N4 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C58 | N5 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C59 | N5 | Gov | Declarativo | _Pendiente (Tablas 3.28-3.34)_ | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |

---

## Determinación del nivel verificado

Para cada subdimensión D1-D4 se aplica la regla del punto 3 (ver "Cómo usar
este documento"): para cada nivel `Nx`, se considera únicamente el
subconjunto de controles de ese nivel con `Evidencia` ∈
{Configuración, Experimental}. Un nivel `Nx` está **verificado en
laboratorio** si (a) al menos uno de esos controles tiene
`Estado en laboratorio` = `✅ Verificado`, y (b) ningún control
Configuración/Experimental de nivel `≤ Nx` está `🔲 Fuera de alcance
experimental`. El nivel verificado de la subdimensión es el `Nx` más alto que
cumple ambas condiciones. Los controles `⚠️ Declarativo` se excluyen del
cálculo (su nivel se evalúa por auditoría documental, junto con D5) y no
bloquean ni habilitan por sí mismos un nivel.

> **Advertencia de completitud:** el único control `🔲 Fuera de alcance
> experimental` que permanece en el instrumento es **C24** (D4-N4), para el
> que esta revisión no encontró un artefacto en el repositorio. Si
> corresponde a una funcionalidad ya implementada bajo otro nombre o
> ubicación, debe reclasificarse a `✅ Verificado` en la tabla
> correspondiente **antes** de tomar como definitivo el resultado de D4.

### D1 — Protección de entrada

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C1, C2, C6, C13, C15, C16, C21 | — | Todos ✅ | **Sí** |
| N2 | C3, C4, C5 | — | Todos ✅ | **Sí** |
| N3 | C31, C32 | — | Todos ✅ | **Sí** |
| N4 | — | C33, C34 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C35, C36 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D1 (Escenario B): N3** — N1, N2 y N3 cumplen (a) y (b); N4 y
N5 no tienen controles de evidencia Configuración/Experimental y se evalúan
por auditoría documental.

### D2 — Control de contexto RAG

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C6, C7, C10, C13, C15, C16, C21 | C30 | Todos ✅ (C30 excluido) | **Sí** |
| N2 | C8, C9, C11, C14, C17 | C22 | Todos ✅ (C22 excluido) | **Sí** |
| N3 | C12, C62 | — | Todos ✅ | **Sí** |
| N4 | — | C37, C38 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C39, C40 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D2 (Escenario B): N3** — N1, N2 y N3 cumplen (a) y (b)
(C30 y C22 son `⚠️ Declarativo` y se excluyen del cálculo); N4 y N5 no tienen
controles de evidencia Configuración/Experimental y se evalúan por auditoría
documental.

### D3 — Gestión de salida

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C16 | — | ✅ | **Sí** |
| N2 | C14, C17, C18, C19 | — | Todos ✅ | **Sí** |
| N3 | C20 | — | ✅ | **Sí** |
| N4 | — | C41, C42 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C43, C44 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D3 (Escenario B): N3** — N1, N2 y N3 cumplen (a) y (b); N4 y
N5 no tienen controles de evidencia Configuración/Experimental y se evalúan
por auditoría documental.

### D4 — Monitoreo y trazabilidad

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | *(sin controles asignados por diseño)* | — | — | No aplica |
| N2 | — | C26, C27, C28 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N3 | C23, C25 | C29 | Todos ✅ (C29 excluido) | **Sí** |
| N4 | C24 | — | 🔲 sin verificar | **No** |
| N5 | — | C45, C46 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D4 (Escenario B): N3** — N3 cumple (a) y (b): C23 y C25
están `✅ Verificado — Experimental` (C29 es `⚠️ Declarativo` y se excluye), y
ningún control Configuración/Experimental de nivel ≤N3 está `🔲`. N1 no tiene
controles asignados por diseño del marco; N2 solo tiene controles
Declarativos (C26-C28) y se evalúa por auditoría documental. N4 no cumple (a)
ni (b) por C24 (`🔲`), lo cual es irrelevante para el nivel verificado de D4
porque N3 ya es el nivel máximo alcanzado y N4 no está por debajo de él.

---

## Regla de piso mínimo

El **nivel verificado global** del sistema corresponde al **mínimo** entre los
niveles verificados de D1-D4 (D5, exclusivamente declarativa, no participa de
esta regla).

### Escenario B (protegido)

```
Nivel global = min( Nivel(D1), Nivel(D2), Nivel(D3), Nivel(D4) )
              = min( N3, N3, N3, N3 )
              = N3
```

**Escenario B (protegido): N3.**

### Escenario A (no protegido)

**Escenario A: N0**, por diseño del marco: **D4 no tiene controles asignados
de nivel N1** (ver tabla D4 — su nivel mínimo asignado es N2). Cualquier
exigencia de piso que requiera un N1 verificado de forma transversal a
D1-D4 nunca puede ser satisfecha por D4, por lo que el piso mínimo de
Escenario A queda en **N0** con independencia de los resultados de D1-D3.

De forma adicional y consistente con esta conclusión: en Escenario A
(`IS_PROTECTED=False`, `SCENARIO=unprotected`) el componente Shield/LLM Guard
no se interpone en el flujo de la solicitud, por lo que los scanners de
entrada/salida que dependen de él (C2, C3, C18, C19, C20) y los controles de
defensa en profundidad del RAG habilitados solo en la configuración protegida
(C4, C8, C9, C11, C12, C17) no pueden contar como `✅ Verificado` — ampliando
el conjunto de controles no verificados de D1-D3 respecto del Escenario B,
sin alterar la conclusión N0 ya determinada por D4.

Por lo tanto, el nivel global del sistema bajo el marco LLM-Sec completo (62
controles) es **N3 para Escenario B** y **N0 para Escenario A**, sujeto a la
advertencia de completitud señalada en la sección anterior (C24, D4-N4).
