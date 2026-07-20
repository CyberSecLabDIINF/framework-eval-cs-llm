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
   subdimensión D1-D4 y cada nivel `Nx`, la regla del paso 4 de la guía de
   evaluación del marco (capítulo 6.1): *"el nivel de cada subdimensión es
   el mayor nivel cuyos controles están completamente implementados,
   respetando la progresión acumulativa"*. Operacionalizada sobre el
   subconjunto de controles de evidencia `Configuración`/`Experimental`
   (los controles `Evidencia = Declarativo` se excluyen del cálculo y se
   verifican aparte, por auditoría documental, junto con D5):
   - Un nivel `Nx` está **verificado en laboratorio** si y solo si **TODOS**
     los controles Configuración/Experimental de nivel `Nx` **y** de todos
     los niveles inferiores (`N1..N(x-1)`) de la subdimensión tienen
     `Estado en laboratorio` = `✅ Verificado` (progresión acumulativa sin
     saltos: no es suficiente que exista al menos uno verificado por nivel).
   - Un control `🔲 Fuera de alcance experimental` en cualquier nivel
     `≤ Nx` impide que `Nx` (y todo nivel superior) se considere verificado.

   El **nivel verificado en laboratorio** de la subdimensión es el `Nx` más
   alto que cumple esta condición. Los niveles cuyo subconjunto
   Configuración/Experimental es vacío (solo controles `⚠️`) no aportan ni
   bloquean por sí mismos: se evalúan exclusivamente por auditoría
   documental (nivel declarado), conforme a la distinción nivel
   verificado/nivel declarado del marco (sección 2.6).
4. **Sección "Regla de piso mínimo"** combina los cuatro resultados anteriores
   en el nivel global del sistema.
5. **D5 (Gobernanza organizacional)** es **exclusivamente declarativa**: sus
   15 controles se verifican únicamente mediante auditoría documental y no
   participan de la regla de piso mínimo (que se calcula solo sobre D1-D4).

> **Nota sobre completitud:** todas las descripciones de esta tabla se
> extrajeron de la definición canónica del marco LLM-Sec (Apéndice A,
> Resumen de controles por nivel, y Apéndice C, Fichas técnicas de
> control), que constituye la fuente de verdad para `Nivel`/`Tipo`/
> `Evidencia`/`Fuente`/subdimensión de cada control. Cuando el Apéndice A
> (tabla resumen) y la ficha correspondiente del Apéndice C discrepan en el
> campo `Tipo`, esta tabla adopta el valor de la ficha del Apéndice C (más
> detallada y argumentada) y la discrepancia queda documentada en
> `docs/CONTROL_AUDIT_REPORT.md`.

---

## D1 — Protección de entrada (LLM01:2025) 

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C1 | N1 | Prev | Configuración | Limita la longitud del prompt de entrada (en tokens) para mitigar payloads de inyección o desbordamiento antes de llegar al modelo. | LLM01:2025 | ✅ Verificado — Configuración | `app/config/global/llm_guard_config.yaml` → `input_scanners.token_limit` (`limit: 512`, `encoding_name: cl100k_base`) |
| C2 | N1 | Cor | Experimental | Elimina tokens especiales del modelo, bytes nulos y caracteres de control Unicode del texto de entrada antes de escanearlo. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `_sanitize_control_chars()` |
| C6 | N1 | Prev | Configuración | Estructura el prompt con delimitadores explícitos `Context:`/`Question:`, separando el contenido recuperado de la consulta del usuario. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()` (plantilla de prompt) |
| C13 | N1 | Prev | Configuración | Limita el volumen total de contexto inyectado en el prompt al restringir la recuperación a `k` fragmentos. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C15 | N1 | Prev | Configuración | Inyecta instrucciones de rol de sistema y restricciones configuradas externamente (`system_role`/`restrictions`) en cada prompt. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()`; `app/config/domains/*/rag.json` |
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de seguridad de entrada del componente generador. | LLM01:2025, LLM02:2025, LLM07:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C21 | N1 | Prev | Configuración | Externaliza toda la configuración de tiempo de ejecución (hosts, escenario, umbrales, rutas) como variables de entorno declaradas en la definición de cada servicio, sin valores hardcodeados en el código fuente. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → bloques `environment:` de `rag_api` / `shield_api` |
| C30 | N1 | Gov | Declarativo | Verifica procedencia e integridad del modelo mediante checksums. | Ley 21.663, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |
| C3 | N2 | Prev | Experimental | Bloquea prompts de entrada clasificados como intentos de inyección de instrucciones mediante el scanner PromptInjection. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_input()` (scanner `PromptInjection`, `threshold: 0.92`) |
| C4 | N2 | Prev | Experimental | Bloquea consultas cuya distancia semántica mínima al corpus supera el umbral configurado, rechazando preguntas fuera de dominio. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_on_domain()` / `DOMAIN_DISTANCE_THRESHOLD` |
| C5 | N2 | Det | Experimental | Solo el texto generado por el modelo se extrae y retorna al cliente; el system prompt (rol/restricciones) nunca se incluye en la respuesta. | LLM01:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `generate()` (`out = response.get("response", "")`) |
| C31 | N3 | Det | Experimental | Registra un motivo de bloqueo estructurado (`input_<scanner>`/`output_<scanner>`) para cada solicitud bloqueada. | LLM01:2025 | ✅ Verificado — Experimental | `app/src/eval/consolidator.py`; `app/src/api/shield.py` → `log_request()` (`block_reason`) |
| C32 | N3 | Prev | Configuración | Verifica mediante hash SHA-256 que el system prompt y las restricciones no hayan sido modificados desde el arranque. | LLM01:2025, LLM07:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `validate_system_prompt_integrity()` |
| C33 | N4 | Prev | Declarativo | Ajusta dinámicamente umbrales de detección según tasas de falsos positivos. | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C34 | N4 | Det | Declarativo | Mide y reporta periódicamente la tasa de prompts rechazados por categoría. | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C35 | N5 | Prev | Declarativo | Actualiza patrones de detección ante nuevas técnicas de inyección. | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |
| C36 | N5 | Prev | Declarativo | Revisa y ajusta el prompt del sistema ante cambios en el modelo base. | LLM01:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D2 — Control de contexto RAG (LLM02:2025)

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C6 | N1 | Prev | Configuración | Estructura el prompt con delimitadores explícitos `Context:`/`Question:`, separando el contenido recuperado de la consulta del usuario. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()` (plantilla de prompt) |
| C7 | N1 | Prev | Configuración | Define mediante una instrucción de sistema externa (`restrictions`) la regla de uso exclusivo del contexto recuperado, prohibiendo inventar información no presente en él. | LLM02:2025 | ✅ Verificado — Configuración | `app/config/domains/*/rag.json` → `restrictions` |
| C10 | N1 | Prev | Configuración | Limita la cantidad de fragmentos recuperados mediante el parámetro `n_results` (`k`) pasado a ChromaDB. | LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C13 | N1 | Prev | Configuración | Limita el volumen total de contexto inyectado en el prompt al restringir la recuperación a `k` fragmentos. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `retrieve_context()` (`k` / `n_results`) |
| C15 | N1 | Prev | Configuración | Inyecta instrucciones de rol de sistema y restricciones configuradas externamente (`system_role`/`restrictions`) en cada prompt. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `app/src/api/rag.py` → `generate()`; `app/config/domains/*/rag.json` |
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de contexto del componente generador. | LLM01:2025, LLM02:2025, LLM07:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C21 | N1 | Prev | Configuración | Externaliza toda la configuración de tiempo de ejecución (hosts, escenario, umbrales, rutas) como variables de entorno declaradas en la definición de cada servicio, sin valores hardcodeados en el código fuente. | LLM01:2025, LLM02:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → bloques `environment:` de `rag_api` / `shield_api` |
| C30 | N1 | Gov | Declarativo | Verifica procedencia e integridad del modelo mediante checksums. | Ley 21.663, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |
| C8 | N2 | Prev | Configuración | Clasifica cada fragmento del corpus según su nivel de sensibilidad al ingestarlo (`_classify_sensitivity()`) y restringe la recuperación a los niveles permitidos según el escenario mediante `where_filter`/`ALLOWED_SENSITIVITY` en `retrieve_context()`. | LLM02:2025, LLM08:2025 | ✅ Verificado — Configuración | `app/src/ingestion/generic_dir.py` → `_classify_sensitivity()`; `app/src/api/rag.py` → `retrieve_context()` |
| C9 | N2 | Prev/Det | Experimental | Verifica los hashes de los fragmentos recuperados contra una línea base (`CORPUS_HASHES`) antes de inyectarlos al contexto del LLM. | LLM02:2025, LLM08:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `validate_corpus_integrity()` |
| C11 | N2 | Prev | Experimental | Bloquea consultas cuya distancia semántica mínima a cualquier fragmento del corpus supera el umbral de coherencia (`QUERY_COHERENCE_THRESHOLD`), rechazando queries incoherentes o codificadas. | LLM02:2025, LLM08:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_coherent_query()` |
| C14 | N2 | Prev | Experimental | Excluye los metadatos de los documentos en la recuperación, de modo que solo el texto y los IDs de fragmento llegan al contexto del LLM. | LLM02:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `retrieve_context()` (`include=["documents","ids"]`) |
| C17 | N2 | Prev/Det | Experimental | Bloquea respuestas cuyo solapamiento de tokens con el contexto recuperado cae por debajo del umbral de "grounding" (`C17_GROUNDING_THRESHOLD`). | LLM02:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_grounded_response()` |
| C22 | N2 | Prev/Det | Declarativo | Controla y audita el acceso por sesión a documentos del vector store. | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C12 | N3 | Det | Experimental | Detecta y bloquea consultas indicativas de reconocimiento o enumeración sistemática del corpus. | LLM02:2025, LLM08:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_safe_from_reconnaissance()` |
| C62 | N3 | Det | Configuración | Registra cada evento de ingesta del corpus (hash, cantidad de documentos, acción) en un registro de versiones persistente (CSV). | LLM02:2025, LLM08:2025 | ✅ Verificado — Configuración | `app/src/cli.py` → `_record_corpus_version()` |
| C37 | N4 | Det | Declarativo | Mide la tasa de recuperación de fragmentos sensibles ante consultas de prueba. | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C38 | N4 | Prev | Declarativo | Ajusta parámetros de retrieval según métricas de exposición. | LLM02:2025 | ⚠️ Declarativo — auditoría documental | — |
| C39 | N5 | Prev | Declarativo | Actualiza particionamiento ante cambios en clasificación de sensibilidad. | LLM02:2025, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |
| C40 | N5 | Prev | Declarativo | Revisa fragmentos indexados ante nuevas amenazas de exfiltración. | LLM02:2025, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D3 — Gestión de salida (LLM07:2025)

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C16 | N1 | Prev | Configuración | Despliega el componente de protección (Shield/LLM Guard) como un servicio independiente que actúa de proxy frente al RAG, separando el control de salida del componente generador. | LLM01:2025, LLM02:2025, LLM07:2025 | ✅ Verificado — Configuración | `docker-compose.yml` → servicio `shield_api` (perfil `lab`, contenedor `tesis_shield`, proxy hacia `rag_api`) |
| C17 | N2 | Prev/Det | Experimental | Bloquea respuestas cuyo solapamiento de tokens con el contexto recuperado cae por debajo del umbral de "grounding" (`C17_GROUNDING_THRESHOLD`). | LLM02:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/rag.py` → `is_grounded_response()` |
| C18 | N2 | Cor | Experimental | Elimina caracteres de control y tokens especiales de la salida del modelo antes de escanearla y retornarla. | LLM01:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (`_sanitize_control_chars(text)`) |
| C19 | N2 | Det/Cor | Experimental | Bloquea respuestas que coincidan con patrones regex deterministas (marcador `[CONFIDENTIAL]`, RUT chileno, email, teléfono, contraseña, tarjeta de crédito). | LLM02:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (scanner `OutputRegex`); `app/config/global/llm_guard_config.yaml` → `output_scanners.regex` |
| C20 | N3 | Det | Experimental | Puntúa y/o bloquea respuestas que contienen información sensible mediante el scanner semántico Sensitive (score continuo, participa del análisis de sensibilidad). | LLM02:2025, LLM07:2025 | ✅ Verificado — Experimental | `app/src/api/shield.py` → `guard_output()` (scanner `Sensitive`); `app/config/global/llm_guard_config.yaml` → `output_scanners.sensitive` |
| C41 | N4 | Det | Declarativo | Ajusta umbrales de sanitización según métricas de falsos positivos. | LLM02:2025, LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C42 | N4 | Det | Declarativo | Mide la tasa de supresión de fragmentos confidenciales por tipo de ataque. | LLM02:2025, LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C43 | N5 | Det | Declarativo | Actualiza patrones de detección de contenido sensible ante nuevas técnicas. | LLM02:2025, LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |
| C44 | N5 | Det | Declarativo | Incorpora retroalimentación de incidentes al conjunto de patrones. | LLM02:2025, LLM07:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D4 — Monitoreo y trazabilidad (LLM08:2025)

> Por diseño, el marco no asigna controles de **N1** a esta subdimensión (ver
> "Regla de piso mínimo").

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C26 | N2 | Gov | Declarativo | Define política de umbrales de detección y bloqueo previo a la operación. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C27 | N2 | Gov | Declarativo | Establece procedimiento de notificación de seguridad ante autoridades. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C28 | N2 | Gov | Declarativo | Define política de retención y eliminación de datos de sesión. | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C23 | N3 | Det | Experimental | Registra en el CSV consolidado el nombre del scanner que originó el bloqueo de cada solicitud. | LLM01:2025, LLM02:2025, LLM07:2025, LLM08:2025 | ✅ Verificado — Experimental | `app/src/eval/consolidator.py`; `app/src/api/shield.py` → `log_request()` (`scanner_triggered`) |
| C25 | N3 | Det | Experimental | Registra latencia y metadatos de cada solicitud en un CSV para análisis post-experimento. | LLM01:2025, LLM02:2025, LLM07:2025, LLM08:2025 | ✅ Verificado — Experimental | `app/src/api/middleware.py` → `LatencyCSVLogger` |
| C29 | N3 | Gov | Declarativo | Documenta y ejecuta plan de pruebas ofensivas previo a cada despliegue. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C24 | N4 | Det | Experimental | Monitorea patrones de consulta anómalos. | LLM02:2025, LLM08:2025 (nota: el Apéndice B del marco atribuye LLM01/02/07/08, mientras que la ficha C.5.7 solo declara LLM02/08; discrepancia normativa entre Apéndice B y C, ver informe de auditoría) | 🔲 Fuera de alcance experimental (resuelto, ver nota) | — |
| C45 | N5 | Det | Declarativo | Actualiza patrones de detección de anomalías ante nuevas amenazas. | LLM01:2025, LLM02:2025, LLM07:2025, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |
| C46 | N5 | Cor | Declarativo | Incorpora retroalimentación de incidentes al sistema de alertas. | LLM01:2025, LLM02:2025, LLM07:2025, LLM08:2025 | ⚠️ Declarativo — auditoría documental | — |

---

## D5 — Gobernanza organizacional

> Subdimensión **exclusivamente declarativa**: los 15 controles se verifican
> mediante auditoría documental (políticas, procesos, marcos regulatorios) y
> no participan de la "Regla de piso mínimo".

| ID | Nivel | Tipo | Evidencia | Descripción | Fuente | Estado en laboratorio | Artefacto / Ubicación |
|----|-------|------|-----------|-------------|--------|------------------------|------------------------|
| C47 | N1 | Gov | Declarativo | Designa formalmente al responsable de seguridad del sistema RAG. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C48 | N1 | Gov | Declarativo | Declara el sistema RAG como activo de información. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C49 | N1 | Gov | Declarativo | Establece política de uso aceptable del sistema RAG. | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C61 | N1 | Gov | Declarativo | Mantiene inventario actualizado de activos del sistema RAG. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C50 | N2 | Gov | Declarativo | Adopta y adapta la matriz RACI del marco LLM-Sec, asignando cada rol genérico a cargos concretos. | Ley 21.663 | ⚠️ Declarativo — auditoría documental | — |
| C51 | N2 | Gov | Declarativo | Establece procedimiento de gestión de accesos (altas, bajas y modificaciones). | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C52 | N2 | Gov | Declarativo | Documenta inventario de datos personales procesados por el sistema. | Ley 21.719 | ⚠️ Declarativo — auditoría documental | — |
| C53 | N3 | Gov | Declarativo | Establece programa de capacitación en seguridad de sistemas LLM dirigido a los roles de la matriz RACI. | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C54 | N3 | Gov | Declarativo | Define ciclo de revisión periódica del marco con frecuencia mínima anual. | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C55 | N3 | Gov | Declarativo | Documenta y comunica formalmente a la dirección los riesgos residuales tras la implementación de controles. | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C60 | N3 | Gov | Declarativo | Realiza evaluación formal de riesgos del sistema con frecuencia mínima anual. | NIST AI RMF | ⚠️ Declarativo — auditoría documental | — |
| C56 | N4 | Gov | Declarativo | Establece métricas de desempeño de la gobernanza de seguridad y las reporta periódicamente a la dirección. | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C57 | N4 | Gov | Declarativo | Implementa un proceso formal que clasifica el sistema RAG según su nivel de criticidad (gestión de riesgos de IA). | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C58 | N5 | Gov | Declarativo | Revisa proactivamente el marco ante cambios normativos, nuevas amenazas o cambios del modelo base. | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |
| C59 | N5 | Gov | Declarativo | Incorpora lecciones aprendidas de incidentes al ciclo de mejora de la gobernanza. | Proyecto Ley IA | ⚠️ Declarativo — auditoría documental | — |

---

## Determinación del nivel verificado

Para cada subdimensión D1-D4 se aplica la regla del punto 3 (ver "Cómo usar
este documento"), derivada del paso 4 de la guía de evaluación del marco
(capítulo 6.1): para cada nivel `Nx`, se considera únicamente el subconjunto
de controles de ese nivel con `Evidencia` ∈ {Configuración, Experimental}.
Un nivel `Nx` está **verificado en laboratorio** si y solo si **todos** los
controles Configuración/Experimental de nivel `Nx` y de todos los niveles
inferiores de la subdimensión tienen `Estado en laboratorio` = `✅
Verificado` (progresión acumulativa, sin saltos). Un control `🔲 Fuera de
alcance experimental` en cualquier nivel `≤ Nx` impide que `Nx` se considere
verificado. El nivel verificado de la subdimensión es el `Nx` más alto que
cumple esta condición. Los controles `⚠️ Declarativo` se excluyen del
cálculo (su nivel se evalúa por auditoría documental, junto con D5) y no
bloquean ni habilitan por sí mismos un nivel.

> **Nota de resolución (C24):** C24 (D4-N4) es el único control
> `🔲 Fuera de alcance experimental` que permanece en el instrumento. Esta
> revisión confirma que no existe artefacto alguno en el repositorio que lo
> implemente, bajo ningún nombre o ubicación. C24 queda intencionalmente
> fuera del alcance experimental TRL 4 y constituye la brecha prioritaria
> para el tránsito N3 a N4, consistente con el plan de remediación de la
> tesis. Dado que N4 no es un nivel inferior a N3, esta brecha no afecta el
> nivel verificado D4 = N3 calculado a continuación.

### D1 — Protección de entrada

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C1, C2, C6, C13, C15, C16, C21 | C30 | Todos ✅ | **Sí** |
| N2 | C3, C4, C5 | — | Todos ✅ | **Sí** |
| N3 | C31, C32 | — | Todos ✅ | **Sí** |
| N4 | — | C33, C34 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C35, C36 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D1 (Escenario B): N3.** Todos los controles
Configuración/Experimental de N1, N2 y N3 están `✅ Verificado` de forma
acumulativa (N1 ⊆ N2 ⊆ N3 completos, sin brechas); N4 y N5 no tienen
controles de evidencia Configuración/Experimental y se evalúan por auditoría
documental.

### D2 — Control de contexto RAG

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C6, C7, C10, C13, C15, C16, C21 | C30 | Todos ✅ (C30 excluido) | **Sí** |
| N2 | C8, C9, C11, C14, C17 | C22 | Todos ✅ (C22 excluido) | **Sí** |
| N3 | C12, C62 | — | Todos ✅ | **Sí** |
| N4 | — | C37, C38 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C39, C40 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D2 (Escenario B): N3.** Todos los controles
Configuración/Experimental de N1, N2 y N3 están `✅ Verificado` de forma
acumulativa (C30 y C22 son `⚠️ Declarativo` y se excluyen del cálculo); N4 y
N5 no tienen controles de evidencia Configuración/Experimental y se evalúan
por auditoría documental.

### D3 — Gestión de salida

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | C16 | — | ✅ | **Sí** |
| N2 | C17, C18, C19 | — | Todos ✅ | **Sí** |
| N3 | C20 | — | ✅ | **Sí** |
| N4 | — | C41, C42 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N5 | — | C43, C44 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D3 (Escenario B): N3.** Todos los controles
Configuración/Experimental de N1, N2 y N3 están `✅ Verificado` de forma
acumulativa; N4 y N5 no tienen controles de evidencia
Configuración/Experimental y se evalúan por auditoría documental.

### D4 — Monitoreo y trazabilidad

| Nivel | Controles Config./Exp. | Controles Declarativos (excluidos) | Estado | ¿Nivel verificado? |
|-------|--------------------------|--------------------------------------|--------|----------------------|
| N1 | *(sin controles asignados por diseño)* | — | — | No aplica |
| N2 | — | C26, C27, C28 | Sin controles Config./Exp. | Auditoría documental (D5) |
| N3 | C23, C25 | C29 | Todos ✅ (C29 excluido) | **Sí** |
| N4 | C24 | — | 🔲 sin verificar | **No** |
| N5 | — | C45, C46 | Sin controles Config./Exp. | Auditoría documental (D5) |

**Nivel verificado D4 (Escenario B): N3.** N3 está completamente verificado:
C23 y C25 están `✅ Verificado — Experimental` (C29 es `⚠️ Declarativo` y se
excluye), y ningún control Configuración/Experimental de nivel ≤N3 está `🔲`.
N1 no tiene controles asignados por diseño del marco; N2 solo tiene
controles Declarativos (C26-C28) y se evalúa por auditoría documental. N4 no
está verificado porque C24 es `🔲` (ver nota de resolución arriba), pero esto
no afecta el nivel verificado de D4, ya que N3 es el nivel acumulativo máximo
alcanzado y N4 no es un nivel inferior a N3.

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
de nivel N1** (ver tabla D4, su nivel mínimo asignado es N2). Cualquier
exigencia de piso que requiera un N1 verificado de forma transversal a
D1-D4 nunca puede ser satisfecha por D4, por lo que el piso mínimo de
Escenario A queda en **N0** con independencia de los resultados de D1-D3.

De forma adicional y consistente con esta conclusión: en Escenario A
(`IS_PROTECTED=False`, `SCENARIO=unprotected`) el componente Shield/LLM Guard
no se interpone en el flujo de la solicitud, por lo que los scanners de
entrada/salida que dependen de él (C2, C3, C18, C19, C20) y los controles de
defensa en profundidad del RAG habilitados solo en la configuración protegida
(C4, C8, C9, C11, C12, C17) no pueden contar como `✅ Verificado`, ampliando
el conjunto de controles no verificados de D1-D3 respecto del Escenario B,
sin alterar la conclusión N0 ya determinada por D4.

Por lo tanto, el nivel global del sistema bajo el marco LLM-Sec completo (62
controles) es **N3 para Escenario B** y **N0 para Escenario A**, sujeto a la
nota de resolución de C24 (D4-N4) señalada en la sección anterior y al
hallazgo crítico descrito a continuación.

---

## Hallazgo crítico: activación real de los controles condicionados por `IS_PROTECTED`

Esta revisión identificó un hallazgo que no puede corregirse desde este
documento (por estar fuera del alcance de "solo documentación") pero que
debe señalarse explícitamente porque afecta la interpretación empírica del
nivel D2 = N3 y de los controles C4, C8, C9, C11, C12, C17 y C32 reportado
más arriba como `✅ Verificado`.

`docker-compose.yml` define el servicio `rag_api` con la variable de entorno
`SCENARIO=unprotected` fijada de forma literal (no interpolada), y esa
misma definición se usa sin cambios tanto para el Escenario A como para el
Escenario B: en ambos casos existe un único contenedor `tesis_rag`, y
`shield_api` (`tesis_shield`, con `SCENARIO=protected`) siempre reenvía sus
solicitudes hacia ese mismo `rag_api`. El selector `GARAK_TARGET` usado por
`garak_runner` solo decide si Garak ataca `rag_api` directamente (Escenario
A) o a través de `shield_api` (Escenario B); no modifica en ningún momento
la variable `SCENARIO` del contenedor `rag_api`.

En consecuencia, dentro de `app/src/api/rag.py` la variable
`IS_PROTECTED = SCENARIO == "protected"` se evalúa como `False` de forma
permanente, incluso cuando Garak ataca vía `shield_api` en una corrida
etiquetada como Escenario B. Todos los bloques `if IS_PROTECTED:` de
`generate()` (que gatillan C32, C4, C11, C12, C9 y el bloqueo de C17) y el
`where_filter` de C8 en `retrieve_context()` quedan, por tanto, sin ejecutar
su rama de bloqueo/filtrado en ninguna corrida registrada, sin importar el
escenario nominal del experimento.

Esto se confirmó empíricamente: los cuatro CSV consolidados en
`artifacts/` (`consolidated_*_protected.csv` y
`consolidated_*_unprotected.csv`) no registran ninguna ocurrencia de los
`block_reason` distintivos de estos controles en ningún run.

Esto no invalida el `Estado en laboratorio = ✅ Verificado` de C4, C8, C9,
C11, C12, C17 y C32 tal como está definido en este instrumento, porque ese
estado certifica la existencia y correctitud del artefacto de código (que
esta revisión confirmó), no su activación efectiva en cada corrida
experimental registrada. Cambiar esos estados sería una decisión de alcance
mayor que excede una auditoría de documentación y que debe tomar el equipo
del laboratorio. El detalle completo de este hallazgo, su evidencia y sus
implicancias para los resultados reportados en la tesis se documentan en
`docs/CONTROL_AUDIT_REPORT.md`.
