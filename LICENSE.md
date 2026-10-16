# Licencia y acceso abierto

Copyright (c) 2026 Valentina Paz Campos Olguín
Universidad de Santiago de Chile — Departamento de Ingeniería Informática (DIINF)

## Declaración de acceso abierto

Este repositorio es de **acceso abierto y libremente accesible**. Cualquier persona puede
consultar, descargar, copiar, ejecutar, reproducir, modificar, redistribuir y construir a
partir de este trabajo —con fines académicos o comerciales— **sin necesidad de pedir
permiso, registrarse ni pagar**. La única condición es la atribución a la autora.

No se aplican ni se aplicarán medidas tecnológicas, contractuales ni administrativas que
restrinjan el acceso a este material o los derechos otorgados por las licencias de abajo.
Ambas licencias elegidas son licencias libres reconocidas (MIT está aprobada por la Open
Source Initiative y CC BY 4.0 cumple la Open Definition), y se seleccionaron precisamente
para que la reproducibilidad del experimento no dependa del permiso de nadie.

---

Este repositorio acompaña a la tesis *"Framework for cybersecurity evaluation in
LLM-integrated platforms"* y se publica con **licencia dual**, porque contiene dos tipos de
obra con necesidades distintas de reutilización:

| Parte del repositorio | Licencia |
|---|---|
| **Software**: todo el código fuente (`app/`, `scripts/`, `llmsec.sh`, `Dockerfile`, `docker-compose.yml`, archivos de configuración y `requirements*.txt`) | **MIT** |
| **Obra académica**: documentación (`README.md`, `docs/`, `CLAUDE.md`), figuras, tablas, resultados y datos derivados del experimento (`artifacts/`, `figuras/`) | **Creative Commons Atribución 4.0 Internacional (CC BY 4.0)** |

La licencia MIT permite reproducir, auditar y extender el laboratorio sin fricción, que es
el requisito central de un trabajo reproducible. CC BY 4.0 cubre el material académico y
exige atribución, que es el requisito central de un trabajo de tesis. Ninguna de las dos
impone restricciones de campo de uso, de tipo de usuario ni de finalidad.

Esta licencia cubre únicamente la contribución original de esta tesis. **No** se extiende a:

- las dependencias de terceros (Garak, LLM Guard, ChromaDB, FastAPI, Ollama, Llama 3 y
  demás paquetes declarados en `requirements.txt`), que conservan sus propias licencias;
- los pesos del modelo `llama3:8b`, sujetos a la *Meta Llama 3 Community License*;
- los documentos fuente del corpus alojados bajo `data/`, que mantienen la licencia o los
  términos de uso de sus publicadores originales (EU Critical Raw Materials Act y Common
  Data Set institucional).

---

## 1. Software — Licencia MIT

Copyright (c) 2026 Valentina Paz Campos Olguín

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

---

## 2. Documentación, figuras y datos — CC BY 4.0

Esta obra está licenciada bajo la
[Licencia Creative Commons Atribución 4.0 Internacional](https://creativecommons.org/licenses/by/4.0/deed.es).
El texto legal completo está disponible en
<https://creativecommons.org/licenses/by/4.0/legalcode.es>.

**Eres libre de:**

- **Compartir** — copiar y redistribuir el material en cualquier medio o formato.
- **Adaptar** — remezclar, transformar y construir a partir del material para cualquier
  finalidad, incluso comercial.

**Bajo la siguiente condición:**

- **Atribución** — debes dar crédito de manera adecuada, brindar un enlace a la licencia e
  indicar si se han realizado cambios. Puedes hacerlo de cualquier forma razonable, pero no
  de forma tal que sugiera que tienes el apoyo de la licenciante o lo recibes por el uso
  que haces.

No puedes aplicar términos legales ni medidas tecnológicas que restrinjan legalmente a
otras personas hacer cualquier uso permitido por la licencia.

---

## 3. Atribución sugerida

Campos Olguín, V. P. (2026). *Framework for cybersecurity evaluation in LLM-integrated
platforms* [Tesis, Universidad de Santiago de Chile, Departamento de Ingeniería
Informática]. Profesor guía: Juan Ignacio Iturbe Araya.

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

---

## 4. Uso responsable

Esta sección es una **nota informativa, no una condición de la licencia**: no restringe ni
modifica ninguno de los derechos otorgados en las secciones 1 y 2.

Este repositorio contiene herramientas de auditoría ofensiva (probes de Garak) y controles
defensivos para sistemas RAG. Se desarrolló con fines académicos y defensivos: evaluar,
medir y endurecer plataformas integradas con LLM. Al auditar sistemas de terceros rige la
legislación aplicable y, en general, hace falta autorización del titular del sistema; eso
es independiente de esta licencia y responsabilidad de quien ejecute la auditoría.
