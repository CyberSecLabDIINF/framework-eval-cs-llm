# Dockerfile (imagen "tesis_lab")
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/root/proyecto_tesis/app/src

# 1) Paquetes del sistema (los del README + utilidades comunes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    curl \
    git \
    nano \
    socat \
    procps \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# 2) Carpeta de trabajo
WORKDIR /root/proyecto_tesis

# 3) Instalar dependencias Python desde requirements.txt
#    (copiamos primero requirements para aprovechar cache de Docker)
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel \
  && python -m pip install -r /tmp/requirements.txt

# 4) Copiar tu código/configs al contenedor (ajusta si tu repo usa otra carpeta)
#    Si tus .py están en ./app, cambia a: COPY app/ /root/proyecto_tesis/
COPY . /root/proyecto_tesis/

# 5) Crear carpetas típicas (ajusta a tu layout real)
RUN mkdir -p /root/proyecto_tesis/chroma_db /root/proyecto_tesis/artifacts/runs

EXPOSE 8000 8001 11434

# 6) Por defecto, abrir shell para ejecutar comandos (garak, scripts, etc.)
CMD ["/bin/bash"]
