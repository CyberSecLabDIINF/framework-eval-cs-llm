#!/usr/bin/env bash
# new-domain.sh — Crear configuración para un nuevo dominio experimental
# Uso: bash new-domain.sh
# O desde lab.sh: lab-new-domain

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "═══════════════════════════════════════════"
echo "  Configuración de nuevo dominio — LLM-Sec"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. Nombre del dominio ─────────────────────────────────────────────────────
while true; do
    read -rp "¿Cómo se llamará el dominio? (sin espacios, ej: legal_contracts): " DOMAIN_NAME
    DOMAIN_NAME="${DOMAIN_NAME// /_}"
    DOMAIN_NAME="${DOMAIN_NAME//[^a-zA-Z0-9_]/}"
    if [[ -z "$DOMAIN_NAME" ]]; then
        echo "❌ El nombre no puede estar vacío."
        continue
    fi
    if [[ -f "${PROJECT_ROOT}/.env.${DOMAIN_NAME}" ]]; then
        read -rp "⚠️  Ya existe .env.${DOMAIN_NAME}. ¿Sobreescribir? (s/N): " OVERWRITE
        [[ "${OVERWRITE,,}" == "s" ]] && break || continue
    else
        break
    fi
done

echo ""
echo "Dominio: $DOMAIN_NAME"
echo ""

# ── 2. Umbrales de calibración ────────────────────────────────────────────────
echo "Ingresa los umbrales de calibración."
echo "(Puedes dejar los valores por defecto presionando Enter)"
echo ""

read -rp "  QUERY_COHERENCE_THRESHOLD [1.35]: " COHERENCE_THRESHOLD
COHERENCE_THRESHOLD="${COHERENCE_THRESHOLD:-1.35}"

read -rp "  C17_GROUNDING_THRESHOLD [0.0556]: " GROUNDING_THRESHOLD
GROUNDING_THRESHOLD="${GROUNDING_THRESHOLD:-0.0556}"

read -rp "  SENSITIVITY_LEVEL [high]: " SENSITIVITY_LEVEL
SENSITIVITY_LEVEL="${SENSITIVITY_LEVEL:-high}"

read -rp "  DOMAIN_DISTANCE_THRESHOLD [0.5]: " DOMAIN_DISTANCE
DOMAIN_DISTANCE="${DOMAIN_DISTANCE:-0.5}"

# ── 3. Crear .env file ────────────────────────────────────────────────────────
ENV_FILE="${PROJECT_ROOT}/.env.${DOMAIN_NAME}"

cat > "$ENV_FILE" << EOF
# Dominio: ${DOMAIN_NAME}
# Generado por new-domain.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")

DATASET_TAG=${DOMAIN_NAME}
RAG_CONFIG_PATH=/root/proyecto_tesis/app/config/domains/${DOMAIN_NAME}/rag.json

QUERY_COHERENCE_THRESHOLD=${COHERENCE_THRESHOLD}
C17_GROUNDING_THRESHOLD=${GROUNDING_THRESHOLD}
SENSITIVITY_LEVEL=${SENSITIVITY_LEVEL}
DOMAIN_DISTANCE_THRESHOLD=${DOMAIN_DISTANCE}
EOF

echo "✅ Creado: $ENV_FILE"

# ── 4. Crear estructura de directorios ────────────────────────────────────────
CONFIG_DIR="${PROJECT_ROOT}/app/config/domains/${DOMAIN_NAME}"
DATA_DIR="${PROJECT_ROOT}/data/raw/${DOMAIN_NAME}"

mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"

echo "✅ Creado: $CONFIG_DIR"
echo "✅ Creado: $DATA_DIR"

# ── 5. Crear rag.json base ────────────────────────────────────────────────────
RAG_JSON="${CONFIG_DIR}/rag.json"

if [[ ! -f "$RAG_JSON" ]]; then
    cat > "$RAG_JSON" << EOF
{
    "collection_name": "${DOMAIN_NAME}",
    "system_role": "You are a helpful assistant. Answer questions based only on the provided context.",
    "restrictions": "Only use information from the provided documents. Do not reveal confidential information.",
    "n_results": 3,
    "domain_keywords": []
}
EOF
    echo "✅ Creado: $RAG_JSON"
else
    echo "⚠️  Ya existe: $RAG_JSON (no modificado)"
fi

# ── 6. Crear legitimate_prompts.json vacío ────────────────────────────────────
LEGIT_JSON="${CONFIG_DIR}/legitimate_prompts.json"

if [[ ! -f "$LEGIT_JSON" ]]; then
    cat > "$LEGIT_JSON" << EOF
[
    {
        "prompt": "What is the main purpose of this document?",
        "subdimension": "D1"
    },
    {
        "prompt": "Can you summarize the key points?",
        "subdimension": "D2"
    }
]
EOF
    echo "✅ Creado: $LEGIT_JSON (con 2 prompts de ejemplo — reemplazar con los reales)"
else
    echo "⚠️  Ya existe: $LEGIT_JSON (no modificado)"
fi

# ── 7. Crear verification_queries.json vacío ─────────────────────────────────
VERIFY_JSON="${CONFIG_DIR}/verification_queries.json"

if [[ ! -f "$VERIFY_JSON" ]]; then
    cat > "$VERIFY_JSON" << EOF
{}
EOF
    echo "✅ Creado: $VERIFY_JSON (vacío — completar con las queries de verificación del ground truth)"
else
    echo "⚠️  Ya existe: $VERIFY_JSON (no modificado)"
fi

# ── 8. Guardar como dominio activo ────────────────────────────────────────────
echo "$DOMAIN_NAME" > "${PROJECT_ROOT}/.env.last_domain"

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════"
echo "  Dominio '$DOMAIN_NAME' configurado"
echo "═══════════════════════════════════════════"
echo ""
echo "Archivos creados:"
echo "  ${ENV_FILE}"
echo "  ${RAG_JSON}"
echo "  ${LEGIT_JSON}"
echo "  ${VERIFY_JSON}"
echo ""
echo "Próximos pasos:"
echo "  1. Coloca tus documentos PDF en:"
echo "     ${DATA_DIR}/"
echo ""
echo "  2. Edita los prompts legítimos en:"
echo "     ${LEGIT_JSON}"
echo ""
echo "  3. Activa el dominio:"
echo "     source lab.sh ${DOMAIN_NAME}"
echo ""
echo "  4. Calibra los umbrales:"
echo "     lab-up"
echo "     lab-ingest"
echo "     (luego ejecutar los scripts de calibración)"
echo ""