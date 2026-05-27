#!/usr/bin/env bash
# smoke-test.sh — Smoke test automatizado con auto-corrección
# Uso: bash smoke-test.sh <dominio>
# O desde lab.sh: lab-smoke

set -euo pipefail

DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
    if [[ -f .env.last_domain ]]; then
        DOMAIN="$(cat .env.last_domain)"
    else
        echo "❌ Falta dominio. Uso: bash smoke-test.sh <dominio>"
        exit 1
    fi
fi

ENV_FILE=".env.${DOMAIN}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "❌ No existe ${ENV_FILE}"
    exit 1
fi

# ── Colores ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
FIXED=0

log_step() { echo -e "\n${BLUE}══ $1 ${NC}"; }
log_ok()   { echo -e "  ${GREEN}✅ $1${NC}"; ((PASS++)) || true; }
log_err()  { echo -e "  ${RED}❌ $1${NC}"; ((FAIL++)) || true; }
log_fix()  { echo -e "  ${YELLOW}🔧 $1${NC}"; ((FIXED++)) || true; }
log_info() { echo -e "  ℹ️  $1"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
wait_healthy() {
    local service="$1"
    local max_wait="${2:-120}"
    local elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' "$service" 2>/dev/null || echo "missing")
        case "$health" in
            healthy) return 0 ;;
            unhealthy) return 1 ;;
            *) sleep 5; ((elapsed+=5)) ;;
        esac
    done
    return 1
}

container_running() {
    docker ps --filter "name=$1" --filter "status=running" -q | grep -q .
}

# ── Inicio ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "  Smoke Test — LLM-Sec Lab"
echo "  Dominio: $DOMAIN"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════════"

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 1 — Prerrequisitos"
# ────────────────────────────────────────────────────────────────────────────

# Docker
if docker compose version &>/dev/null; then
    log_ok "Docker Compose disponible"
else
    log_err "Docker Compose no encontrado"
    exit 1
fi

# GPU
if nvidia-smi &>/dev/null; then
    log_ok "GPU disponible"
else
    log_err "nvidia-smi no responde — el experimento puede ser muy lento"
fi

# Archivos de configuración
for f in "$ENV_FILE" "app/config/domains/${DOMAIN}/rag.json" \
          "app/config/domains/${DOMAIN}/legitimate_prompts.json"; do
    if [[ -f "$f" ]]; then
        log_ok "Existe: $f"
    else
        log_err "Falta: $f — ejecuta: lab-new-domain"
    fi
done

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 2 — Stack docker compose"
# ────────────────────────────────────────────────────────────────────────────

# Levantar si no está corriendo
if container_running "tesis_rag" && container_running "tesis_shield"; then
    log_ok "Stack ya está corriendo"
else
    log_info "Levantando stack..."
    docker compose --env-file "$ENV_FILE" --profile lab up -d
    log_fix "Stack levantado"
fi

# Esperar health rag_api
log_info "Esperando health de tesis_rag (máx 120s)..."
if wait_healthy "tesis_rag" 120; then
    log_ok "tesis_rag healthy"
else
    log_info "tesis_rag unhealthy — intentando auto-corrección..."
    # Causa más común: colección no existe aún
    log_fix "Reiniciando tesis_rag..."
    docker restart tesis_rag
    sleep 10
    if wait_healthy "tesis_rag" 60; then
        log_ok "tesis_rag healthy (tras restart)"
    else
        log_err "tesis_rag sigue unhealthy — es posible que falte ingestar el corpus"
        log_info "Intentando ingestar corpus y reiniciar..."
        docker compose --env-file "$ENV_FILE" run --rm rag_api \
            python3 -m cli ingest --source "$DOMAIN" --reset 2>&1 | tail -3
        docker restart tesis_rag
        sleep 15
        if wait_healthy "tesis_rag" 60; then
            log_ok "tesis_rag healthy (tras ingestión)"
            log_fix "Se realizó ingestión automática"
        else
            log_err "tesis_rag sigue unhealthy — revisar logs: docker logs tesis_rag"
        fi
    fi
fi

# Esperar health shield_api
log_info "Esperando health de tesis_shield (máx 120s)..."
if wait_healthy "tesis_shield" 120; then
    log_ok "tesis_shield healthy"
else
    log_err "tesis_shield unhealthy — revisar logs: docker logs tesis_shield"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 3 — Ingestión y ground truth"
# ────────────────────────────────────────────────────────────────────────────

# Verificar que la colección tiene datos
CHUNK_COUNT=$(docker exec tesis_rag python3 -c "
import chromadb
try:
    c = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
    col = c.get_collection('${DOMAIN}')
    print(col.count())
except Exception as e:
    print(0)
" 2>/dev/null || echo "0")

if [[ "$CHUNK_COUNT" -gt 0 ]]; then
    log_ok "Corpus indexado: $CHUNK_COUNT chunks"
else
    log_info "Corpus vacío — ejecutando ingestión..."
    docker compose --env-file "$ENV_FILE" run --rm rag_api \
        python3 -m cli ingest --source "$DOMAIN" --reset 2>&1 | tail -5
    log_fix "Corpus ingestado"

    docker restart tesis_rag
    sleep 10
    wait_healthy "tesis_rag" 60 && log_ok "tesis_rag healthy tras ingestión" || true
fi

# Verificar ground truth
log_info "Verificando ground truth..."
GT_RESULT=$(docker exec tesis_rag python3 -m cli ingest verify \
    --collection "$DOMAIN" 2>&1 | tail -5)
if echo "$GT_RESULT" | grep -qi "error\|fail\|❌"; then
    log_err "Ground truth con errores:"
    echo "$GT_RESULT"
else
    log_ok "Ground truth verificado"
fi

# Verificar distribución de sensibilidad
SENS_RESULT=$(docker exec tesis_rag python3 -c "
import chromadb
from collections import Counter
c = chromadb.PersistentClient(path='/root/proyecto_tesis/chroma_db')
col = c.get_collection('${DOMAIN}')
result = col.get(include=['metadatas'])
cnt = Counter(m.get('sensitivity','unknown') for m in result['metadatas'])
for k,v in sorted(cnt.items()):
    print(f'  {k}: {v} chunks')
" 2>/dev/null || echo "  error al leer sensibilidad")
log_ok "Distribución de sensibilidad:"
echo "$SENS_RESULT"

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 4 — Smoke probe (Escenario A)"
# ────────────────────────────────────────────────────────────────────────────

log_info "Ejecutando 1 probe × 1 repetición (LLM07 goodside.Tag)..."
PROBE_RC=0
docker compose --env-file "$ENV_FILE" --profile attacks run --rm \
    garak_runner attack garak \
    --target unprotected \
    --suite LLM07 \
    --probe goodside.Tag \
    --smoke-test 2>&1 | tail -10 || PROBE_RC=$?

if [[ $PROBE_RC -eq 0 ]]; then
    log_ok "Probe ejecutado sin errores (rc=0)"
else
    log_err "Probe terminó con rc=$PROBE_RC"
fi

# Verificar que se generó el reporte
REPORT_COUNT=$(find artifacts/runs -name "*.report.jsonl" -newer "$ENV_FILE" 2>/dev/null | wc -l || echo "0")
if [[ "$REPORT_COUNT" -gt 0 ]]; then
    log_ok "Reportes generados: $REPORT_COUNT archivo(s)"
else
    log_err "No se encontraron reportes — verificar artifacts/runs/"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 5 — Prompts legítimos (Escenario A)"
# ────────────────────────────────────────────────────────────────────────────

log_info "Ejecutando prompts legítimos (1 repetición)..."
LEGIT_RC=0
docker exec -e RUN_KIND=smoke_test tesis_rag python3 -m cli attack legitimate \
    --target unprotected --repetitions 1 2>&1 | tail -5 || LEGIT_RC=$?

if [[ $LEGIT_RC -eq 0 ]]; then
    log_ok "Prompts legítimos ejecutados"
else
    log_err "Error en prompts legítimos (rc=$LEGIT_RC)"
fi

# Verificar CSV consolidado (smoke_test/ subdir)
CSV_PATH="artifacts/smoke_test/consolidated_${DOMAIN}_unprotected.csv"
if [[ -f "$CSV_PATH" ]]; then
    ROW_COUNT=$(python3 -c "
import csv
with open('${CSV_PATH}') as f:
    print(sum(1 for _ in csv.DictReader(f)))
" 2>/dev/null || echo "0")
    log_ok "CSV consolidado: $ROW_COUNT filas ($CSV_PATH)"
else
    log_err "CSV no encontrado: $CSV_PATH"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 6 — Patch garak_passed"
# ────────────────────────────────────────────────────────────────────────────

PATCH_RC=0
docker exec tesis_rag python3 -m cli metrics patch-garak \
    --domain "$DOMAIN" --scenario unprotected 2>&1 | tail -3 || PATCH_RC=$?

if [[ $PATCH_RC -eq 0 ]]; then
    log_ok "patch-garak completado"
else
    log_err "Error en patch-garak (rc=$PATCH_RC)"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 7 — Smoke probe (Escenario B)"
# ────────────────────────────────────────────────────────────────────────────

log_info "Ejecutando 1 probe × 1 repetición en Escenario B..."
PROBE_B_RC=0
docker compose --env-file "$ENV_FILE" --profile attacks run --rm \
    garak_runner attack garak \
    --target protected \
    --suite LLM07 \
    --probe goodside.Tag \
    --smoke-test 2>&1 | tail -10 || PROBE_B_RC=$?

if [[ $PROBE_B_RC -eq 0 ]]; then
    log_ok "Probe B ejecutado sin errores"
else
    log_err "Probe B terminó con rc=$PROBE_B_RC"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 7b — Prompts legítimos (Escenario B)"
# ────────────────────────────────────────────────────────────────────────────

log_info "Ejecutando prompts legítimos Escenario B (1 repetición)..."
LEGIT_B_RC=0
docker exec -e RUN_KIND=smoke_test tesis_shield python3 -m cli attack legitimate \
    --target protected --repetitions 1 2>&1 | tail -5 || LEGIT_B_RC=$?

if [[ $LEGIT_B_RC -eq 0 ]]; then
    log_ok "Prompts legítimos Escenario B ejecutados"
else
    log_err "Error en prompts legítimos Escenario B (rc=$LEGIT_B_RC)"
fi

# Verificar CSV consolidado protegido (smoke_test/ subdir)
CSV_B_PATH="artifacts/smoke_test/consolidated_${DOMAIN}_protected.csv"
if [[ -f "$CSV_B_PATH" ]]; then
    ROW_B_COUNT=$(python3 -c "
import csv
with open('${CSV_B_PATH}') as f:
    print(sum(1 for _ in csv.DictReader(f)))
" 2>/dev/null || echo "0")
    log_ok "CSV consolidado (B): $ROW_B_COUNT filas ($CSV_B_PATH)"
else
    log_err "CSV no encontrado: $CSV_B_PATH"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 7c — Patch garak_passed (Escenario B)"
# ────────────────────────────────────────────────────────────────────────────

PATCH_B_RC=0
docker exec tesis_rag python3 -m cli metrics patch-garak \
    --domain "$DOMAIN" --scenario protected 2>&1 | tail -3 || PATCH_B_RC=$?

if [[ $PATCH_B_RC -eq 0 ]]; then
    log_ok "patch-garak Escenario B completado"
else
    log_err "Error en patch-garak Escenario B (rc=$PATCH_B_RC)"
fi

# ────────────────────────────────────────────────────────────────────────────
log_step "PASO 8 — Limpieza de artefactos del smoke test"
# ────────────────────────────────────────────────────────────────────────────

read -rp "  ¿Limpiar artefactos del smoke test? (s/N): " CLEAN
if [[ "${CLEAN,,}" == "s" ]]; then
    rm -rf artifacts/runs/*
    rm -rf artifacts/smoke_test 2>/dev/null || true
    rm -f artifacts/latency/latency_*.csv 2>/dev/null || true
    log_fix "Artefactos del smoke test eliminados"
else
    log_info "Artefactos conservados"
fi

# ────────────────────────────────────────────────────────────────────────────
# Resumen final
# ────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "  Resumen smoke test"
echo "═══════════════════════════════════════════════"
echo -e "  ${GREEN}✅ Pasos OK:       $PASS${NC}"
echo -e "  ${RED}❌ Pasos fallidos: $FAIL${NC}"
echo -e "  ${YELLOW}🔧 Auto-correcciones: $FIXED${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}El laboratorio está listo para el experimento completo.${NC}"
    echo ""
    echo "  Próximos pasos:"
    echo "    source lab.sh $DOMAIN"
    echo "    lab-attack-a    # Escenario A completo"
    echo "    lab-attack-b    # Escenario B completo"
    exit 0
else
    echo -e "  ${RED}Hay $FAIL error(s) que requieren atención manual.${NC}"
    echo "  Revisar los mensajes ❌ arriba."
    exit 1
fi