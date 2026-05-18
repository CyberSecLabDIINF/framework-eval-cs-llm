#!/usr/bin/env bash
# lab.sh — Shortcuts para el laboratorio LLM-Sec
# Uso: source lab.sh [dominio]
# Ejemplo: source lab.sh regulatory_technical
#
# Comandos disponibles después de hacer source:
#   lab-up           Levantar stack completo (lab)
#   lab-down         Bajar stack
#   lab-status       Ver estado de contenedores
#   lab-health       Verificar health de rag_api y shield_api
#   lab-logs         Ver logs en tiempo real (todos los servicios)
#   lab-logs-rag     Ver logs de tesis_rag
#   lab-logs-shield  Ver logs de tesis_shield
#   lab-ingest       Ingestar corpus del dominio activo
#   lab-verify       Verificar ground truth del dominio activo
#   lab-attack-a     Lanzar ataque completo Escenario A
#   lab-attack-b     Lanzar ataque completo Escenario B
#   lab-legit-a      Prompts legítimos Escenario A
#   lab-legit-b      Prompts legítimos Escenario B
#   lab-patch-a      Parchear garak_passed Escenario A
#   lab-patch-b      Parchear garak_passed Escenario B
#   lab-domain       Ver dominio activo
#   lab-smoke        Ejecutar smoke test automatizado
#   lab-new-domain   Crear archivos de configuración para un nuevo dominio

set -euo pipefail

# ── Detectar dominio ──────────────────────────────────────────────────────────
if [[ "${1:-}" != "" ]]; then
    LAB_DOMAIN="$1"
elif [[ -f .env.last_domain ]]; then
    LAB_DOMAIN="$(cat .env.last_domain)"
else
    echo "⚠️  No se especificó dominio."
    echo "   Uso: source lab.sh <dominio>"
    echo "   Dominios disponibles:"
    ls .env.* 2>/dev/null | sed 's/\.env\./   - /' || echo "   (ninguno encontrado)"
    return 1 2>/dev/null || exit 1
fi

# Verificar que existe el env file
ENV_FILE=".env.${LAB_DOMAIN}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "❌ No existe ${ENV_FILE}"
    echo "   Ejecuta: lab-new-domain para crear la configuración"
    return 1 2>/dev/null || exit 1
fi

echo "$LAB_DOMAIN" > .env.last_domain
echo "✅ Dominio activo: $LAB_DOMAIN (usando $ENV_FILE)"

# ── Funciones ─────────────────────────────────────────────────────────────────

lab-domain() {
    echo "Dominio activo: $LAB_DOMAIN"
    echo "Env file:       $ENV_FILE"
}

lab-up() {
    echo "▶ Levantando stack (dominio: $LAB_DOMAIN)..."
    docker compose --env-file "$ENV_FILE" --profile lab up -d
    echo "⏳ Esperando que los servicios estén healthy..."
    local i=0
    while [[ $i -lt 24 ]]; do
        local status
        status=$(docker compose --env-file "$ENV_FILE" ps --format json 2>/dev/null \
            | python3 -c "
import sys, json
lines = sys.stdin.read().strip().split('\n')
healthy = all(
    json.loads(l).get('Health','') in ('healthy','')
    for l in lines if l.strip()
)
print('ok' if healthy else 'wait')
" 2>/dev/null || echo "wait")
        if [[ "$status" == "ok" ]]; then
            echo "✅ Stack healthy"
            return 0
        fi
        sleep 5
        ((i++))
    done
    echo "⚠️  Timeout esperando health. Verificar con: lab-status"
}

lab-down() {
    echo "⏹ Bajando stack..."
    docker compose --env-file "$ENV_FILE" --profile lab down
}

lab-status() {
    docker compose --env-file "$ENV_FILE" ps
}

lab-health() {
    echo "── RAG API ──────────────────────────────"
    curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "❌ No responde"
    echo ""
    echo "── Shield API ───────────────────────────"
    curl -s http://localhost:8001/health | python3 -m json.tool 2>/dev/null || echo "❌ No responde"
}

lab-logs() {
    docker compose --env-file "$ENV_FILE" --profile lab logs -f
}

lab-logs-rag() {
    docker logs tesis_rag -f
}

lab-logs-shield() {
    docker logs tesis_shield -f
}

lab-ingest() {
    echo "▶ Ingestando corpus '$LAB_DOMAIN'..."
    docker compose --env-file "$ENV_FILE" run --rm rag_api \
        python3 -m cli ingest --source "$LAB_DOMAIN" --reset
}

lab-verify() {
    echo "▶ Verificando ground truth '$LAB_DOMAIN'..."
    docker exec tesis_rag python3 -m cli ingest verify \
        --collection "$LAB_DOMAIN"
}

lab-attack-a() {
    echo "▶ Lanzando ataque Escenario A (dominio: $LAB_DOMAIN)..."
    docker compose --env-file "$ENV_FILE" --profile attacks run --rm \
        garak_runner attack garak --target unprotected
}

lab-attack-b() {
    echo "▶ Lanzando ataque Escenario B (dominio: $LAB_DOMAIN)..."
    docker compose --env-file "$ENV_FILE" --profile attacks run --rm \
        garak_runner attack garak --target protected
}

lab-legit-a() {
    echo "▶ Prompts legítimos Escenario A..."
    docker exec tesis_rag python3 -m cli attack legitimate --target unprotected
}

lab-legit-b() {
    echo "▶ Prompts legítimos Escenario B..."
    docker exec tesis_shield python3 -m cli attack legitimate --target protected
}

lab-patch-a() {
    echo "▶ Parcheando garak_passed Escenario A..."
    docker exec tesis_rag python3 -m cli metrics patch-garak \
        --domain "$LAB_DOMAIN" --scenario unprotected
}

lab-patch-b() {
    echo "▶ Parcheando garak_passed Escenario B..."
    docker exec tesis_rag python3 -m cli metrics patch-garak \
        --domain "$LAB_DOMAIN" --scenario protected
}

lab-new-domain() {
    bash "$(dirname "${BASH_SOURCE[0]}")/new-domain.sh"
}

lab-smoke() {
    bash "$(dirname "${BASH_SOURCE[0]}")/smoke-test.sh" "$LAB_DOMAIN"
}

lab-help() {
    echo ""
    echo "Comandos disponibles (dominio activo: $LAB_DOMAIN)"
    echo ""
    echo "  lab-domain        Ver dominio activo"
    echo "  lab-up            Levantar stack"
    echo "  lab-down          Bajar stack"
    echo "  lab-status        Estado de contenedores"
    echo "  lab-health        Health check de ambas APIs"
    echo "  lab-logs          Logs en tiempo real"
    echo "  lab-logs-rag      Logs de tesis_rag"
    echo "  lab-logs-shield   Logs de tesis_shield"
    echo ""
    echo "  lab-ingest        Ingestar corpus del dominio activo"
    echo "  lab-verify        Verificar ground truth"
    echo ""
    echo "  lab-attack-a      Ataque completo Escenario A"
    echo "  lab-attack-b      Ataque completo Escenario B"
    echo "  lab-legit-a       Prompts legítimos Escenario A"
    echo "  lab-legit-b       Prompts legítimos Escenario B"
    echo "  lab-patch-a       Parchear garak_passed Escenario A"
    echo "  lab-patch-b       Parchear garak_passed Escenario B"
    echo ""
    echo "  lab-new-domain    Crear configuración para nuevo dominio"
    echo "  lab-smoke         Ejecutar smoke test automatizado"
    echo "  lab-help          Mostrar esta ayuda"
    echo ""
}

echo "💡 Ejecuta lab-help para ver todos los comandos disponibles"