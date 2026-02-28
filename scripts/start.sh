#!/usr/bin/env bash
# ── VulnSentinel one-click start ──────────────────────────────────
# Usage: ./scripts/start.sh
#
# Starts: Docker infra → DB init → Backend (uvicorn) → Frontend (next dev)
# Stop:   Ctrl+C (kills both backend and frontend)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $1"; }
fail()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}── $1 ──${NC}"; }

# ── 1. Check prerequisites ────────────────────────────────────────

step "Checking prerequisites"
command -v docker >/dev/null 2>&1 || fail "docker not found"
command -v python >/dev/null 2>&1 || fail "python not found"
command -v npm    >/dev/null 2>&1 || fail "npm not found"
info "docker / python / npm found"

# ── 2. Load and validate .env ─────────────────────────────────────

step "Validating .env"

if [ ! -f .env ]; then
    fail ".env not found. Copy .env.example → .env and fill in values."
fi

set -a
source .env
set +a

errors=0

if [ -z "${VULNSENTINEL_JWT_SECRET:-}" ]; then
    echo -e "${RED}[ERR]${NC} VULNSENTINEL_JWT_SECRET is empty (required)"
    errors=1
else
    info "JWT_SECRET = ${VULNSENTINEL_JWT_SECRET:0:8}..."
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo -e "${RED}[ERR]${NC} DATABASE_URL is empty (required)"
    errors=1
else
    info "DATABASE_URL = ${DATABASE_URL%%@*}@***"
fi

if [ -z "${GITHUB_TOKEN:-}" ]; then
    warn "GITHUB_TOKEN is empty — event collection won't work"
else
    info "GITHUB_TOKEN = ${GITHUB_TOKEN:0:8}..."
fi

if [ -z "${VULNSENTINEL_ADMIN_PASSWORD:-}" ]; then
    warn "VULNSENTINEL_ADMIN_PASSWORD is empty — no auto-admin"
else
    info "Admin user: ${VULNSENTINEL_ADMIN_USERNAME:-admin}"
fi

if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    info "DEEPSEEK_API_KEY = ${DEEPSEEK_API_KEY:0:8}..."
else
    warn "DEEPSEEK_API_KEY is empty — LLM analysis won't work"
fi

[ "$errors" -ne 0 ] && fail "Fix the errors above before starting."

# ── 3. Docker infrastructure ─────────────────────────────────────

step "Starting Docker services"
docker compose up -d postgres neo4j 2>&1 | grep -v "^$" | tail -5

# Wait for PostgreSQL to be ready
echo -n "  Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if docker exec z-vulnsentinel-postgres-1 pg_isready -U vulnsentinel > /dev/null 2>&1; then
        echo " ready"
        break
    fi
    echo -n "."
    sleep 1
    [ "$i" -eq 30 ] && fail "PostgreSQL did not become ready in 30s"
done
info "Docker services running"

# ── 4. Create database if needed ──────────────────────────────────

step "Database setup"

DB_NAME=$(echo "$DATABASE_URL" | sed -E 's|.*/([^?]+).*|\1|')
DB_EXISTS=$(docker exec z-vulnsentinel-postgres-1 \
    psql -U vulnsentinel -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null | tr -d '[:space:]')

if [ "$DB_EXISTS" != "1" ]; then
    warn "Database '$DB_NAME' missing, creating..."
    docker exec z-vulnsentinel-postgres-1 \
        psql -U vulnsentinel -d postgres -c "CREATE DATABASE \"$DB_NAME\";" 2>/dev/null
    info "Database '$DB_NAME' created"
else
    info "Database '$DB_NAME' exists"
fi

# ── 5. Create tables (SQLAlchemy metadata.create_all) ─────────────

python -c "
import asyncio
from vulnsentinel.core.database import Base
from vulnsentinel.models import *
from sqlalchemy.ext.asyncio import create_async_engine

async def init():
    engine = create_async_engine('$DATABASE_URL')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

asyncio.run(init())
"
info "Tables initialized (9 tables)"

# ── 6. Pick available ports ───────────────────────────────────────

step "Resolving ports"

find_free_port() {
    local port=$1
    while ss -tlnp 2>/dev/null | grep -q ":${port} "; do
        echo -e "${YELLOW}[!!]${NC} Port $port is busy, trying $((port+1))" >&2
        port=$((port+1))
    done
    echo $port
}

BACKEND_PORT=$(find_free_port 8000)
FRONTEND_PORT=$(find_free_port 3001)  # 3000 often taken by Grafana

export VULNSENTINEL_CORS_ORIGINS="http://localhost:$FRONTEND_PORT"
info "Backend  → :$BACKEND_PORT"
info "Frontend → :$FRONTEND_PORT"

# ── 7. Install frontend deps if needed ────────────────────────────

if [ ! -d frontend/node_modules ]; then
    step "Installing frontend dependencies"
    (cd frontend && npm install --silent 2>&1 | tail -2)
    info "Frontend deps installed"
fi

# ── 8. Start backend + frontend ──────────────────────────────────

step "Launching"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  API Docs:  http://localhost:$BACKEND_PORT/api/v1/docs ${NC}"
echo -e "${GREEN}  Frontend:  http://localhost:$FRONTEND_PORT             ${NC}"
echo -e "${GREEN}  Login:     ${VULNSENTINEL_ADMIN_USERNAME:-admin} / ********           ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Press Ctrl+C to stop both services."
echo ""

cleanup() {
    echo ""
    info "Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    info "Done"
}
trap cleanup EXIT INT TERM

# Backend
uvicorn vulnsentinel.api:create_app --factory --host 0.0.0.0 --port "$BACKEND_PORT" &
BACKEND_PID=$!

# Wait for backend health before starting frontend
echo -n "  Waiting for backend..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:$BACKEND_PORT/health" > /dev/null 2>&1; then
        echo " ready"
        break
    fi
    echo -n "."
    sleep 1
done

# Frontend (NEXT_PUBLIC_API_URL points to actual backend port)
NEXT_PUBLIC_API_URL="http://localhost:$BACKEND_PORT" PORT=$FRONTEND_PORT \
    npm --prefix frontend run dev &
FRONTEND_PID=$!

wait $BACKEND_PID $FRONTEND_PID
