#!/usr/bin/env bash
# ============================================================================
# NeuroSploit v3 — Rebuild & Launch (Claude 4.6)
# ============================================================================
# ./rebuild.sh                        Default (backend + frontend)
# ./rebuild.sh --backend-only         Skip frontend
# ./rebuild.sh --frontend-only        Skip backend
# ./rebuild.sh --model MODEL          Override LLM model
# ./rebuild.sh --install              Force reinstall dependencies
# ./rebuild.sh --reset-db             Delete + recreate database
# ./rebuild.sh --build                Production frontend build
# ./rebuild.sh --port 9000            Custom backend port
# ============================================================================

set -e

DIR="/opt/NeuroSploitv2"
VENV="$DIR/venv"
FRONT="$DIR/frontend"
LOGS="$DIR/logs"
PIDS="$DIR/.pids"
DB="$DIR/data/neurosploit.db"

# ── Colors ───────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' C='\033[0;36m' N='\033[0m'
header() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
ok()     { echo -e "  ${G}✓${N} $1"; }
warn()   { echo -e "  ${Y}!${N} $1"; }
fail()   { echo -e "  ${R}✗${N} $1"; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────
BACK_ONLY=false; FRONT_ONLY=false; BUILD=false; INSTALL=false; RESET=false
MODEL=""; PORT=8000; FPORT=3000

while [[ $# -gt 0 ]]; do
  case $1 in
    --backend-only)  BACK_ONLY=true;  shift ;;
    --frontend-only) FRONT_ONLY=true; shift ;;
    --build)         BUILD=true;      shift ;;
    --install)       INSTALL=true;    shift ;;
    --reset-db)      RESET=true;      shift ;;
    --model)         MODEL="$2";      shift 2 ;;
    --port)          PORT="$2";       shift 2 ;;
    --frontend-port) FPORT="$2";     shift 2 ;;
    *) shift ;;
  esac
done

# ── 0. Stop previous ────────────────────────────────────────────────
header "Stopping previous"
mkdir -p "$PIDS" "$LOGS" "$DIR/data" "$DIR/reports/screenshots"

for f in "$PIDS"/*.pid; do
  [ -f "$f" ] || continue
  pid=$(cat "$f" 2>/dev/null)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && ok "Stopped $(basename "$f" .pid)"
  rm -f "$f"
done
lsof -ti:$PORT  >/dev/null 2>&1 && kill $(lsof -ti:$PORT)  2>/dev/null || true
lsof -ti:$FPORT >/dev/null 2>&1 && kill $(lsof -ti:$FPORT) 2>/dev/null || true
sleep 1

# ── 1. Database reset ───────────────────────────────────────────────
if [ "$RESET" = true ] && [ -f "$DB" ]; then
  header "Reset database"
  cp "$DB" "$DB.bak.$(date +%s)"
  rm -f "$DB"
  ok "DB backed up and deleted"
fi

# ── 2. Environment check ────────────────────────────────────────────
header "Environment"

[ -f "$DIR/.env" ] || { [ -f "$DIR/.env.example" ] && cp "$DIR/.env.example" "$DIR/.env" && warn "Created .env from example"; } || fail "No .env"
ok ".env"

PY=$(command -v python3 || command -v python) || fail "Python not found"
ok "Python: $($PY --version 2>&1)"

if [ "$BACK_ONLY" = false ]; then
  command -v node &>/dev/null || fail "Node.js not found"
  ok "Node: $(node --version)"
fi

command -v docker &>/dev/null && ok "Docker: available" || warn "Docker: not found (sandbox disabled)"

# ── 3. Backend setup ────────────────────────────────────────────────
if [ "$FRONT_ONLY" = false ]; then
  header "Backend"

  [ -d "$VENV" ] && [ "$INSTALL" = false ] || { $PY -m venv "$VENV"; ok "Venv created"; }
  source "$VENV/bin/activate"

  if [ "$INSTALL" = true ] || [ ! -f "$VENV/.ok" ]; then
    pip install -q --upgrade pip
    pip install -q -r "$DIR/backend/requirements.txt" 2>&1 | tail -3
    pip install -q -r "$DIR/requirements.txt" 2>&1 | tail -3
    [ -f "$DIR/requirements-optional.txt" ] && pip install -q -r "$DIR/requirements-optional.txt" 2>/dev/null || true
    touch "$VENV/.ok"
    ok "Dependencies installed"
  else
    ok "Dependencies cached"
  fi

  # Quick validation
  $PY -c "
import sys; sys.path.insert(0,'$DIR')
mods = ['backend.main','backend.config','backend.core.autonomous_agent','backend.core.md_agent',
        'backend.core.smart_router.router','backend.core.vuln_engine.registry']
ok=err=0
for m in mods:
    try: __import__(m); ok+=1
    except: err+=1
print(f'  {ok}/{ok+err} core modules OK')
" 2>&1 || true
fi

# ── 4. Frontend setup ───────────────────────────────────────────────
if [ "$BACK_ONLY" = false ]; then
  header "Frontend"
  cd "$FRONT"
  if [ ! -d "node_modules" ] || [ "$INSTALL" = true ]; then
    npm install --silent 2>&1 | tail -3
    ok "Dependencies installed"
  else
    ok "Dependencies cached"
  fi
  cd "$DIR"
fi

# ── 5. Launch backend ───────────────────────────────────────────────
if [ "$FRONT_ONLY" = false ]; then
  header "Starting backend :$PORT"
  source "$VENV/bin/activate"
  set -a; source "$DIR/.env"; set +a

  [ -n "$MODEL" ] && export DEFAULT_LLM_MODEL="$MODEL" && ok "Model: $MODEL"

  PYTHONPATH="$DIR" uvicorn backend.main:app \
    --host 0.0.0.0 --port $PORT --reload --log-level info \
    > "$LOGS/backend.log" 2>&1 &
  echo $! > "$PIDS/backend.pid"
  ok "PID: $(cat "$PIDS/backend.pid")"

  for i in $(seq 1 15); do
    curl -s "http://localhost:$PORT/docs" >/dev/null 2>&1 && break
    sleep 1
  done
fi

# ── 6. Launch frontend ──────────────────────────────────────────────
if [ "$BACK_ONLY" = false ]; then
  header "Starting frontend :$FPORT"
  cd "$FRONT"
  if [ "$BUILD" = true ]; then
    npm run build 2>&1 | tail -3
    npx vite preview --port $FPORT > "$LOGS/frontend.log" 2>&1 &
  else
    npx vite --port $FPORT > "$LOGS/frontend.log" 2>&1 &
  fi
  echo $! > "$PIDS/frontend.pid"
  ok "PID: $(cat "$PIDS/frontend.pid")"
  cd "$DIR"
fi

# ── 7. Summary ──────────────────────────────────────────────────────
echo ""
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "${G}  NeuroSploit v3 — Agent-First AI Pentest Platform${N}"
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
[ "$FRONT_ONLY" = false ] && {
  echo -e "  ${G}API${N}        http://localhost:$PORT"
  echo -e "  ${G}Docs${N}       http://localhost:$PORT/docs"
  echo -e "  ${G}Model${N}      ${MODEL:-claude-sonnet-4-6-20250918}"
}
[ "$BACK_ONLY" = false ] && echo -e "  ${G}Frontend${N}   http://localhost:$FPORT"
echo ""
echo -e "  ${B}Architecture${N}"
echo -e "  ├─ 108 AI agents (real HTTP testing, PLAN→EXECUTE→ANALYZE)"
echo -e "  ├─ 100 vulnerability types + validation pipeline"
echo -e "  ├─ Claude 4.6: Opus, Sonnet 4.6, Sonnet 4.5, Haiku 4.5"
echo -e "  ├─ 20 LLM providers (auto-failover)"
echo -e "  └─ Agent-first flow: Recon (20%) → Agent Grid (65%) → Report (15%)"
echo ""
echo -e "  ${B}Auto Pentest Flow${N}"
echo -e "   0-20%   Recon: endpoints, tech stack, WAF, params, CVEs"
echo -e "  20-85%   Agent Grid: 108 agents execute real HTTP tests"
echo -e "  85-100%  Finalization: chains, screenshots, AI report"
echo ""
echo -e "  ${Y}Logs${N}   tail -f $LOGS/backend.log"
echo -e "  ${Y}Stop${N}   kill \$(cat $PIDS/backend.pid $PIDS/frontend.pid 2>/dev/null)"
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""

wait
