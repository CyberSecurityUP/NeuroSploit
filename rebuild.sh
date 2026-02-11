#!/usr/bin/env bash
# ============================================================================
# NeuroSploit v3 - Rebuild & Launch Script
# ============================================================================
# Usage: chmod +x rebuild.sh && ./rebuild.sh
# Options:
#   --backend-only   Only start the backend (skip frontend)
#   --frontend-only  Only start the frontend (skip backend)
#   --build          Build frontend for production instead of dev mode
#   --install        Force reinstall all dependencies
#   --reset-db       Delete and recreate the database (for schema changes)
# ============================================================================

set -e

PROJECT_DIR="/opt/NeuroSploitv2"
VENV_DIR="$PROJECT_DIR/venv"
FRONTEND_DIR="$PROJECT_DIR/frontend"
DATA_DIR="$PROJECT_DIR/data"
LOGS_DIR="$PROJECT_DIR/logs"
PID_DIR="$PROJECT_DIR/.pids"
DB_PATH="$DATA_DIR/neurosploit.db"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse args
BACKEND_ONLY=false
FRONTEND_ONLY=false
PRODUCTION_BUILD=false
FORCE_INSTALL=false
RESET_DB=false

for arg in "$@"; do
  case $arg in
    --backend-only)  BACKEND_ONLY=true ;;
    --frontend-only) FRONTEND_ONLY=true ;;
    --build)         PRODUCTION_BUILD=true ;;
    --install)       FORCE_INSTALL=true ;;
    --reset-db)      RESET_DB=true ;;
  esac
done

header() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}  $1${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

step() {
  echo -e "${GREEN}[+]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[!]${NC} $1"
}

fail() {
  echo -e "${RED}[x]${NC} $1"
  exit 1
}

# ============================================================================
# 0. Kill previous instances
# ============================================================================
header "Stopping previous instances"

mkdir -p "$PID_DIR"

# Kill by PID files if they exist
for pidfile in "$PID_DIR"/*.pid; do
  [ -f "$pidfile" ] || continue
  pid=$(cat "$pidfile" 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    step "Stopping process $pid ($(basename "$pidfile" .pid))"
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
done

# Also kill any lingering uvicorn/vite on our ports
if lsof -ti:8000 >/dev/null 2>&1; then
  step "Killing process on port 8000"
  kill $(lsof -ti:8000) 2>/dev/null || true
fi
if lsof -ti:3000 >/dev/null 2>&1; then
  step "Killing process on port 3000"
  kill $(lsof -ti:3000) 2>/dev/null || true
fi

sleep 1
step "Previous instances stopped"

# ============================================================================
# 1. Ensure directories exist
# ============================================================================
header "Preparing directories"
mkdir -p "$DATA_DIR" "$LOGS_DIR" "$PID_DIR"
mkdir -p "$PROJECT_DIR/reports/screenshots"
mkdir -p "$PROJECT_DIR/reports/benchmark_results/logs"
step "Directories ready"

# ============================================================================
# 1b. Database reset (if requested)
# ============================================================================
if [ "$RESET_DB" = true ]; then
  header "Resetting database"
  if [ -f "$DB_PATH" ]; then
    BACKUP="$DB_PATH.backup.$(date +%Y%m%d%H%M%S)"
    step "Backing up existing DB to $BACKUP"
    cp "$DB_PATH" "$BACKUP"
    rm -f "$DB_PATH"
    step "Database deleted (will be recreated with new schema on startup)"
  else
    step "No existing database found"
  fi
fi

# ============================================================================
# 2. Environment check
# ============================================================================
header "Checking environment"

if [ ! -f "$PROJECT_DIR/.env" ]; then
  if [ -f "$PROJECT_DIR/.env.example" ]; then
    warn ".env not found, copying from .env.example"
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  else
    fail ".env file not found and no .env.example to copy from"
  fi
fi
step ".env file present"

# Check Python
if command -v python3 &>/dev/null; then
  PYTHON=python3
elif command -v python &>/dev/null; then
  PYTHON=python
else
  fail "Python not found. Install Python 3.10+"
fi
step "Python: $($PYTHON --version)"

# Check Node
if command -v node &>/dev/null; then
  step "Node: $(node --version)"
else
  if [ "$BACKEND_ONLY" = false ]; then
    fail "Node.js not found. Install Node.js 18+"
  fi
fi

# Check Docker (optional - needed for sandbox & benchmarks)
if command -v docker &>/dev/null; then
  step "Docker: $(docker --version 2>/dev/null | head -1)"
  # Check compose
  if docker compose version &>/dev/null 2>&1; then
    step "Docker Compose: plugin (docker compose)"
  elif command -v docker-compose &>/dev/null; then
    step "Docker Compose: standalone ($(docker-compose version --short 2>/dev/null))"
  else
    warn "Docker Compose not found (needed for sandbox & benchmarks)"
  fi
else
  warn "Docker not found (optional - needed for sandbox & benchmarks)"
fi

# ============================================================================
# 3. Python virtual environment & dependencies
# ============================================================================
if [ "$FRONTEND_ONLY" = false ]; then
  header "Setting up Python backend"

  if [ ! -d "$VENV_DIR" ] || [ "$FORCE_INSTALL" = true ]; then
    step "Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
  fi

  source "$VENV_DIR/bin/activate"
  step "Virtual environment activated"

  if [ "$FORCE_INSTALL" = true ] || [ ! -f "$VENV_DIR/.deps_installed" ]; then
    step "Installing backend dependencies..."
    pip install --quiet --upgrade pip

    # Install from requirements files (pyproject.toml is for tool config only)
    pip install --quiet -r "$PROJECT_DIR/backend/requirements.txt" 2>&1 | tail -5
    pip install --quiet -r "$PROJECT_DIR/requirements.txt" 2>&1 | tail -5
    touch "$VENV_DIR/.deps_installed"
    step "Core dependencies installed"

    # Try optional deps (may fail on Python <3.10)
    if [ -f "$PROJECT_DIR/requirements-optional.txt" ]; then
      step "Installing optional dependencies (best-effort)..."
      pip install --quiet -r "$PROJECT_DIR/requirements-optional.txt" 2>/dev/null && \
        step "Optional deps installed (mcp, playwright)" || \
        warn "Some optional deps skipped (Python 3.10+ required for mcp/playwright)"
    fi
  else
    step "Dependencies already installed (use --install to force)"
  fi

  # Validate key modules
  step "Validating Python modules..."
  $PYTHON -c "
import sys
modules = [
    ('backend.main', 'FastAPI app'),
    ('backend.config', 'Settings'),
    ('backend.api.v1.vuln_lab', 'VulnLab API'),
    ('backend.models.vuln_lab', 'VulnLab Model'),
    ('core.llm_manager', 'LLM Manager'),
    ('core.model_router', 'Model Router'),
    ('core.scheduler', 'Scheduler'),
    ('core.knowledge_augmentor', 'Knowledge Augmentor'),
    ('core.browser_validator', 'Browser Validator'),
    ('core.mcp_client', 'MCP Client'),
    ('core.mcp_server', 'MCP Server'),
    ('core.sandbox_manager', 'Sandbox Manager'),
    ('backend.core.agent_memory', 'Agent Memory'),
    ('backend.core.response_verifier', 'Response Verifier'),
    ('backend.core.vuln_engine.registry', 'VulnEngine Registry'),
    ('backend.core.vuln_engine.payload_generator', 'VulnEngine Payloads'),
    ('backend.core.vuln_engine.ai_prompts', 'VulnEngine AI Prompts'),
]
errors = 0
for mod, name in modules:
    try:
        __import__(mod)
        print(f'  OK  {name} ({mod})')
    except Exception as e:
        print(f'  WARN {name} ({mod}): {e}')
        errors += 1
if errors > 0:
    print(f'\n  {errors} module(s) had import warnings (optional deps may be missing)')
else:
    print('\n  All modules loaded successfully')
" 2>&1 || true

  # Validate knowledge base
  step "Validating knowledge base..."
  $PYTHON -c "
import json, os
kb_path = os.path.join('$PROJECT_DIR', 'data', 'vuln_knowledge_base.json')
if os.path.exists(kb_path):
    kb = json.load(open(kb_path))
    types = len(kb.get('vulnerability_types', {}))
    insights = len(kb.get('xbow_insights', kb.get('attack_insights', {})))
    print(f'  OK  Knowledge base: {types} vuln types, {insights} insight categories')
else:
    print('  WARN Knowledge base not found at data/vuln_knowledge_base.json')
" 2>&1 || true

  # Validate VulnEngine coverage
  step "Validating VulnEngine coverage..."
  $PYTHON -c "
from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.core.vuln_engine.payload_generator import PayloadGenerator
from backend.core.vuln_engine.ai_prompts import VULN_AI_PROMPTS
r = VulnerabilityRegistry()
p = PayloadGenerator()
total_payloads = sum(len(v) for v in p.payload_libraries.values())
print(f'  OK  Registry: {len(r.VULNERABILITY_INFO)} types, {len(r.TESTER_CLASSES)} testers')
print(f'  OK  Payloads: {total_payloads} across {len(p.payload_libraries)} categories')
print(f'  OK  AI Prompts: {len(VULN_AI_PROMPTS)} per-vuln decision prompts')
" 2>&1 || true
fi

# ============================================================================
# 4. Frontend dependencies
# ============================================================================
if [ "$BACKEND_ONLY" = false ]; then
  header "Setting up React frontend"

  cd "$FRONTEND_DIR"

  if [ ! -d "node_modules" ] || [ "$FORCE_INSTALL" = true ]; then
    step "Installing frontend dependencies..."
    npm install --silent 2>&1 | tail -3
    step "Frontend dependencies installed"
  else
    step "node_modules present (use --install to force)"
  fi

  cd "$PROJECT_DIR"
fi

# ============================================================================
# 5. Launch backend
# ============================================================================
if [ "$FRONTEND_ONLY" = false ]; then
  header "Starting FastAPI backend (port 8000)"

  source "$VENV_DIR/bin/activate"

  # Export env vars
  set -a
  source "$PROJECT_DIR/.env"
  set +a

  PYTHONPATH="$PROJECT_DIR" uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info \
    > "$LOGS_DIR/backend.log" 2>&1 &

  BACKEND_PID=$!
  echo "$BACKEND_PID" > "$PID_DIR/backend.pid"
  step "Backend started (PID: $BACKEND_PID)"
  step "Backend logs: $LOGS_DIR/backend.log"

  # Wait for backend to be ready
  step "Waiting for backend..."
  for i in $(seq 1 15); do
    if curl -s http://localhost:8000/docs >/dev/null 2>&1; then
      step "Backend is ready"
      break
    fi
    if [ $i -eq 15 ]; then
      warn "Backend may still be starting. Check logs."
    fi
    sleep 1
  done
fi

# ============================================================================
# 6. Launch frontend
# ============================================================================
if [ "$BACKEND_ONLY" = false ]; then
  header "Starting React frontend (port 3000)"

  cd "$FRONTEND_DIR"

  if [ "$PRODUCTION_BUILD" = true ]; then
    step "Building production frontend..."
    npm run build 2>&1 | tail -5
    step "Build complete. Serving from dist/"
    npx vite preview --port 3000 \
      > "$LOGS_DIR/frontend.log" 2>&1 &
  else
    step "Starting development server..."
    npx vite --port 3000 \
      > "$LOGS_DIR/frontend.log" 2>&1 &
  fi

  FRONTEND_PID=$!
  echo "$FRONTEND_PID" > "$PID_DIR/frontend.pid"
  step "Frontend started (PID: $FRONTEND_PID)"
  step "Frontend logs: $LOGS_DIR/frontend.log"

  cd "$PROJECT_DIR"

  # Wait for frontend
  for i in $(seq 1 10); do
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

# ============================================================================
# 7. Summary
# ============================================================================
header "NeuroSploit v3 is running"

echo ""
if [ "$FRONTEND_ONLY" = false ]; then
  echo -e "  ${GREEN}Backend API:${NC}    http://localhost:8000"
  echo -e "  ${GREEN}API Docs:${NC}       http://localhost:8000/docs"
  echo -e "  ${GREEN}Scheduler API:${NC}  http://localhost:8000/api/v1/scheduler/"
  echo -e "  ${GREEN}VulnLab API:${NC}    http://localhost:8000/api/v1/vuln-lab/"
fi
if [ "$BACKEND_ONLY" = false ]; then
  echo -e "  ${GREEN}Frontend UI:${NC}    http://localhost:3000"
fi
echo ""
echo -e "  ${BLUE}Logs:${NC}"
[ "$FRONTEND_ONLY" = false ] && echo -e "    Backend:  tail -f $LOGS_DIR/backend.log"
[ "$BACKEND_ONLY" = false ]  && echo -e "    Frontend: tail -f $LOGS_DIR/frontend.log"
echo ""
echo -e "  ${YELLOW}Stop:${NC}  $0 (re-run kills previous)"
echo -e "         kill \$(cat $PID_DIR/backend.pid) \$(cat $PID_DIR/frontend.pid)"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  NeuroSploit v3 - Autonomous Security Agent${NC}"
echo -e ""
echo -e "  ${BLUE}VulnEngine (100-Type):${NC}"
echo -e "  - Registry:          100 vuln types, 428 payloads, 100 testers"
echo -e "  - AI Prompts:        100 per-vuln AI decision prompts"
echo -e "  - Agent Memory:      Bounded dedup stores, baseline caching"
echo -e "  - Multi-Signal:      4-signal verification (tester+baseline+"
echo -e "                       payload_effect+error_patterns)"
echo -e "  - Payload Effect:    Baseline-compared checks (eliminates FP"
echo -e "                       for NoSQL, HPP, type juggling, HTML inj)"
echo -e "  - Anti-Hallucination: AI cross-validation, evidence grounding"
echo -e "  - Knowledge Base:    100 vuln types + insight categories"
echo -e "  - Attack Plan:       5-tier priority (P1 critical -> P5 info)"
echo -e ""
echo -e "  ${BLUE}Autonomous Agent:${NC}"
echo -e "  - Full Auto:         One-click full vulnerability assessment"
echo -e "  - Auto Pentest:      6-phase automated penetration testing"
echo -e "  - Pause/Resume/Stop: Real-time scan control (pause, resume, terminate)"
echo -e "  - MCP Server:        12 tools (screenshot, dns, port scan, etc.)"
echo -e "  - Security Sandbox:  Docker-based tool isolation (22 tools)"
echo -e "  - Benchmark Runner:  104 CTF challenges for accuracy testing"
echo -e ""
echo -e "  ${BLUE}Vulnerability Lab:${NC}"
echo -e "  - Isolated Testing:  Test individual vuln types one at a time"
echo -e "  - 100 Vuln Types:    All VulnEngine types available for testing"
echo -e "  - Lab/CTF Support:   PortSwigger, CTFs, custom targets"
echo -e "  - Auth Support:      Cookie, Bearer, Basic, Custom headers"
echo -e "  - Detection Stats:   Per-type & per-category detection rates"
echo -e "  - Challenge History: Full history with results tracking"
echo -e ""
echo -e "  ${BLUE}Verification & Reports:${NC}"
echo -e "  - Anti-FP:           Baseline-compared payload effect checks"
echo -e "  - ZIP Reports:       Download HTML report + screenshots as ZIP"
echo -e "  - OHVR Reports:      Observation-Hypothesis-Validation-Result"
echo -e "  - Severity Sorting:  Critical/High findings appear first"
echo -e ""
echo -e "  ${BLUE}Platform Features:${NC}"
echo -e "  - Scheduler:         /scheduler (cron & interval scheduling)"
echo -e "  - OpenRouter:        Settings > LLM Configuration > OpenRouter"
echo -e "  - Model Routing:     Settings > Advanced Features toggle"
echo -e "  - Knowledge Aug:     Settings > Advanced Features toggle"
echo -e "  - Browser Validation: Settings > Advanced Features toggle"
echo -e "  - Skip-to-Phase:     Agent + Scan pages (skip ahead in pipeline)"
echo -e "  - Reset DB:          ./rebuild.sh --reset-db (schema changes)"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Keep script running so bg processes stay alive
wait
