#!/bin/bash

# NeuroSploit v3 Startup Script

echo "================================================"
echo "  NeuroSploit v3 - AI-Powered Penetration Testing"
echo "================================================"
echo ""

# Check for .env file
if [ ! -f ".env" ]; then
    echo "[!] No .env file found. Creating from .env.example..."
    cp .env.example .env
    echo ""
    echo "=========================================="
    echo "  IMPORTANT: Configure your API key!"
    echo "=========================================="
    echo ""
    echo "Edit the .env file and add your Claude API key:"
    echo "  ANTHROPIC_API_KEY=sk-ant-..."
    echo ""
    echo "Get your API key at: https://console.anthropic.com/"
    echo ""
    read -p "Press Enter to continue (or Ctrl+C to exit and configure)..."
    echo ""
fi

# Check if API key is configured
if grep -q "^ANTHROPIC_API_KEY=$" .env 2>/dev/null || grep -q "^ANTHROPIC_API_KEY=your-" .env 2>/dev/null; then
    echo "[WARNING] ANTHROPIC_API_KEY not configured in .env"
    echo "The AI agent will not work without an API key!"
    echo ""
fi

# Check for lite mode
COMPOSE_FILE="docker-compose.yml"
if [ "$1" = "--lite" ] || [ "$1" = "-l" ]; then
    echo "[INFO] Using LITE mode (faster build, no security tools)"
    COMPOSE_FILE="docker-compose.lite.yml"
fi

# Check if docker-compose is available
if command -v docker-compose &> /dev/null; then
    echo "Starting with Docker Compose..."
    docker-compose -f $COMPOSE_FILE up -d
    echo ""
    echo "NeuroSploit is starting..."
    echo "  - Backend API: http://localhost:8000"
    echo "  - Web Interface: http://localhost:3000"
    echo "  - API Docs: http://localhost:8000/api/docs"
    echo "  - LLM Status: http://localhost:8000/api/v1/agent/status"
    echo ""
    echo "Run 'docker-compose logs -f' to view logs"
    echo ""
    echo "To check if LLM is configured:"
    echo "  curl http://localhost:8000/api/v1/agent/status"
elif command -v docker &> /dev/null && command -v docker compose &> /dev/null; then
    echo "Starting with Docker Compose (v2)..."
    docker compose -f $COMPOSE_FILE up -d
    echo ""
    echo "NeuroSploit is starting..."
    echo "  - Backend API: http://localhost:8000"
    echo "  - Web Interface: http://localhost:3000"
    echo "  - API Docs: http://localhost:8000/api/docs"
    echo "  - LLM Status: http://localhost:8000/api/v1/agent/status"
else
    echo "Docker not found. Starting manually..."
    echo ""

    # Start backend
    echo "Starting backend..."
    cd backend
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    else
        source venv/bin/activate
    fi
    python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
    BACKEND_PID=$!
    cd ..

    # Start frontend
    echo "Starting frontend..."
    cd frontend
    if [ ! -d "node_modules" ]; then
        npm install
    fi
    npm run dev &
    FRONTEND_PID=$!
    cd ..

    echo ""
    echo "NeuroSploit is running:"
    echo "  - Backend API: http://localhost:8000"
    echo "  - Web Interface: http://localhost:3000"
    echo ""
    echo "Press Ctrl+C to stop"

    # Wait for Ctrl+C
    trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
    wait
fi
