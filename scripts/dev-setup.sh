#!/bin/bash
# FixOps Development Setup Script
# Run: chmod +x scripts/dev-setup.sh && ./scripts/dev-setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "==================================================="
echo "FixOps Development Environment Setup"
echo "==================================================="

cd "$PROJECT_ROOT"

# Backend setup
echo ""
echo "[1/4] Installing backend dependencies..."
pip install -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt

echo ""
echo "[2/4] Backend ready!"

# Frontend setup
echo ""
echo "[3/4] Installing frontend dependencies..."
cd "$PROJECT_ROOT/ui/aldeci"
npm install

echo ""
echo "[4/4] Frontend ready!"

echo ""
echo "==================================================="
echo "Setup Complete!"
echo "==================================================="
echo ""
echo "To start the application:"
echo ""
echo "  Backend (Terminal 1):"
echo "    cd $PROJECT_ROOT"
echo "    python -m uvicorn backend.app:create_app --factory --reload --port 8000"
echo ""
echo "  Frontend (Terminal 2):"
echo "    cd $PROJECT_ROOT/ui/aldeci"
echo "    npm run dev"
echo ""
echo "API Documentation: http://localhost:8000/docs"
echo "Frontend: http://localhost:5173"
echo "==================================================="
