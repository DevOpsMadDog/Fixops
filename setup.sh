#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ALdeci FixOps CTEM+ Enterprise — One-Command Setup
# ─────────────────────────────────────────────────────────────
# Usage: ./setup.sh
# Requires: Python 3.11+, Node.js 20+, npm
# ─────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║   ALdeci FixOps CTEM+ Enterprise Platform        ║"
echo "║   One-Command Production Setup                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check prerequisites ─────────────────────────────────────
echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"
command -v python3 >/dev/null 2>&1 || { echo -e "${RED}Python 3.11+ required${NC}"; exit 1; }
command -v node >/dev/null 2>&1 || { echo -e "${RED}Node.js 20+ required${NC}"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo -e "${RED}npm required${NC}"; exit 1; }
echo -e "${GREEN}  ✓ Python $(python3 --version | cut -d' ' -f2)${NC}"
echo -e "${GREEN}  ✓ Node $(node --version)${NC}"

# ── Generate secrets if not set ──────────────────────────────
echo -e "${YELLOW}[2/7] Configuring secrets...${NC}"
if [ -z "$FIXOPS_API_TOKEN" ]; then
  export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(f'fixops_sk_{secrets.token_urlsafe(32)}')")
  echo -e "${GREEN}  ✓ Generated API token: ${FIXOPS_API_TOKEN:0:20}...${NC}"
else
  echo -e "${GREEN}  ✓ Using existing API token${NC}"
fi

if [ -z "$FIXOPS_JWT_SECRET" ]; then
  export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  echo -e "${GREEN}  ✓ Generated JWT secret${NC}"
else
  echo -e "${GREEN}  ✓ Using existing JWT secret${NC}"
fi

export FIXOPS_MODE=enterprise
export FIXOPS_DISABLE_RATE_LIMIT=0

# ── Install Python dependencies ──────────────────────────────
echo -e "${YELLOW}[3/7] Installing Python dependencies...${NC}"
pip install -r requirements.txt -q
echo -e "${GREEN}  ✓ Python dependencies installed${NC}"

# ── Install Node dependencies (root — for serve.js) ─────────
echo -e "${YELLOW}[4/7] Installing Node dependencies (production server)...${NC}"
npm install --production -q
echo -e "${GREEN}  ✓ Production server dependencies installed${NC}"

# ── Build frontend ───────────────────────────────────────────
echo -e "${YELLOW}[5/7] Building frontend...${NC}"
cd suite-ui/aldeci-ui-new
npm install -q
npx vite build
cd ../..
echo -e "${GREEN}  ✓ Frontend built${NC}"

# ── Set PYTHONPATH ───────────────────────────────────────────
export PYTHONPATH="$(pwd)/suite-api:$(pwd)/suite-api/apps:$(pwd):$(pwd)/suite-core:$(pwd)/suite-attack:$(pwd)/suite-evidence-risk:$(pwd)/suite-integrations"

# ── Start API backend ────────────────────────────────────────
echo -e "${YELLOW}[6/7] Starting API backend (port 8000)...${NC}"
python3 -m uvicorn api.app:create_app \
  --factory --host 0.0.0.0 --port 8000 \
  --app-dir suite-api/apps \
  --log-level info &
API_PID=$!

# Wait for API
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ API backend ready (PID: $API_PID)${NC}"
    break
  fi
  sleep 1
done

# ── Start production server ──────────────────────────────────
echo -e "${YELLOW}[7/7] Starting production server (port 3000)...${NC}"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗"
echo -e "║                                                  ║"
echo -e "║   ALdeci FixOps CTEM+ is LIVE                    ║"
echo -e "║                                                  ║"
echo -e "║   → http://localhost:3000                        ║"
echo -e "║                                                  ║"
echo -e "║   API Token: $FIXOPS_API_TOKEN  ║"
echo -e "║                                                  ║"
echo -e "║   Press Ctrl+C to stop                           ║"
echo -e "║                                                  ║"
echo -e "╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Trap Ctrl+C to cleanup
trap "echo ''; echo 'Shutting down...'; kill $API_PID 2>/dev/null; exit 0" INT TERM

node serve.js
