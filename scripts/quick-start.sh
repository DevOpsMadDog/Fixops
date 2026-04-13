#!/bin/bash
# ============================================
# ALdeci — Quick Start
# One-command: start everything and confirm ready
# ============================================
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

ALDECI_PORT="${ALDECI_PORT:-8000}"
ALDECI_UI_PORT="${ALDECI_UI_PORT:-3000}"
API_URL="http://localhost:${ALDECI_PORT}"
UI_URL="http://localhost:${ALDECI_UI_PORT}"

echo -e "${CYAN}Starting ALDECI Platform...${NC}"

# Ensure a default API token is available so compose doesn't abort
if [[ -z "${FIXOPS_API_TOKEN:-}" ]]; then
    export FIXOPS_API_TOKEN="aldeci-demo-$(python3 -c 'import secrets; print(secrets.token_hex(8))' 2>/dev/null || echo 'changeme')"
    echo -e "${YELLOW}No FIXOPS_API_TOKEN set — using generated demo token: ${FIXOPS_API_TOKEN}${NC}"
    echo -e "${YELLOW}Set FIXOPS_API_TOKEN in your environment or a .env file for production.${NC}"
fi

docker compose up -d

echo -e "${CYAN}Waiting for API to be ready at ${API_URL}/health ...${NC}"
elapsed=0
until curl -sf "${API_URL}/health" > /dev/null 2>&1; do
    if (( elapsed >= 60 )); then
        echo -e "\n${RED}Timed out waiting for API after ${elapsed}s.${NC}"
        echo -e "${YELLOW}Check logs with: docker compose logs aldeci${NC}"
        exit 1
    fi
    sleep 2
    elapsed=$(( elapsed + 2 ))
    echo -n "."
done
echo ""

echo -e "${GREEN}ALDECI is ready!${NC}"
echo ""
echo -e "  ${GREEN}API docs:${NC}  ${API_URL}/docs"
echo -e "  ${GREEN}API health:${NC} ${API_URL}/health"
echo -e "  ${GREEN}UI:${NC}         ${UI_URL}"
echo ""
echo -e "${CYAN}Useful commands:${NC}"
echo -e "  docker compose logs -f aldeci     # Follow API logs"
echo -e "  docker compose logs -f aldeci-ui  # Follow UI logs"
echo -e "  docker compose down               # Stop everything"
