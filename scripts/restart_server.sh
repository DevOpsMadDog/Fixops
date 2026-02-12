#!/bin/bash
cd /Users/devops.ai/developement/fixops/Fixops

echo "=== Killing old server ==="
pkill -f "uvicorn.*apps.api" 2>/dev/null
sleep 2

echo "=== Clearing __pycache__ ==="
find . -name "__pycache__" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/.git/*" -exec rm -rf {} + 2>/dev/null

echo "=== Starting server ==="
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy"
export PYTHONDONTWRITEBYTECODE=1
export FIXOPS_MODE=enterprise
export DEMO_MODE=false
export FIXOPS_JWT_SECRET="test-jwt-secret-key-1234567890"
export FIXOPS_API_TOKEN=test-token-123
export FIXOPS_AUTH_MODE=dev
export FIXOPS_BRAIN_DB_PATH=".fixops_data/brain.db"
export FIXOPS_DATA_DIR=".fixops_data"

# Load API keys from .env file (LLM providers need these)
if [ -f .env ]; then
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
        # Only export API key variables
        case "$key" in
            OPENAI_API_KEY|FIXOPS_OPENAI_KEY|ANTHROPIC_API_KEY|FIXOPS_ANTHROPIC_KEY|GOOGLE_API_KEY|FIXOPS_GOOGLE_KEY|FIXOPS_GEMINI_KEY)
                export "$key=$value"
                ;;
        esac
    done < .env
fi

nohup .venv/bin/uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --log-level info > /tmp/fixops_server.log 2>&1 &
echo "Server PID=$!"

echo "=== Waiting for startup ==="
sleep 6

echo "=== Server log (last 5 lines) ==="
tail -5 /tmp/fixops_server.log

echo ""
echo "=== Health check ==="
curl -s -o /dev/null -w "Backend: HTTP %{http_code}\n" http://localhost:8000/api/v1/health
curl -s -o /dev/null -w "Frontend: HTTP %{http_code}\n" http://localhost:3001/

