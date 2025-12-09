#!/bin/bash
# Start FixOps API Server for local testing

set -e

echo "🚀 Starting FixOps API Server..."

# Set environment variables
export FIXOPS_API_TOKEN=${FIXOPS_API_TOKEN:-"test-api-key-12345"}
export FIXOPS_ENABLE_OPENAI=${FIXOPS_ENABLE_OPENAI:-"false"}
export FIXOPS_ENABLE_ANTHROPIC=${FIXOPS_ENABLE_ANTHROPIC:-"false"}
export FIXOPS_ENABLE_GEMINI=${FIXOPS_ENABLE_GEMINI:-"false"}
export FIXOPS_ENABLE_SENTINEL=${FIXOPS_ENABLE_SENTINEL:-"false"}

# Database URL (use SQLite for testing)
export DATABASE_URL=${DATABASE_URL:-"sqlite:///./fixops_test.db"}

# Redis URL (optional for testing)
export REDIS_URL=${REDIS_URL:-""}

# Start server
cd "$(dirname "$0")/.."

echo "📡 API Server will be available at: http://localhost:8000"
echo "🔑 API Key: $FIXOPS_API_TOKEN"
echo ""
echo "Starting server..."

python -m uvicorn apps.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
