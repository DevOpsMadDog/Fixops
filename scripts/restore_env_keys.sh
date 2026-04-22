#!/usr/bin/env bash
# Restore the MuleRouter/OpenRouter keys that got stripped from .env.
# Per /Users/devops.ai/.claude/projects/-Users-devops-ai-fixops-Fixops/memory/project_mulerouter_key.md
# Usage: MULEROUTER_KEY=<paste-key> bash scripts/restore_env_keys.sh

set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${MULEROUTER_KEY:-}" ]; then
    echo "ERROR: set MULEROUTER_KEY env var with the key before running this script."
    echo "Example: MULEROUTER_KEY=sk-... bash scripts/restore_env_keys.sh"
    exit 1
fi

# Guard against appending duplicates
if grep -q "^MULEROUTER_API_KEY=" .env 2>/dev/null; then
    echo "MULEROUTER_API_KEY already present in .env — updating in place"
    sed -i.bak "s|^MULEROUTER_API_KEY=.*|MULEROUTER_API_KEY=${MULEROUTER_KEY}|" .env
    sed -i.bak "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=${MULEROUTER_KEY}|" .env
else
    echo "Appending MuleRouter block to .env"
    cat >> .env <<EOF

# --- MuleRouter / OpenRouter (Qwen 3.6 Plus / qwen3-6b-max) ---
# Restored $(date -u +%Y-%m-%d) after .env corruption. Source: project_mulerouter_key memory.
MULEROUTER_API_KEY=${MULEROUTER_KEY}
OPENROUTER_API_KEY=${MULEROUTER_KEY}
MULEROUTER_BASE_URL=https://mulerouter.ai/api/v1
MULEROUTER_DEFAULT_MODEL=qwen/qwen3-6b-max
EOF
fi

echo "Done. Verifying..."
grep -E "^(MULEROUTER|OPENROUTER)" .env | sed 's/=.*/=***REDACTED***/'
