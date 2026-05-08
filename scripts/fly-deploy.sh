#!/bin/bash
# ALDECI Fly.io deploy quick-start
# Usage: ./scripts/fly-deploy.sh [region]  (default: syd)
set -euo pipefail

REGION="${1:-syd}"
APP_NAME="${ALDECI_APP_NAME:-aldeci}"

echo "=== ALDECI Fly.io Deploy ==="
echo "App: $APP_NAME · Region: $REGION"
echo ""

# 1. Check flyctl
if ! command -v flyctl &> /dev/null; then
  echo "ERROR: flyctl not installed."
  echo "Install: curl -L https://fly.io/install.sh | sh"
  echo "Then: flyctl auth login"
  exit 1
fi

# 2. Check auth
if ! flyctl auth whoami &> /dev/null; then
  echo "ERROR: not logged in. Run: flyctl auth login"
  exit 1
fi

# 3. Create app if missing (idempotent)
if ! flyctl apps list 2>/dev/null | grep -q "^${APP_NAME}\b"; then
  echo "Creating Fly app '${APP_NAME}' in ${REGION}..."
  flyctl apps create "$APP_NAME" --org personal
else
  echo "App '${APP_NAME}' already exists. Skipping create."
fi

# 4. Set secrets (idempotent — only sets if missing in env)
echo ""
echo "Setting secrets (skip lines for already-set secrets)..."
for var in FIXOPS_API_TOKEN FIXOPS_JWT_SECRET ANTHROPIC_API_KEY OPENROUTER_API_KEY \
           FIXOPS_SMTP_HOST FIXOPS_SMTP_USER FIXOPS_SMTP_PASS FIXOPS_SMTP_FROM \
           FIXOPS_SLACK_WEBHOOK_URL FIXOPS_STRIPE_SECRET_KEY \
           FIXOPS_STRIPE_WEBHOOK_SECRET; do
  if [ -n "${!var:-}" ]; then
    echo "  setting $var"
    flyctl secrets set "${var}=${!var}" --app "$APP_NAME" --stage
  fi
done
flyctl secrets deploy --app "$APP_NAME" 2>/dev/null || true

# 5. Create volume if missing
if ! flyctl volumes list --app "$APP_NAME" 2>/dev/null | grep -q "aldeci_data"; then
  echo ""
  echo "Creating 10GB volume in ${REGION}..."
  flyctl volumes create aldeci_data --size 10 --region "$REGION" --app "$APP_NAME" --yes
fi

# 6. Deploy
echo ""
echo "Deploying..."
flyctl deploy --remote-only --app "$APP_NAME"

# 7. Status
echo ""
echo "=== Deploy complete ==="
flyctl status --app "$APP_NAME"
echo ""
echo "URL: https://${APP_NAME}.fly.dev"
echo "Logs: flyctl logs --app $APP_NAME"
echo "Custom domain: flyctl certs create yourdomain.com --app $APP_NAME"
