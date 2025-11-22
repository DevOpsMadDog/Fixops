#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "   FixOps Setup Wizard"
echo "========================================"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local value
    read -p "$prompt [$default]: " value
    echo "${value:-$default}"
}

prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local value
    read -p "$prompt (y/n) [$default]: " value
    value="${value:-$default}"
    [[ "$value" =~ ^[Yy] ]] && echo "true" || echo "false"
}

generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}

echo "This wizard will help you set up FixOps for your environment."
echo ""

echo "1. Select Deployment Mode"
echo "   - demo: Quick local testing with minimal setup"
echo "   - docker: Local Docker Compose deployment"
echo "   - aws: AWS EKS production deployment"
echo "   - gcp: GCP GKE production deployment"
echo "   - azure: Azure AKS production deployment"
echo ""
DEPLOYMENT_MODE=$(prompt_with_default "Deployment mode" "demo")

ENV_FILE=".env"
if [[ -f "$ENV_FILE" ]]; then
    echo -e "${YELLOW}Warning: $ENV_FILE already exists${NC}"
    OVERWRITE=$(prompt_yes_no "Overwrite existing .env file?" "n")
    if [[ "$OVERWRITE" != "true" ]]; then
        echo "Keeping existing .env file. Exiting."
        exit 0
    fi
fi

echo "" > "$ENV_FILE"

echo ""
echo "2. Core Configuration"
API_TOKEN=$(prompt_with_default "API Token (or leave blank to generate)" "")
if [[ -z "$API_TOKEN" ]]; then
    API_TOKEN=$(generate_secret)
    echo -e "${GREEN}Generated API token: $API_TOKEN${NC}"
fi
echo "FIXOPS_API_TOKEN=$API_TOKEN" >> "$ENV_FILE"
echo "FIXOPS_ENVIRONMENT=$DEPLOYMENT_MODE" >> "$ENV_FILE"

echo ""
echo "3. LLM Provider Configuration"
echo "   FixOps uses multi-LLM consensus by default for better decisions."
echo "   You can enable single-LLM mode by providing only one API key,"
echo "   or run in deterministic mode without any API keys."
echo ""

USE_LLMS=$(prompt_yes_no "Configure LLM providers?" "y")
if [[ "$USE_LLMS" == "true" ]]; then
    echo "" >> "$ENV_FILE"
    echo "# LLM Provider Configuration" >> "$ENV_FILE"
    
    ENABLE_OPENAI=$(prompt_yes_no "Enable OpenAI GPT?" "y")
    echo "FIXOPS_ENABLE_OPENAI=$ENABLE_OPENAI" >> "$ENV_FILE"
    if [[ "$ENABLE_OPENAI" == "true" ]]; then
        OPENAI_KEY=$(prompt_with_default "OpenAI API Key (optional)" "")
        [[ -n "$OPENAI_KEY" ]] && echo "OPENAI_API_KEY=$OPENAI_KEY" >> "$ENV_FILE"
    fi
    
    ENABLE_ANTHROPIC=$(prompt_yes_no "Enable Anthropic Claude?" "y")
    echo "FIXOPS_ENABLE_ANTHROPIC=$ENABLE_ANTHROPIC" >> "$ENV_FILE"
    if [[ "$ENABLE_ANTHROPIC" == "true" ]]; then
        ANTHROPIC_KEY=$(prompt_with_default "Anthropic API Key (optional)" "")
        [[ -n "$ANTHROPIC_KEY" ]] && echo "ANTHROPIC_API_KEY=$ANTHROPIC_KEY" >> "$ENV_FILE"
    fi
    
    ENABLE_GEMINI=$(prompt_yes_no "Enable Google Gemini?" "y")
    echo "FIXOPS_ENABLE_GEMINI=$ENABLE_GEMINI" >> "$ENV_FILE"
    if [[ "$ENABLE_GEMINI" == "true" ]]; then
        GEMINI_KEY=$(prompt_with_default "Google API Key (optional)" "")
        [[ -n "$GEMINI_KEY" ]] && echo "GOOGLE_API_KEY=$GEMINI_KEY" >> "$ENV_FILE"
    fi
    
    ENABLE_SENTINEL=$(prompt_yes_no "Enable Sentinel?" "y")
    echo "FIXOPS_ENABLE_SENTINEL=$ENABLE_SENTINEL" >> "$ENV_FILE"
    if [[ "$ENABLE_SENTINEL" == "true" ]]; then
        SENTINEL_KEY=$(prompt_with_default "Sentinel API Key (optional)" "")
        [[ -n "$SENTINEL_KEY" ]] && echo "SENTINEL_API_KEY=$SENTINEL_KEY" >> "$ENV_FILE"
    fi
else
    echo "" >> "$ENV_FILE"
    echo "# LLM Provider Configuration - Deterministic Mode" >> "$ENV_FILE"
    echo "FIXOPS_ENABLE_OPENAI=false" >> "$ENV_FILE"
    echo "FIXOPS_ENABLE_ANTHROPIC=false" >> "$ENV_FILE"
    echo "FIXOPS_ENABLE_GEMINI=false" >> "$ENV_FILE"
    echo "FIXOPS_ENABLE_SENTINEL=false" >> "$ENV_FILE"
fi

echo ""
echo "4. External Integrations (Optional)"
CONFIGURE_INTEGRATIONS=$(prompt_yes_no "Configure Jira/Confluence/Slack?" "n")
if [[ "$CONFIGURE_INTEGRATIONS" == "true" ]]; then
    echo "" >> "$ENV_FILE"
    echo "# Integration Tokens" >> "$ENV_FILE"
    
    JIRA_TOKEN=$(prompt_with_default "Jira Token (optional)" "")
    [[ -n "$JIRA_TOKEN" ]] && echo "FIXOPS_JIRA_TOKEN=$JIRA_TOKEN" >> "$ENV_FILE"
    
    CONFLUENCE_TOKEN=$(prompt_with_default "Confluence Token (optional)" "")
    [[ -n "$CONFLUENCE_TOKEN" ]] && echo "FIXOPS_CONFLUENCE_TOKEN=$CONFLUENCE_TOKEN" >> "$ENV_FILE"
    
    SLACK_WEBHOOK=$(prompt_with_default "Slack Webhook URL (optional)" "")
    [[ -n "$SLACK_WEBHOOK" ]] && echo "FIXOPS_SLACK_WEBHOOK_URL=$SLACK_WEBHOOK" >> "$ENV_FILE"
fi

if [[ "$DEPLOYMENT_MODE" != "demo" ]]; then
    echo ""
    echo "5. Database Configuration"
    echo "" >> "$ENV_FILE"
    echo "# Database Configuration" >> "$ENV_FILE"
    
    MONGO_USER=$(prompt_with_default "MongoDB Username" "fixops")
    MONGO_PASS=$(prompt_with_default "MongoDB Password (or leave blank to generate)" "")
    if [[ -z "$MONGO_PASS" ]]; then
        MONGO_PASS=$(generate_secret)
        echo -e "${GREEN}Generated MongoDB password${NC}"
    fi
    echo "MONGO_USERNAME=$MONGO_USER" >> "$ENV_FILE"
    echo "MONGO_PASSWORD=$MONGO_PASS" >> "$ENV_FILE"
    
    REDIS_PASS=$(prompt_with_default "Redis Password (or leave blank to generate)" "")
    if [[ -z "$REDIS_PASS" ]]; then
        REDIS_PASS=$(generate_secret)
        echo -e "${GREEN}Generated Redis password${NC}"
    fi
    echo "REDIS_PASSWORD=$REDIS_PASS" >> "$ENV_FILE"
    
    SECRET_KEY=$(prompt_with_default "Application Secret Key (or leave blank to generate)" "")
    if [[ -z "$SECRET_KEY" ]]; then
        SECRET_KEY=$(generate_secret)
        echo -e "${GREEN}Generated application secret key${NC}"
    fi
    echo "SECRET_KEY=$SECRET_KEY" >> "$ENV_FILE"
fi

echo ""
echo "========================================="
echo -e "${GREEN}✅ Configuration Complete!${NC}"
echo "========================================="
echo ""
echo "Configuration saved to: $ENV_FILE"
echo ""
echo "Next steps:"
echo "  1. Review and edit $ENV_FILE if needed"
echo "  2. Run: ./scripts/bootstrap.sh"
echo "  3. Start API: uvicorn apps.api.app:create_app --factory --reload"
echo ""
