#!/usr/bin/env bash
# =============================================================================
# ALDECI — Kubernetes Deployment Script
# =============================================================================
# Usage:
#   ./scripts/deploy-k8s.sh [ENVIRONMENT] [OPTIONS]
#
# Environments:
#   dev   — deploys to aldeci-dev namespace with reduced resources
#   prod  — deploys to aldeci namespace with production settings
#
# Options:
#   --dry-run       Print what would be applied without making changes
#   --skip-secrets  Skip secret validation (for CI where secrets are injected)
#   --force         Apply even if validation warnings exist
#   --help          Show this help message
#
# Prerequisites:
#   - kubectl configured and pointing at target cluster
#   - kustomize >= 5.0 OR kubectl >= 1.27 (has built-in kustomize)
#   - Secrets pre-populated (see docker/kubernetes/secrets.yaml template)
#
# Examples:
#   ./scripts/deploy-k8s.sh dev
#   ./scripts/deploy-k8s.sh prod --dry-run
#   ./scripts/deploy-k8s.sh prod --force
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLUE}[deploy]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# ── Defaults ──────────────────────────────────────────────────────────────────
ENVIRONMENT="${1:-dev}"
DRY_RUN=false
SKIP_SECRETS=false
FORCE=false

# ── Parse options ─────────────────────────────────────────────────────────────
shift 2>/dev/null || true
for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY_RUN=true ;;
    --skip-secrets) SKIP_SECRETS=true ;;
    --force)        FORCE=true ;;
    --help)
      sed -n '/^# Usage/,/^# =====/p' "$0" | head -n -1
      exit 0
      ;;
    *) err "Unknown option: $arg"; exit 1 ;;
  esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
K8S_DIR="${REPO_ROOT}/docker/kubernetes"

case "$ENVIRONMENT" in
  dev)
    OVERLAY_DIR="${K8S_DIR}/overlays/dev"
    NAMESPACE="aldeci-dev"
    ;;
  prod)
    OVERLAY_DIR="${K8S_DIR}/overlays/prod"
    NAMESPACE="aldeci"
    ;;
  *)
    err "Unknown environment: '${ENVIRONMENT}'. Use 'dev' or 'prod'."
    exit 1
    ;;
esac

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  ALDECI Kubernetes Deployment${NC}"
echo -e "${BLUE}  Environment : ${GREEN}${ENVIRONMENT}${NC}"
echo -e "${BLUE}  Namespace   : ${GREEN}${NAMESPACE}${NC}"
echo -e "${BLUE}  Dry Run     : ${DRY_RUN}${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────
log "Checking prerequisites..."

if ! command -v kubectl &>/dev/null; then
  err "kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"
  exit 1
fi

KUBECTL_VERSION=$(kubectl version --client -o json 2>/dev/null | python3 -c "import sys,json; v=json.load(sys.stdin)['clientVersion']; print(f\"{v['major']}.{v['minor']}\")" 2>/dev/null || echo "unknown")
ok "kubectl ${KUBECTL_VERSION}"

# Check cluster connectivity
if ! kubectl cluster-info &>/dev/null; then
  err "Cannot reach Kubernetes cluster. Check your kubeconfig."
  exit 1
fi

CONTEXT=$(kubectl config current-context)
ok "Cluster context: ${CONTEXT}"

# ── Production guard ──────────────────────────────────────────────────────────
if [[ "$ENVIRONMENT" == "prod" && "$FORCE" != "true" ]]; then
  warn "You are deploying to PRODUCTION."
  read -rp "Type 'yes' to confirm: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    log "Aborted."
    exit 0
  fi
fi

# ── Secrets validation ────────────────────────────────────────────────────────
if [[ "$SKIP_SECRETS" != "true" ]]; then
  log "Validating secrets are populated..."

  SECRET_FILE="${K8S_DIR}/secrets.yaml"
  if grep -q "CHANGE_ME" "$SECRET_FILE" 2>/dev/null; then
    if [[ "$FORCE" == "true" ]]; then
      warn "secrets.yaml still contains CHANGE_ME placeholders. Continuing with --force."
    else
      err "secrets.yaml contains CHANGE_ME placeholder values."
      err "Populate real secrets before deploying, or use --skip-secrets if using external secret injection."
      err "Generate secrets:"
      err "  JWT:        openssl rand -base64 48 | base64"
      err "  API token:  openssl rand -hex 32 | base64"
      exit 1
    fi
  else
    ok "Secrets file looks populated."
  fi
fi

# ── Kustomize build ───────────────────────────────────────────────────────────
log "Building kustomize manifests from ${OVERLAY_DIR}..."

if command -v kustomize &>/dev/null; then
  KUSTOMIZE_CMD="kustomize build"
else
  KUSTOMIZE_CMD="kubectl kustomize"
fi

# Validate YAML before applying
if ! $KUSTOMIZE_CMD "${OVERLAY_DIR}" > /dev/null 2>&1; then
  err "Kustomize build failed. Check your overlay configuration."
  $KUSTOMIZE_CMD "${OVERLAY_DIR}" || true
  exit 1
fi

ok "Kustomize build succeeded."

# ── Namespace pre-create ──────────────────────────────────────────────────────
log "Ensuring namespace '${NAMESPACE}' exists..."
if [[ "$DRY_RUN" == "true" ]]; then
  log "[dry-run] Would create namespace ${NAMESPACE}"
else
  kubectl apply -f "${K8S_DIR}/namespace.yaml" || true
fi

# ── Apply manifests ───────────────────────────────────────────────────────────
log "Applying manifests..."

KUBECTL_APPLY_ARGS=("apply" "-f" "-")
if [[ "$DRY_RUN" == "true" ]]; then
  KUBECTL_APPLY_ARGS+=("--dry-run=client")
fi

$KUSTOMIZE_CMD "${OVERLAY_DIR}" | kubectl "${KUBECTL_APPLY_ARGS[@]}"

if [[ "$DRY_RUN" == "true" ]]; then
  ok "Dry run complete. No changes were made."
  exit 0
fi

# ── Wait for rollout ──────────────────────────────────────────────────────────
log "Waiting for API deployment rollout..."
kubectl rollout status deployment/aldeci-api -n "${NAMESPACE}" --timeout=300s

log "Waiting for UI deployment rollout..."
kubectl rollout status deployment/aldeci-ui -n "${NAMESPACE}" --timeout=120s

# ── Health check ──────────────────────────────────────────────────────────────
log "Running post-deploy health check..."

API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "app.kubernetes.io/name=aldeci-api" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$API_POD" ]]; then
  HEALTH=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -sf http://localhost:8000/health 2>/dev/null || echo "FAILED")
  if echo "$HEALTH" | grep -qi "ok\|healthy\|true"; then
    ok "API health check passed (pod: ${API_POD})"
  else
    warn "API health check returned unexpected response: ${HEALTH}"
  fi
else
  warn "Could not find running API pod to health-check."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Deployment complete!${NC}"
echo -e "${GREEN}============================================================${NC}"

echo ""
log "Resources in namespace '${NAMESPACE}':"
kubectl get all -n "${NAMESPACE}" 2>/dev/null | grep -E "^(NAME|pod|service|deployment|replicaset|horizontalpodautoscaler|cronjob)" || true

echo ""
log "Ingress:"
kubectl get ingress -n "${NAMESPACE}" 2>/dev/null || true

echo ""
ok "Done. ALDECI is deployed."
