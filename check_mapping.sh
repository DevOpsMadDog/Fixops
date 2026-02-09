#!/bin/bash
cd /Users/devops.ai/developement/fixops/Fixops

FILES=(
  "risk/enrichment.py"
  "risk/forecasting.py"
  "risk/threat_model.py"
  "risk/scoring.py"
  "risk/feeds/epss.py"
  "risk/feeds/kev.py"
  "risk/feeds/orchestrator.py"
  "compliance/__init__.py"
  "compliance/mapping.py"
  "services/match/indexes.py"
  "services/match/join.py"
  "services/match/utils.py"
  "services/provenance/attestation.py"
  "new_backend/processing/__init__.py"
  "new_backend/processing/bayesian.py"
  "new_backend/processing/explanation.py"
  "new_backend/processing/knowledge_graph.py"
  "new_backend/processing/sarif.py"
  "telemetry/__init__.py"
  "backend/__init__.py"
  "backend/app.py"
  "backend/normalizers.py"
  "fixops/utils/__init__.py"
  "fixops/utils/paths.py"
  "core/evidence.py"
  "core/modules.py"
  "core/probabilistic.py"
  "core/sarif_canon.py"
  "core/stage_runner.py"
  "apps/api/routes/enhanced.py"
  "apps/api/upload_manager.py"
  "apps/api/middleware.py"
  "simulations/cve_scenario/runner.py"
)

for f in "${FILES[@]}"; do
  result=$(find . -path "*/$f" -not -path '*/node_modules/*' -not -path '*/__pycache__/*' -not -path '*/archive/*' 2>/dev/null | head -1)
  if [ -n "$result" ]; then
    echo "FOUND: $f -> $result"
  else
    arch=$(find . -path "*/$f" -not -path '*/node_modules/*' -not -path '*/__pycache__/*' 2>/dev/null | head -1)
    if [ -n "$arch" ]; then
      echo "ARCHIVE_ONLY: $f -> $arch"
    else
      echo "MISSING: $f"
    fi
  fi
done

echo ""
echo "=== git remote commit check ==="
git rev-parse ce6eb1e9 2>/dev/null && echo "Commit ce6eb1e9 exists locally" || echo "Commit ce6eb1e9 NOT found locally"
echo ""
echo "=== fixops-enterprise on remote ==="
git ls-tree -r --name-only ce6eb1e9 2>/dev/null | grep '^fixops-enterprise/' | head -30
echo "COUNT: $(git ls-tree -r --name-only ce6eb1e9 2>/dev/null | grep '^fixops-enterprise/' | wc -l)"

