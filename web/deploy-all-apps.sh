#!/bin/bash
set -e

APPS=(
  "dashboard"
  "triage"
  "risk-graph"
  "findings"
  "compliance"
  "evidence"
  "saved-views"
  "automations"
  "integrations"
  "settings"
  "users"
  "teams"
  "inventory"
  "policies"
  "reports"
  "audit"
  "workflows"
  "sso"
  "secrets"
  "iac"
  "bulk"
  "pentagi"
)

echo "Deploying all 22 apps..."
for app in "${APPS[@]}"; do
  echo "Deploying $app..."
  devin deploy frontend "apps/$app/out"
done

echo "All 22 apps deployed successfully!"
