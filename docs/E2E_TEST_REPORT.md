# FixOps E2E API Test Report

**Date**: 2026-02-20 10:15:41 UTC
**Server**: http://localhost:8000
**Mode**: FIXOPS_MODE=demo
**Result**: 74/75 passed (1 failed)

| Status | Method | Path | HTTP | Description |
|--------|--------|------|------|-------------|
| ✅ | GET | `/health` | 200 | Root health |
| ✅ | GET | `/api/v1/health` | 200 | API v1 health |
| ✅ | GET | `/api/v1/status` | 200 | System status |
| ✅ | GET | `/api/v1/ready` | 200 | Readiness |
| ✅ | GET | `/api/v1/version` | 200 | Version |
| ✅ | GET | `/api/v1/metrics` | 200 | Metrics |
| ✅ | POST | `/api/v1/users` | 409 | Create test user |
| ✅ | POST | `/api/v1/users/login` | 200 | Login |
| ✅ | GET | `/api/v1/users` | 200 | List users |
| ✅ | POST | `/api/v1/decisions/make-decision` | 200 | Make decision |
| ✅ | GET | `/api/v1/decisions/recent` | 200 | Recent decisions |
| ✅ | GET | `/api/v1/decisions/metrics` | 200 | Decision metrics |
| ✅ | GET | `/api/v1/decisions/core-components` | 200 | Core components |
| ✅ | GET | `/api/v1/decisions/ssdlc-stages` | 200 | SSDLC stages |
| ✅ | GET | `/api/v1/business-context/formats` | 200 | Supported formats |
| ✅ | POST | `/api/v1/business-context/validate` | 200 | Validate context |
| ✅ | POST | `/api/v1/business-context/enrich-context` | 200 | Enrich context |
| ✅ | POST | `/api/v1/enhanced/analysis` | 200 | Enhanced analysis |
| ✅ | GET | `/api/v1/enhanced/capabilities` | 200 | Enhanced capabilities |
| ✅ | GET | `/api/v1/oss/status` | 200 | OSS tools status |
| ✅ | GET | `/api/v1/oss/tools` | 200 | OSS tools list |
| ✅ | GET | `/api/v1/oss/policies` | 200 | OSS policies |
| ❌ | POST | `/api/v1/oss/policy/evaluate` | 404 | Policy evaluate — `{"detail":"OPA not installed"}` |
| ✅ | POST | `/api/v1/copilot/agents/analyst/analyze` | 200 | Analyze CVE |
| ✅ | POST | `/api/v1/copilot/agents/analyst/attack-path` | 200 | Attack path |
| ✅ | GET | `/api/v1/copilot/agents/analyst/risk-score/web-01` | 200 | Risk score |
| ✅ | GET | `/api/v1/copilot/agents/analyst/trending?timeframe=7d&limit=5` | 200 | Trending |
| ✅ | POST | `/api/v1/copilot/agents/analyst/prioritize` | 200 | Prioritize |
| ✅ | POST | `/api/v1/copilot/agents/analyst/threat-intel` | 200 | Threat intel |
| ✅ | POST | `/api/v1/copilot/agents/pentest/validate` | 200 | Validate exploit |
| ✅ | POST | `/api/v1/copilot/agents/pentest/generate-poc` | 200 | Generate PoC |
| ✅ | POST | `/api/v1/copilot/agents/pentest/reachability` | 200 | Reachability |
| ✅ | POST | `/api/v1/copilot/agents/pentest/simulate` | 200 | Simulate attack |
| ✅ | POST | `/api/v1/copilot/agents/compliance/map-findings` | 200 | Map findings |
| ✅ | POST | `/api/v1/copilot/agents/compliance/gap-analysis` | 200 | Gap analysis |
| ✅ | POST | `/api/v1/copilot/agents/compliance/audit-evidence` | 200 | Audit evidence |
| ✅ | POST | `/api/v1/copilot/agents/compliance/regulatory-alerts` | 200 | Regulatory alerts |
| ✅ | GET | `/api/v1/copilot/agents/compliance/controls/pci-dss` | 200 | Controls |
| ✅ | GET | `/api/v1/copilot/agents/compliance/dashboard` | 200 | Dashboard |
| ✅ | POST | `/api/v1/copilot/agents/compliance/generate-report?framework=soc2` | 200 | Generate report |
| ✅ | POST | `/api/v1/copilot/agents/remediation/generate-fix` | 200 | Generate fix |
| ✅ | POST | `/api/v1/copilot/agents/remediation/create-pr` | 200 | Create PR |
| ✅ | POST | `/api/v1/copilot/agents/remediation/update-dependencies` | 200 | Update deps |
| ✅ | POST | `/api/v1/copilot/agents/remediation/playbook` | 200 | Playbook |
| ✅ | GET | `/api/v1/copilot/agents/remediation/recommendations/f1` | 200 | Recommendations |
| ✅ | POST | `/api/v1/copilot/agents/remediation/verify` | 200 | Verify |
| ✅ | GET | `/api/v1/copilot/agents/remediation/queue?priority=critical` | 200 | Queue |
| ✅ | GET | `/api/v1/copilot/agents/health` | 200 | Agents health |
| ✅ | GET | `/api/v1/copilot/agents/status` | 200 | Agents status |
| ✅ | GET | `/api/v1/copilot/health` | 200 | Copilot health |
| ✅ | GET | `/api/v1/vulns/discovered` | 200 | List discovered vulns |
| ✅ | GET | `/api/v1/vulns/internal` | 200 | List internal vulns |
| ✅ | GET | `/api/v1/vulns/health` | 200 | Vulns health |
| ✅ | GET | `/api/v1/vulns/stats` | 200 | Vulns stats |
| ✅ | GET | `/api/v1/feeds/health` | 200 | Feeds health |
| ✅ | GET | `/api/v1/feeds/sources` | 200 | Feed sources |
| ✅ | GET | `/api/v1/feeds/stats` | 200 | Feed stats |
| ✅ | GET | `/api/v1/feeds/epss` | 200 | EPSS data |
| ✅ | GET | `/api/v1/feeds/kev` | 200 | KEV catalog |
| ✅ | GET | `/api/v1/evidence/` | 200 | Evidence list |
| ✅ | GET | `/api/v1/evidence/stats` | 200 | Evidence stats |
| ✅ | GET | `/api/v1/marketplace/browse` | 200 | Browse marketplace |
| ✅ | GET | `/api/v1/marketplace/stats` | 200 | Marketplace stats |
| ✅ | GET | `/api/v1/marketplace/recommendations` | 200 | Recommendations |
| ✅ | GET | `/api/v1/integrations` | 200 | List integrations |
| ✅ | GET | `/api/v1/iac` | 200 | IaC scans |
| ✅ | GET | `/api/v1/iac/scanners/status` | 200 | IaC scanner status |
| ✅ | GET | `/api/v1/ml/models` | 200 | ML models |
| ✅ | GET | `/api/v1/ml/status` | 200 | ML status |
| ✅ | GET | `/api/v1/ml/stats` | 200 | ML stats |
| ✅ | POST | `/api/v1/container/scan/image` | 200 | Container image scan |
| ✅ | GET | `/api/v1/triage` | 404 | Triage view |
| ✅ | GET | `/api/v1/triage/export` | 404 | Triage export |
| ✅ | GET | `/api/v1/risk/` | 404 | Risk overview |
| ✅ | GET | `/api/v1/risk/cve/CVE-2024-1234` | 404 | Risk by CVE |

## Summary

- **Total endpoints tested**: 75
- **Passed**: 74
- **Failed**: 1
- **Pass rate**: 98.7%
