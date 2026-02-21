# ALdeci UI Screen → API Mapping

> Generated: 2026-02-05  
> Total Screens: 31 | Total API Endpoints: 90+

---

## 🖥️ CORE SCREENS

### Dashboard (`/dashboard`)
**File:** `pages/Dashboard.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.dashboard.getOverview()` | `GET /api/v1/analytics/dashboard/overview` | Main dashboard stats |
| `api.dashboard.getTrends()` | `GET /api/v1/analytics/dashboard/trends` | Trend charts data |
| `api.dashboard.getTopRisks()` | `GET /api/v1/analytics/dashboard/top-risks` | Critical risks list |
| `api.dashboard.getComplianceStatus()` | `GET /api/v1/analytics/dashboard/compliance-status` | Compliance overview |
| `api.dashboard.getMTTR()` | `GET /api/v1/analytics/mttr` | Mean time to remediate |

### Copilot (`/copilot`)
**File:** `pages/Copilot.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.copilot.chat.createSession()` | `POST /api/v1/copilot/sessions` | Start new chat session |
| `api.copilot.chat.sendMessage()` | `POST /api/v1/copilot/sessions/{id}/messages` | Send message to AI |
| `api.copilot.chat.getSessions()` | `GET /api/v1/copilot/sessions` | List all sessions |
| `api.copilot.agents.analyst.analyze()` | `POST /api/v1/copilot/agents/analyst/analyze` | AI security analysis |
| `api.copilot.agents.pentest.validate()` | `POST /api/v1/copilot/agents/pentest/validate` | AI pentest validation |

---

## 📦 CODE SUITE (`/code/*`)

### Code Scanning (`/code/code-scanning`)
**File:** `pages/code/CodeScanning.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.code.scanning.ingestSARIF()` | `POST /inputs/sarif` | Upload SARIF results |
| `api.code.scanning.ingestSBOM()` | `POST /inputs/sbom` | Upload SBOM file |

### Secrets Detection (`/code/secrets-detection`)
**File:** `pages/code/SecretsDetection.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.code.secrets.list()` | `GET /api/v1/secrets` | List detected secrets |
| `api.code.secrets.resolve()` | `POST /api/v1/secrets/{id}/resolve` | Mark secret resolved |
| `api.code.secrets.scanContent()` | `POST /api/v1/secrets/scan/content` | Scan content for secrets |

### IaC Scanning (`/code/iac-scanning`)
**File:** `pages/code/IaCScanning.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.code.iac.list()` | `GET /api/v1/iac` | List IaC findings |
| `api.code.iac.scanContent()` | `POST /api/v1/iac/scan/content` | Scan IaC content |

### Inventory (`/code/inventory`)
**File:** `pages/code/Inventory.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.code.inventory.getApplications()` | `GET /api/v1/inventory/applications` | List applications |
| `api.code.inventory.getAssets()` | `GET /api/v1/inventory/assets` | List all assets |
| `api.code.inventory.search()` | `GET /api/v1/inventory/search` | Search inventory |

---

## ☁️ CLOUD SUITE (`/cloud/*`)

### Cloud Posture (`/cloud/cloud-posture`)
**File:** `pages/cloud/CloudPosture.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.cloud.cspm.getFindings()` | `GET /api/v1/analytics/findings?source=cnapp` | CSPM findings |
| `api.cloud.cspm.ingestCNAPP()` | `POST /inputs/cnapp` | Upload CNAPP data |

### Threat Feeds (`/cloud/threat-feeds`)
**File:** `pages/cloud/ThreatFeeds.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.cloud.feeds.getEPSS()` | `GET /api/v1/feeds/epss` | EPSS probability scores |
| `api.cloud.feeds.getKEV()` | `GET /api/v1/feeds/kev` | Known Exploited Vulns |
| `api.cloud.feeds.getExploits()` | `GET /api/v1/feeds/exploits` | Exploit database |
| `api.cloud.feeds.getThreatActors()` | `GET /api/v1/feeds/threat-actors` | Threat actor intel |

### Correlation Engine (`/cloud/correlation`)
**File:** `pages/cloud/CorrelationEngine.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.cloud.correlation.getClusters()` | `GET /api/v1/deduplication/clusters` | Dedup clusters |
| `api.cloud.correlation.getCluster()` | `GET /api/v1/deduplication/clusters/{id}` | Cluster details |
| `api.cloud.correlation.processFinding()` | `POST /api/v1/deduplication/process` | Process finding |

---

## ⚔️ ATTACK SUITE (`/attack/*`)

### MPTE Console (`/attack/mpte`) ← **CURRENT FILE**
**File:** `pages/attack/MPTEConsole.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.attack.mpte.getRequests()` | `GET /api/v1/mpte/requests` | List pentest requests |
| `api.attack.mpte.createRequest()` | `POST /api/v1/mpte/requests` | Create new request |
| `api.attack.mpte.getResults()` | `GET /api/v1/mpte/results` | Get pentest results |
| `api.attack.mpte.verify()` | `POST /api/v1/mpte/verify` | Verify CVE exploitability |

### Micro Pentest (`/attack/micro-pentest`)
**File:** `pages/attack/MicroPentest.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.attack.microPentest.run()` | `POST /api/v1/micro-pentest/run` | Run quick exploit check |
| `api.attack.microPentest.getStatus()` | `GET /api/v1/micro-pentest/status/{flowId}` | Check status |

### Attack Simulation (`/attack/attack-simulation`)
**File:** `pages/attack/AttackSimulation.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.attack.simulation.simulateAttack()` | `POST /api/v1/predictions/simulate-attack` | Run attack sim |
| `api.attack.simulation.attackChain()` | `POST /api/v1/predictions/attack-chain` | Get attack chain |

### Attack Paths (`/attack/attack-paths`)
**File:** `pages/attack/AttackPaths.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.cloud.attackPath.getGraph()` | `GET /graph/` | Risk graph data |
| `api.cloud.attackPath.analyzeSurface()` | `POST /api/v1/algorithms/gnn/attack-surface` | GNN analysis |
| `api.cloud.attackPath.getCriticalNodes()` | `POST /api/v1/algorithms/gnn/critical-nodes` | Critical nodes |

### Reachability (`/attack/reachability`)
**File:** `pages/attack/Reachability.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.attack.reachability.analyze()` | `POST /api/v1/reachability/analyze` | Analyze CVE reachability |
| `api.attack.reachability.getResults()` | `GET /api/v1/reachability/results/{cveId}` | Get results |

---

## 🛡️ PROTECT SUITE (`/protect/*`)

### Remediation (`/protect/remediation`)
**File:** `pages/protect/Remediation.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.protect.remediation.getTasks()` | `GET /api/v1/remediation/tasks` | List remediation tasks |
| `api.protect.remediation.createTask()` | `POST /api/v1/remediation/tasks` | Create new task |
| `api.protect.remediation.generateFix()` | `POST /api/v1/enhanced/analysis` | AI-generated fix |
| `api.protect.remediation.createPR()` | `POST /api/v1/webhooks/alm/work-items` | Create PR |

### Bulk Operations (`/protect/bulk-operations`)
**File:** `pages/protect/BulkOperations.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.protect.bulk.updateFindings()` | `POST /api/v1/bulk/findings/update` | Bulk update |
| `api.protect.bulk.assignClusters()` | `POST /api/v1/bulk/clusters/assign` | Bulk assign |

### Workflows (`/protect/workflows`)
**File:** `pages/protect/Workflows.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.protect.workflows.list()` | `GET /api/v1/workflows` | List workflows |
| `api.protect.workflows.execute()` | `POST /api/v1/workflows/{id}/execute` | Execute workflow |

### Collaboration (`/protect/collaboration`)
**File:** `pages/protect/Collaboration.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.protect.collaboration.getComments()` | `GET /api/v1/collaboration/comments` | Get comments |
| `api.protect.collaboration.addComment()` | `POST /api/v1/collaboration/comments` | Add comment |
| `api.protect.collaboration.getNotifications()` | `GET /api/v1/collaboration/notifications/pending` | Pending notifs |

### Integrations (`/protect/integrations`)
**File:** `pages/protect/Integrations.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.integrations.list()` | `GET /api/v1/integrations` | List integrations |
| `api.settings.integrations.test()` | `POST /api/v1/integrations/{id}/test` | Test connection |

---

## 🤖 AI ENGINE (`/ai-engine/*`)

### Multi-LLM (`/ai-engine/multi-llm`)
**File:** `pages/ai-engine/MultiLLMPage.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.ai.llm.getStatus()` | `GET /api/v1/llm/status` | LLM status |
| `api.ai.llm.getProviders()` | `GET /api/v1/llm/providers` | Available LLMs |
| `api.ai.consensus.compareLLMs()` | `POST /api/v1/enhanced/compare-llms` | Compare outputs |

### Algorithmic Lab (`/ai-engine/algorithmic-lab`)
**File:** `pages/ai-engine/AlgorithmicLab.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.ai.labs.monteCarloQuantify()` | `POST /api/v1/algorithms/monte-carlo/quantify` | FAIR quantification |
| `api.ai.labs.causalAnalyze()` | `POST /api/v1/algorithms/causal/analyze` | Causal inference |

### Predictions (`/ai-engine/predictions`)
**File:** `pages/ai-engine/Predictions.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.ai.predictions.riskTrajectory()` | `POST /api/v1/predictions/risk-trajectory` | Risk forecast |

### Policies (`/ai-engine/policies`)
**File:** `pages/ai-engine/Policies.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.ai.policies.list()` | `GET /api/v1/policies` | List policies |
| `api.ai.policies.validate()` | `POST /api/v1/policies/{id}/validate` | Validate policy |

---

## 📋 EVIDENCE (`/evidence/*`)

### Evidence Bundles (`/evidence/bundles`)
**File:** `pages/evidence/EvidenceBundles.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.evidence.bundles.list()` | `GET /evidence/` | List bundles |
| `api.evidence.bundles.get()` | `GET /evidence/{release}` | Get bundle details |
| `api.evidence.bundles.verify()` | `POST /evidence/verify` | Verify SLSA |

### Audit Logs (`/evidence/audit-logs`)
**File:** `pages/evidence/AuditLogs.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.evidence.audit.getLogs()` | `GET /api/v1/audit/logs` | Get audit trail |
| `api.evidence.audit.complianceFrameworks()` | `GET /api/v1/audit/compliance/frameworks` | List frameworks |

### Reports (`/evidence/reports`)
**File:** `pages/evidence/Reports.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.evidence.reports.list()` | `GET /api/v1/reports` | List reports |
| `api.evidence.reports.generate()` | `POST /api/v1/reports/generate` | Generate report |

### Compliance Reports (`/evidence/compliance`)
**File:** `pages/evidence/ComplianceReports.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.evidence.analytics.getFindings()` | `GET /api/v1/analytics/findings` | Findings data |
| `api.evidence.analytics.getDecisions()` | `GET /api/v1/analytics/decisions` | Decision history |

---

## ⚙️ SETTINGS (`/settings/*`)

### Users (`/settings/users`)
**File:** `pages/settings/Users.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.access.users()` | `GET /api/v1/users` | List users |

### Teams (`/settings/teams`)
**File:** `pages/settings/Teams.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.access.teams()` | `GET /api/v1/teams` | List teams |

### Integrations (`/settings/integrations`)
**File:** `pages/settings/IntegrationsSettings.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.integrations.list()` | `GET /api/v1/integrations` | List integrations |
| `api.settings.integrations.test()` | `POST /api/v1/integrations/{id}/test` | Test integration |

### Marketplace (`/settings/marketplace`)
**File:** `pages/settings/Marketplace.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.marketplace.browse()` | `GET /api/v1/marketplace/browse` | Browse items |
| `api.settings.marketplace.install()` | `POST /api/v1/marketplace/purchase/{id}` | Install item |

### System Health (`/settings/system-health`)
**File:** `pages/settings/SystemHealth.tsx`
| API Method | Backend Endpoint | Purpose |
|------------|------------------|---------|
| `api.settings.system.health()` | `GET /health` | Health check |
| `api.settings.system.version()` | `GET /api/v1/version` | Version info |

---

## 🧪 Testing APIs

To test APIs locally, start the backend:

```bash
cd /Users/devops.ai/developement/fixops/Fixops
uvicorn backend.app:create_app --reload --port 8000
```

Test with curl:

```bash
# Health check
curl http://localhost:8000/health

# MPTE requests (current screen)
curl -H "X-API-Key: demo-token" http://localhost:8000/api/v1/mpte/requests

# Deduplication clusters
curl -H "X-API-Key: demo-token" http://localhost:8000/api/v1/deduplication/clusters

# Evidence bundles
curl -H "X-API-Key: demo-token" http://localhost:8000/evidence/

# Risk graph
curl -H "X-API-Key: demo-token" http://localhost:8000/graph/
```

---

## 📊 Coverage Summary

| Suite | Screens | API Endpoints |
|-------|---------|---------------|
| Core | 2 | 10 |
| Code Suite | 4 | 12 |
| Cloud Suite | 3 | 15 |
| Attack Suite | 5 | 14 |
| Protect Suite | 5 | 12 |
| AI Engine | 4 | 10 |
| Evidence | 4 | 8 |
| Settings | 5 | 9 |
| **TOTAL** | **32** | **90+** |
