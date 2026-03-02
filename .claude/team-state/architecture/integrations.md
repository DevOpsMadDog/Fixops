# Integration Architecture — ALdeci CTEM+ Platform

**Last Updated**: 2026-03-02 (evening, Run 7) by enterprise-architect
**Pillars**: V7 (MCP-Native), V3 (Decision Intelligence), V9 (Air-Gapped)
**ADR Reference**: ADR-009 (MCP Auto-Discovery Architecture)

---

## 1. Integration Summary

ALdeci integrates with external systems in three modes:

| Mode | Direction | Count | Pattern |
|------|-----------|-------|---------|
| **Outbound Connectors** | ALdeci → Tool | 7 | `_BaseConnector` subclass |
| **Security Connectors** | ALdeci → Scanner API | 10 | `_BaseConnector` subclass |
| **Inbound Parsers** | Scanner → ALdeci | 15 | Webhook normalizer class |
| **Webhook Receivers** | External → ALdeci | 4 | HMAC-verified webhook endpoints |
| **MCP Gateway** | AI Agent → ALdeci | 705 tools | JSON-RPC auto-discovered |
| **Threat Feeds** | Public DB → ALdeci | 4 | Pull + cache |
| **Total Integration Points** | | **32 connectors + 705 MCP tools** | |

---

## 2. Outbound Connectors (7)

**File**: `suite-core/core/connectors.py` (3,005 LOC)
**Pattern**: All inherit `_BaseConnector` with retry, circuit-breaker, rate-limit.

| Connector | Auth | Calls From ALdeci | Failure Mode |
|-----------|------|-------------------|-------------|
| **Jira** | API Token | Create/update issues, sync status | Ticket creation queued locally |
| **Confluence** | API Token | Publish reports, update spaces | Report saved locally |
| **Slack** | Bot Token | Send alerts, channel notifications | Alert buffered in EventBus |
| **ServiceNow** | OAuth2 | Create incidents, sync CMDB | Incident queued locally |
| **GitLab** | Personal Access Token | Create MRs, push branches | MR data saved locally |
| **Azure DevOps** | PAT | Create work items, push code | Work items queued |
| **GitHub** | App/PAT | Create PRs, push branches | PR data saved locally |

### Auth Pattern
```python
class JiraConnector(_BaseConnector):
    def __init__(self, settings):
        super().__init__(timeout=15.0)
        self.base_url = settings.get("base_url")
        self.token = os.getenv(settings.get("token_env")) or settings.get("token")
```

### Circuit Breaker
- 3 consecutive failures → circuit OPEN (30s cooldown)
- Half-open after cooldown → 1 probe request
- Success → circuit CLOSED

---

## 3. Security Connectors (10)

**File**: `suite-core/core/security_connectors.py` (1,335 LOC)
**Pattern**: Inherit `_BaseConnector`, fetch vulnerability data from scanner APIs.

| Connector | Auth | Pulls From | Data Type |
|-----------|------|-----------|-----------|
| **Snyk** | API Token | REST API v1 | SCA + SAST findings |
| **SonarQube** | Token | Web API 10.x | Code quality issues |
| **Dependabot** | GitHub Token | GraphQL/REST | Dependency alerts |
| **AWS Security Hub** | IAM/boto3 | SecurityHub API | Cloud findings |
| **Azure Defender** | Service Principal | REST API | Cloud security alerts |
| **Wiz** | API Token | GraphQL API | Cloud security posture |
| **Prisma Cloud** | Access Key | REST API | CSPM findings |
| **Orca** | API Token | REST API | Cloud workload findings |
| **Lacework** | API Key | REST API | Cloud activity findings |
| **ThreatMapper** | API Key | REST API | Runtime threats |

### Data Flow
```
Security Connector → Fetch from scanner API → Normalize → Brain Pipeline Step 1
```

### Fallback (V9 Air-Gapped)
When external scanner APIs are unreachable:
1. Use cached last-known data (SQLite persistence)
2. Fall back to 8 native scanners (SAST, DAST, Secrets, Container, CSPM, API Fuzzer, etc.)
3. Accept manual file upload via scanner-ingest endpoints

---

## 4. Inbound Parsers (15)

**File**: `suite-core/core/scanner_parsers.py` (1,100+ LOC, defusedxml hardened)
**API**: `suite-api/apps/api/scanner_ingest_router.py` (388 LOC)
**Pattern**: Webhook normalizer — scanner pushes output to ALdeci.

| Parser | Scanner | Formats | Category |
|--------|---------|---------|----------|
| ZAPNormalizer | OWASP ZAP | JSON, XML | DAST |
| BurpNormalizer | Burp Suite | XML | DAST |
| NessusNormalizer | Nessus | XML | Infrastructure |
| OpenVASNormalizer | OpenVAS/GVM | XML | Infrastructure |
| BanditNormalizer | Bandit | JSON | SAST |
| **CheckmarxNormalizer** | Checkmarx | JSON, XML | SAST |
| **SonarQubeNormalizer** | SonarQube | JSON | SAST |
| **FortifyNormalizer** | Fortify | FPR/XML, JSON | SAST |
| **VeracodeNormalizer** | Veracode | JSON, XML | SAST |
| NiktoNormalizer | Nikto | JSON | DAST |
| NucleiNormalizer | Nuclei | JSONL | DAST |
| NmapNormalizer | Nmap | XML | Infrastructure |
| **SnykNormalizer** | Snyk | JSON | SCA |
| ProwlerNormalizer | Prowler | JSONL | Cloud |
| CheckovNormalizer | Checkov | JSON | Cloud/IaC |

### Ingestion Flow
```
CI/CD Pipeline → POST /api/v1/scanner-ingest/webhook/{type}
              → scanner_parsers.py normalizer (defusedxml for XML)
              → List[UnifiedFinding]
              → (optional) Brain Pipeline Step 1
```

### Auto-Detection
ALdeci can auto-detect scanner type from output content:
```bash
# No need to specify scanner type
curl -X POST /api/v1/scanner-ingest/upload \
  -F "file=@scan-output.json"
# Response: {"detected": "checkmarx", "confidence": 0.95}
```

### Security (Updated 2026-03-02)
- XML parsing uses `defusedxml.defuse_stdlib()` for XXE protection
- Primary parser: `defusedxml.ElementTree.fromstring`
- Fallback: regex DOCTYPE/ENTITY stripping + stdlib parser
- Size limits: 100 MB for XML and JSON inputs
- All 142 parser tests passing

---

## 5. Webhook Receivers (4)

**File**: `suite-integrations/api/webhooks_router.py` (1,800+ LOC)
**Pattern**: HMAC signature verification, no API key required.

| Receiver | Source | Auth | Handler |
|----------|--------|------|---------|
| `/api/v1/webhooks/jira` | Jira | HMAC-SHA256 | Issue sync |
| `/api/v1/webhooks/servicenow` | ServiceNow | HMAC-SHA256 | Incident sync |
| `/api/v1/webhooks/gitlab` | GitLab | X-Gitlab-Token header | MR/pipeline events |
| `/api/v1/webhooks/azure-devops` | Azure DevOps | Token header | Work item events |

### Security
- Uses `hmac.compare_digest()` for constant-time comparison (prevents timing attacks)
- Secrets stored in environment variables
- No API key required (webhook authentication is signature-based per industry standard)

---

## 6. MCP Gateway (V7) — See ADR-009

**Files**:
- `suite-api/apps/api/mcp_router.py` (977 LOC) — Auto-discovery router
- `suite-core/core/mcp_server.py` (979 LOC) — Protocol engine
- `suite-integrations/api/mcp_protocol_router.py` — JSON-RPC adapter
**Protocol**: JSON-RPC 2.0 over HTTP (stdio + SSE + WebSocket transports)

### Two Subsystems
1. **Auto-Discovery Router** (`/api/v1/mcp/*`): Introspects all FastAPI routes at startup, generates typed MCP tool definitions. 705 tools from 769 routes.
2. **Protocol Engine** (`/api/v1/mcp-protocol/*`): Full MCP 2024-11-05 JSON-RPC 2.0 implementation with session management, resources, and prompt templates.

### What Calls ALdeci (External AI Agents)
```
AI Agent → POST /api/v1/mcp-protocol/rpc → JSON-RPC request
        → MCPProtocolHandler dispatches
        → tools/list → returns 705 tool definitions
        → tools/call → executes any ALdeci endpoint
```

### Tools Auto-Discovery (Startup-time, cached)
- 705 tools auto-generated from 769 API endpoints at startup (~50ms)
- Each tool maps to one REST endpoint with typed inputSchema
- Categories: query (GET), action (POST), analysis (keyword-based)
- Schema exported via `GET /api/v1/mcp/tools` (paginated, filterable)
- Refreshable via `POST /api/v1/mcp/refresh`

### Honesty Note
The 705 tools are ALdeci's own endpoints (self-discovered, not external). Real auto-discovery from live routes, but self-referential.

### Security
- All MCP endpoints require API key authentication
- Tool execution is subject to same auth/scope as the underlying endpoint
- Rate limited (120 req/min shared with all other endpoints)
- Session-based capability negotiation via `initialize`

---

## 7. Threat Feeds (suite-feeds)

**File**: `suite-feeds/api/feeds_router.py` (31 endpoints)
**Pattern**: Pull from public databases, cache locally.

| Feed | Source | Update Frequency | Air-Gapped Fallback |
|------|--------|-----------------|---------------------|
| NVD | nvd.nist.gov | Daily | Bundled snapshot |
| KEV | CISA | Daily | Bundled snapshot |
| EPSS | FIRST.org | Daily | Bundled snapshot |
| OSV | osv.dev | On-demand | Bundled snapshot |

---

## 8. External Services

| Service | Port | Purpose | Required |
|---------|------|---------|----------|
| MPTE Engine | 8443 | External micro-pentest service | Optional (built-in fallback) |
| MindsDB | 47334 | ML model serving | Optional (deterministic fallback) |
| vLLM | 8001 | Self-hosted LLM (V9) | Optional (cloud LLM fallback) |
| FalkorDB | 6379 | Graph database | Optional (in-memory fallback) |

---

## 9. Failure Modes & Recovery

| Scenario | Impact | Recovery |
|----------|--------|----------|
| LLM API timeout | Step 9 fails | Deterministic fallback scoring |
| MPTE unreachable | Step 10 fails | Skip pentest, mark unvalidated |
| Scanner API down | No new pull data | Use cached data + file upload |
| Redis down | No caching | Direct DB queries |
| FalkorDB down | No graph queries | In-memory graph computation |
| Internet down | No feeds/LLMs | Full air-gapped mode (V9) |

**Design Principle**: Every external dependency has an offline fallback. ALdeci degrades gracefully, never crashes.

---

## 10. API Contract Summary

### ALdeci Calls OUT
| Destination | Protocol | Auth | Timeout | Retry |
|-------------|----------|------|---------|-------|
| Jira/Confluence | REST HTTPS | API Token | 15s | 3x with backoff |
| Slack | REST HTTPS | Bot Token | 10s | 3x with backoff |
| GitHub/GitLab/Azure | REST HTTPS | PAT | 15s | 3x with backoff |
| ServiceNow | REST HTTPS | OAuth2 | 15s | 3x with backoff |
| Scanner APIs (10) | REST HTTPS | Various | 30s | 3x with backoff |
| LLM APIs | REST HTTPS | API Key | 60s | 2x |
| Threat Feeds | REST HTTPS | None/API Key | 30s | 3x |

### External Systems Call IN
| Source | Protocol | Auth | Rate Limit |
|--------|----------|------|-----------|
| Webhook providers | REST HTTPS | HMAC Signature | 120/min |
| CI/CD scanners | REST HTTPS | API Key | 120/min |
| AI Agents (MCP) | JSON-RPC over HTTPS | API Key | 120/min |
| User browsers | HTTPS | JWT | 120/min |

---

*Maintained by enterprise-architect. Serves pillars: V3, V7, V9.*
