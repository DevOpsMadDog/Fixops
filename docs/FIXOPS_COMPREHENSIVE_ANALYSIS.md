# FixOps / ALdeci — Comprehensive Codebase Analysis

> **Generated**: 2025 | **Scope**: Every suite, every file, every interconnection  
> **Total Python files**: 428 (suites) + 239 (tests) + ~60 (scripts)  
> **Total TypeScript/TSX**: 95 (frontend)  
> **Estimated total LOC**: ~120,000+  
> **Total API endpoints**: 689 raw (640 unique) across 66 router files (55 unique)
>
> **⚠️ Code-verified**: All findings verified against actual source code. Items marked ~~strikethrough~~ were determined to be false positives after code verification. Finding count: **36 confirmed** (4 false positives removed from original 28, 12 new from router audit).  
> **📋 Per-endpoint detail**: See [ROUTER_ENDPOINT_INVENTORY.md](ROUTER_ENDPOINT_INVENTORY.md) for the full endpoint-by-endpoint table.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Import System — sitecustomize.py](#2-import-system--sitecustomizepy)
3. [suite-core — The Brain](#3-suite-core--the-brain)
4. [suite-api — FastAPI Gateway](#4-suite-api--fastapi-gateway)
5. [suite-attack — Offensive Security](#5-suite-attack--offensive-security)
6. [suite-feeds — Threat Intelligence](#6-suite-feeds--threat-intelligence)
7. [suite-evidence-risk — Compliance & Risk](#7-suite-evidence-risk--compliance--risk)
8. [suite-integrations — External Connectors](#8-suite-integrations--external-connectors)
9. [suite-ui — React Frontend](#9-suite-ui--react-frontend)
10. [Testing Infrastructure](#10-testing-infrastructure)
11. [Build & DevOps](#11-build--devops)
12. [Cross-Suite Data Flow](#12-cross-suite-data-flow) ← expanded: 7 interaction flows, full dependency graph, data store map
13. [Critical Bugs & Security Vulnerabilities](#13-critical-bugs--security-vulnerabilities) ← 36 confirmed issues
14. [Architectural Concerns](#14-architectural-concerns)
15. [Recommendations](#15-recommendations) ← 24 prioritized actions
16. [Big Picture — How 640 Unique Endpoints Connect](#16-big-picture--how-640-unique-endpoints-connect) ← system map, data flows, maturity breakdown

---

## 1. Architecture Overview

FixOps is a **7-suite monolith** — a security platform that combines vulnerability scanning, penetration testing, threat intelligence, risk scoring, evidence management, and remediation into a single deployable unit.

```
┌─────────────────────────────────────────────────────────┐
│                    suite-ui (React SPA)                  │
│                   Port 3001 (Vite dev)                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│              suite-api (FastAPI Gateway)                 │
│                     Port 8000                           │
│    27 routers in app.py / 66 router files total         │
│                                                         │
├──────────┬──────────┬──────────┬────────────────────────┤
│suite-core│suite-    │suite-    │suite-evidence-risk     │
│(Brain,   │attack    │feeds     │(Compliance, Evidence,  │
│Pipeline, │(MPTE,    │(NVD,     │ Reachability, SBOM,    │
│Decision, │DAST,     │CISA KEV, │ Runtime Protection,    │
│Connectors│SAST,     │EPSS,     │ Risk Scoring)          │
│Event Bus)│Fuzzer)   │CERTs)    │                        │
├──────────┴──────────┤          ├────────────────────────┤
│  suite-integrations │          │                        │
│  (GitHub, Jenkins,  │          │                        │
│   Jira, SSVC,       │          │                        │
│   SBOM, MCP)        │          │                        │
└─────────────────────┴──────────┴────────────────────────┘
                          │
                    sitecustomize.py
                  (sys.path unification)
```

### Key Design Decisions

| Decision | Rationale | Risk |
|----------|-----------|------|
| Single Python process | Simplicity, shared memory | No horizontal scaling |
| sitecustomize.py for imports | Zero-config cross-suite imports | Fragile, order-dependent |
| SQLite WAL mode everywhere | No external DB dependency | Single-writer bottleneck |
| In-memory event bus | No message queue needed | Events lost on restart |
| ~3 in-memory dicts + file/SQLite stores | Fast development cycle | Only in-memory items lost on restart |
| Multi-LLM consensus | Reduces single-model bias | Triple API cost |
| Try/except router loading | Graceful degradation | Silent failures hide bugs |

### Dependency Stack

```
FastAPI 0.115+          # Web framework
PyJWT 2.10+             # Authentication
bcrypt 4.3+             # Password hashing
cryptography 44+        # RSA signing, Fernet encryption
structlog 25+           # Structured logging
networkx 3.4+           # Graph operations
pgmpy 0.1+              # Bayesian networks
scikit-learn 1.6+       # ML for risk scoring
opentelemetry-api 1.30+ # Distributed tracing
httpx 0.28+             # Async HTTP client
tenacity 9+             # Retry logic
sarif-om 1.0+           # SARIF format support
ssvc 0.3+               # Stakeholder-Specific Vulnerability Categorization
Jinja2 3.1+             # Template rendering
pydantic 2.x            # Data validation
```

---

## 2. Import System — sitecustomize.py

**File**: `sitecustomize.py` (40 lines)  
**Purpose**: Auto-loaded by CPython at startup, prepends all suite directories to `sys.path`.

```python
_SUITE_PATHS = [
    "suite-api",        # Priority 1: API gateway
    "suite-core",       # Priority 2: Core engine
    "suite-attack",     # Priority 3: Offensive security
    "suite-feeds",      # Priority 4: Threat intelligence
    "suite-integrations", # Priority 5: External connectors
    "suite-evidence-risk", # Priority 6: Compliance & risk
]
```

**How it works**: Each suite directory is inserted at position 0 of `sys.path`, meaning:
- `from core.connectors import JiraConnector` resolves to `suite-core/core/connectors.py`
- `from apps.api.app import create_app` resolves to `suite-api/apps/api/app.py`
- `from risk.scoring import RiskProfiler` resolves to `suite-evidence-risk/risk/scoring.py`

**Problems**:
1. **Order sensitivity**: If two suites have identically-named modules, the first suite in the list wins silently
2. **No namespace isolation**: Any suite can import from any other suite with no dependency boundary enforcement
3. **IDE confusion**: Without proper pyproject.toml path configuration, IDEs may not resolve imports correctly
4. **Testing fragility**: Tests must run from the project root or import resolution fails

---

## 3. suite-core — The Brain

**Total files**: ~32 Python modules  
**Total LOC**: ~25,000+  
**Purpose**: Decision engine, pipeline orchestration, connectors, event bus, crypto, analytics

### 3.1 core/connectors.py (3,005 lines)

The largest connector framework, providing enterprise integrations with circuit breaker, rate limiting, and retry logic.

**Architecture**:
```
_BaseConnector (abstract)
├── JiraConnector        — Issue tracking
├── ConfluenceConnector  — Documentation
├── ServiceNowConnector  — ITSM
├── GitLabConnector      — SCM + CI/CD
├── AzureDevOpsConnector — Microsoft DevOps
├── GitHubConnector      — SCM + Actions
└── SlackConnector       — Notifications
```

**Key patterns**:
- `CircuitBreaker` dataclass: tracks failure count, opens circuit after threshold, auto-resets after cooldown
- `Retry` from urllib3: exponential backoff with configurable max retries
- Rate limiter: token bucket algorithm with per-connector limits
- `health_check()` on every connector for liveness probes

~~Bug — ConnectorOutcome.success~~: **VERIFIED FALSE** — The actual code checks `self.status in ("sent", "success", "fetched")`, correctly handling all operation types.

**Bug — Circuit breaker race condition**: The `CircuitBreaker` dataclass is not thread-safe. Multiple concurrent requests can read stale failure counts.

### 3.2 core/brain_pipeline.py (863 lines)

The **12-step orchestration pipeline** that processes CVE findings end-to-end:

```
Step 1:  Input normalization
Step 2:  Deduplication check
Step 3:  CVE lookup (NVD)
Step 4:  CVSS parsing
Step 5:  EPSS + KEV enrichment     ← FAKE DATA
Step 6:  Exploit signal analysis
Step 7:  Multi-LLM consensus
Step 8:  Policy evaluation          ← Fragile string matching
Step 9:  Remediation generation
Step 10: Evidence bundle creation
Step 11: Graph update
Step 12: Event emission
```

**HIGH — Step 5 (Synthetic enrichment)**:
```python
# Instead of calling real EPSS/KEV APIs, derives synthetic values from severity:
epss = min(cvss / 10.0 * 0.6, 0.97)  # Deterministic, but not real EPSS
kev_listed = cvss >= 9.0               # Heuristic, not real KEV lookup
```
This means EPSS/KEV data is *deterministic* (not random), but still synthetic — derived solely from CVSS severity rather than actual threat intelligence feeds. Risk scores are therefore plausible but not grounded in real-world exploitation data.

~~MEDIUM — Step 10 (FD leak)~~: **VERIFIED FALSE** — Both `asyncio.new_event_loop()` calls (lines 703 and 845) have corresponding `loop.close()` in `finally` blocks. No file descriptor leak exists.

**LOW — Step 8 (Fragile policy matching)**:
Policy names are matched using substring comparison on display names rather than enum values, so renaming a policy breaks the pipeline silently.

### 3.3 core/llm_providers.py (664 lines)

Multi-LLM adapter supporting 4 providers with consensus voting:

```
BaseLLMProvider (abstract)
├── OpenAIProvider       — GPT-4/GPT-4o
├── AnthropicMessagesProvider — Claude 3.5 Sonnet
├── GeminiProvider       — Gemini Pro
└── SentinelProvider     — Local fallback (heuristic-based)
```

**Consensus mechanism**: All configured providers analyze the same CVE. If ≥85% agree on the recommended action, that action is selected. Otherwise, the most conservative action wins.

**HIGH — Anthropic API misuse (line ~340)**:
```python
"messages": [
    {"role": "system", "content": "..."},  # WRONG: Anthropic doesn't support this
    {"role": "user", "content": prompt},
]
```
Anthropic's Messages API requires `system` as a top-level parameter, not a message. This causes a 400 error on every Anthropic call, making Claude silently fall back to the heuristic provider — the multi-LLM consensus is effectively 2-model consensus.

**Fix**:
```python
payload = {
    "model": self.model,
    "max_tokens": 400,
    "system": "Return a JSON object with...",  # Top-level
    "messages": [{"role": "user", "content": prompt}],
}
```

### 3.4 core/event_bus.py (243 lines)

In-memory async event bus implementing pub/sub across all suites.

**26 event types** organized into 8 categories:
- Scan & Discovery (6 events)
- Attack & Pentest (5 events)
- Remediation (3 events)
- AutoFix (7 events)
- Evidence & Risk (3 events)
- Intelligence (4 events)
- Collaboration (4 events)
- System (4 events)
- Copilot/AI (3 events)

**Architecture**: Singleton pattern via `EventBus.get_instance()`. Subscribers register via `@bus.on(EventType.CVE_DISCOVERED)` decorator or `bus.subscribe()`. Events are dispatched sequentially to all matching handlers.

**Problems**:
1. **Dead variable**: Module-level `_bus: Optional[EventBus] = None` is defined but never used — `get_event_bus()` calls `EventBus.get_instance()` directly
2. **Lazy brain import**: On every `emit()`, checks if `self._brain is None` and imports `knowledge_brain`. This is a hot path — the import check happens on every single event emission
3. **No persistence**: All events are in-memory only. The event log is capped at 10,000 entries via list slicing
4. **No async concurrency**: Handlers are awaited sequentially — a slow handler blocks all subsequent handlers
5. **No dead letter queue**: Failed handler exceptions are logged and swallowed silently

### 3.5 core/crypto.py (571 lines)

RSA-SHA256 signing infrastructure for evidence bundles.

**Features**:
- 2048-bit RSA key generation
- SHA-256 message signing with PSS padding
- Key fingerprint tracking
- PEM key serialization

**Issue — Unencrypted private keys**:
```python
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),  # Keys stored unencrypted
)
```
Private keys are serialized without encryption. If the key file is compromised, the attacker gets immediate access to the signing key.

### 3.6 core/micro_pentest.py (2,007 lines)

Core vulnerability scanner supporting multiple test types:
- CORS misconfiguration
- SQL injection (error-based, time-based, Union-based)
- XSS (reflected, stored, DOM-based)
- SSTI (Server-Side Template Injection)
- SSRF (Server-Side Request Forgery)
- Open redirect
- Header injection
- IDOR (Insecure Direct Object Reference)

**HIGH — Incomplete SSRF validation**:
```python
def _is_safe_url(self, url: str) -> bool:
    # Checks for 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, ::1
    # MISSING: 169.254.x.x (link-local / AWS metadata)
    # MISSING: IPv6 private ranges (fc00::, fe80::)
    # MISSING: Hex/octal encoded IPs (0x7f000001)
    # MISSING: DNS rebinding protection
```
The blocklist DOES include `::1` (IPv6 loopback). However, an attacker can still bypass SSRF protection using `169.254.169.254` (AWS/GCP/Azure metadata service), IPv6 private ranges (`fc00::`, `fe80::`), or hex-encoded IPs.

**MEDIUM — SSL verification disabled**:
```python
self.session = requests.Session()
self.session.verify = False  # SSL verification disabled globally
```

### 3.7 core/evidence.py (436 lines)

Evidence bundle creation with compression, encryption, and signing.

**CRITICAL — Hardcoded fallback encryption key**:
```python
# When encryption_env is not set and not in demo/test/CI mode:
key = "XA4YsbLpheGujMd1vXX4HR1jAWGTL9D9ZvGBZgy00eg="
# This key is in the source code — any attacker can decrypt evidence bundles
```

The code has nuance: in demo/test/CI mode, encryption is disabled entirely. In production mode, if the env var is missing, it uses this hardcoded key. The intent was a development convenience, but the fallback path is reachable in production.

**Otherwise well-designed**:
- Atomic writes via temp file + rename
- Gzip compression configurable via overlay config
- RSA-SHA256 signing with fingerprint tracking
- Feature flag integration for runtime toggle
- Retention policy (default: 2555 days ≈ 7 years)

### 3.8 core/auth_middleware.py (235 lines)

JWT + API key authentication with scoped access control.

**CRITICAL — Missing method on AuthContext**:
```python
class AuthContext:
    __slots__ = ("user_id", "email", "role", "org_id", "scopes", "auth_method")
    # No has_scope() method defined!

# But require_scope() calls it:
async def _check(auth: AuthContext = Depends(require_auth)):
    if not auth.has_scope(scope):  # AttributeError at runtime!
```
Because `AuthContext` uses `__slots__`, you cannot dynamically add methods. Any endpoint using `require_scope()` will crash with `AttributeError: 'AuthContext' object has no attribute 'has_scope'`.

**HIGH — Hardcoded JWT secret**:
```python
_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
```
If `FIXOPS_JWT_SECRET` is not set (common in dev/staging), any attacker who knows this default can forge JWT tokens for any user.

**MEDIUM — Dev-mode bypass enabled by default**:
```python
_AUTH_MODE = os.getenv("FIXOPS_AUTH_MODE", "dev")  # Default is "dev", not "enforced"
```
In dev mode, unauthenticated requests get full admin access:
```python
return AuthContext(
    user_id="dev-user",
    email="dev@fixops.local",
    role="admin",
    org_id="default",
    scopes=ROLE_SCOPES[UserRole.ADMIN],
    auth_method="dev-bypass",
)
```

### 3.9 core/processing_layer.py (462 lines)

Advanced analytics using Bayesian networks (pgmpy), Markov chains, and NetworkX graph analysis.

**CRITICAL — Bayesian CPD has zero discriminative power**:
```python
risk_cpd = TabularCPD(
    variable="risk",
    variable_card=4,
    values=[
        [0.35] * 324,  # P(low)  = 0.35 regardless of evidence
        [0.3]  * 324,  # P(med)  = 0.30 regardless of evidence
        [0.2]  * 324,  # P(high) = 0.20 regardless of evidence
        [0.15] * 324,  # P(crit) = 0.15 regardless of evidence
    ],
    evidence=["exploitation", "exposure", "utility", "safety_impact", "mission_impact"],
    evidence_card=[3, 3, 3, 4, 3],
)
```
The risk CPD assigns identical probabilities for every combination of evidence states (3×3×3×4×3 = 324 combinations). This means the Bayesian network **always outputs "low" as the most likely risk** regardless of exploitation status, exposure level, or mission impact. The entire SSVC-inspired decision framework is decorative.

### 3.10 core/decision_tree.py (330 lines)

6-step CVE exploitation analysis orchestrator:
1. Basic CVE info extraction
2. Exploit availability check
3. Attack complexity assessment
4. Impact analysis
5. Environmental context
6. Final decision (patch/mitigate/accept/defer)

**Problem**: Imports `core.exploit_signals`, `core.knowledge_brain`, `core.connectors` — if any of these fail, the entire decision tree is unavailable. No graceful degradation.

### 3.11 core/knowledge_brain.py (853 lines)

SQLite-backed knowledge graph with NetworkX overlay.

**Architecture**:
- SQLite for persistence (WAL mode)
- NetworkX `DiGraph` for in-memory graph operations
- Thread-safe singleton via `threading.Lock`
- Supports nodes (CVE, asset, component, finding) and edges (affects, depends_on, mitigates)

**Scalability concern**: On initialization, loads ALL nodes and edges into the NetworkX graph:
```python
def _load_graph(self):
    for row in cursor.fetchall():
        self.graph.add_node(row["id"], **json.loads(row["data"]))
    for row in cursor.fetchall():
        self.graph.add_edge(row["source"], row["target"], **json.loads(row["data"]))
```
At ~100K nodes, this will consume significant memory and take noticeable startup time.

### 3.12 core/vector_store.py (445 lines)

Vector similarity search with two backends:

```
BaseVectorStore (abstract)
├── InMemoryVectorStore  — SHA-256 hash-based "embeddings"
└── ChromaVectorStore    — ChromaDB with real embeddings
```

**MEDIUM — Fake embeddings in InMemoryVectorStore**:
```python
def _embed(self, text: str) -> Vector:
    tokens = self._tokenise(text)
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        for index in range(self.dimensions):
            vector[index] += digest[index % len(digest)] / 255.0
    # Normalize...
```
This is a **bag-of-words hash trick**, not true semantic embeddings. Texts that share tokens (e.g., "SQL injection vulnerability" and "SQL injection attack") WILL have higher cosine similarity. However, semantically similar texts with different wording (e.g., "SQL injection" vs "database query manipulation") will score near zero. It captures lexical overlap but not semantic meaning — better than random, but far inferior to real embeddings.

ChromaVectorStore is properly implemented using real embeddings, but it requires the optional `chromadb` dependency which may not be installed.

### 3.13 core/playbook_runner.py (1,270 lines)

YAML/JSON playbook engine supporting ~30 action types:
- `run_scan`, `run_pentest`, `run_sast`, `run_dast`
- `create_ticket`, `send_notification`, `update_finding`
- `enrich_cve`, `check_kev`, `check_epss`
- `evaluate_policy`, `generate_evidence`, `create_pr`
- `wait`, `condition`, `parallel`, `loop`

**Good practices**:
- Uses `yaml.safe_load` (not `yaml.load`) — no arbitrary code execution
- Step timeout enforcement
- Variable interpolation with `${variable}` syntax
- Conditional execution via `when` clauses

**Concern**: No sandboxing — playbook actions execute with full application privileges.

### 3.14 core/configuration.py (1,528 lines)

Overlay configuration system with hierarchical merging:
```
defaults.yaml → environment.yaml → env vars → feature flags
```

**Features**:
- `OverlayConfig` class with typed accessors
- Feature flag provider integration (LaunchDarkly-style)
- Data directory management with secure path resolution
- Evidence settings, LLM provider config, connector config

**Problem**: At 1,528 lines, this is a god-class that handles too many responsibilities.

### 3.15 core/cli.py (5,908 lines)

The largest single file in the codebase. CLI interface providing terminal access to all FixOps capabilities.

**Problems**:
1. **Side-effects at import**: `sys.path.append()` and `os.environ` mutations happen at module load time
2. **God file**: 5,908 lines covering scanning, pentesting, reporting, evidence, feeds, integrations, configuration — should be split into subcommands
3. **Duplicated logic**: Many CLI commands re-implement logic that exists in the core modules rather than delegating

### 3.16 core/mpte_advanced.py (1,090 lines)

Multi-AI consensus engine for pen testing with 3 roles:
1. **Architect** — analyzes attack surface
2. **Developer** — proposes exploit techniques  
3. **Lead** — synthesizes findings and assigns severity

**MEDIUM — Prompt injection risk**:
Raw vulnerability data is interpolated directly into LLM prompts:
```python
prompt = f"Analyze vulnerability: {vuln_data}"  # vuln_data is user-controlled
```
An attacker who controls the vulnerability description could inject prompt instructions.

### 3.17 core/probabilistic.py (693 lines)

Monte Carlo simulation, Bayesian priors, and Markov transitions for risk forecasting.

**Implementation quality**: Mathematically sound. Uses proper statistical methods:
- Monte Carlo: 10,000 iterations with configurable distributions
- Bayesian: Beta distribution priors updated with Bernoulli likelihood
- Markov: Row-stochastic transition matrices with absorbing state detection

### 3.18 core/hallucination_guards.py (325 lines)

LLM output validation to detect hallucinated CVEs, scores, and references.

**Features**:
- CVE format validation (CVE-YYYY-NNNNN pattern)
- CVSS score range checking (0.0-10.0)
- Citation verification against known sources
- Confidence calibration

**Problem**: Citation checking uses exact string matching — a slightly rephrased but factually correct citation is flagged as hallucinated.

### 3.19 core/model_registry.py (471 lines)

Risk model versioning and A/B testing framework.

**Features**:
- Model version tracking with semantic versioning
- A/B test configuration with traffic splitting
- Model performance metrics (accuracy, precision, recall)
- Rollback capability

**Status**: Framework only — no models are registered by default. The A/B testing infrastructure exists but is unused.

### 3.20 core/stage_runner.py (1,150 lines)

Per-stage processor for the brain pipeline.

**Problem — Testing backdoor**:
```python
fake_now = os.environ.get("FIXOPS_FAKE_NOW")
if fake_now:
    now = datetime.fromisoformat(fake_now)
```
`FIXOPS_FAKE_NOW` allows overriding the current time via environment variable. While useful for testing, this backdoor exists in production code and could be exploited if an attacker can set environment variables.

### 3.21 Other core/ files

| File | Lines | Purpose | Notable Issues |
|------|-------|---------|----------------|
| `exploit_signals.py` | ~350 | Exploit availability scoring from ExploitDB, GitHub, Metasploit | Uses `requests.get` without timeout in some paths |
| `ai_agents.py` | ~400 | Agent framework for autonomous CVE analysis | Stub implementations for some agent types |
| `analytics.py` | ~300 | Dashboard metrics aggregation | In-memory counters, lost on restart |
| `storage.py` | ~250 | Abstract storage layer (file, S3, GCS) | S3/GCS backends are stubs |
| `policy.py` | ~200 | Policy evaluation engine | String-based matching as noted in brain_pipeline |
| `feedback.py` | ~250 | User feedback collection for model improvement | SQLite-backed, no validation |
| `compliance.py` | ~300 | Compliance framework mappings | Static data, no dynamic updates |
| `logging_config.py` | ~150 | Structlog configuration | Well-implemented |
| `paths.py` | ~100 | Secure directory utilities | Good: uses `resolve_within_root` for path traversal prevention |

---

## 4. suite-api — FastAPI Gateway

**Total files**: ~35+ Python modules  
**Total LOC**: ~15,000+  
**Purpose**: HTTP API layer, authentication, routing, middleware

### 4.1 apps/api/app.py (2,456 lines)

The main FastAPI application factory.

**Architecture**:
```python
def create_app() -> FastAPI:
    app = FastAPI(title="FixOps API", version="2.0.0")
    
    # Middleware
    app.add_middleware(CORSMiddleware, ...)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    
    # 27 routers loaded via try/except (66 unique router files exist across all suites)
    try:
        from apps.api.findings_router import router as findings_router
        app.include_router(findings_router, dependencies=[Depends(_verify_api_key)])
    except ImportError:
        logger.warning("findings_router not available")
    # ... repeat for each router
```

**Key characteristics**:
1. **All routers protected**: Every `include_router` call includes `dependencies=[Depends(_verify_api_key)]`
2. **Try/except loading**: Routers from other suites may not be available; failures are logged and swallowed
3. **CORS middleware**: Configured for localhost development (ports 3000, 3001, 5173, 8080)
4. **JWT generation**: If `FIXOPS_JWT_SECRET` env var is not set, an ephemeral secret is generated at startup — all JWTs become invalid after restart

**Problems**:
1. **~3 pure in-memory dicts** (`artifacts`, `archive_records`, `last_pipeline_result`) lose data on restart. Most other stores (analytics, archive, feedback, knowledge brain, feeds, auth, evidence) are file/SQLite-backed.
2. **No RBAC**: Any valid API key grants full admin access to every endpoint
3. **God file**: At 2,456 lines, app.py handles too many concerns (routes, business logic, data storage)
4. **Path allowlist**: Some endpoints validate paths against an allowlist, but the validation is inconsistent across routes

### 4.2 apps/api/dependencies.py (85 lines)

FastAPI dependency injection for multi-tenancy:
- `get_org_id()` — extracts org ID from headers, defaults to "default"
- `get_correlation_id()` — unique request tracing ID
- `_verify_api_key()` — API key validation wrapper

Clean and minimal. No issues found.

### 4.3 apps/api/middleware.py (~110 lines)

Two middleware classes:
1. **CorrelationIdMiddleware**: Adds `X-Correlation-ID` header to every request/response
2. **RequestLoggingMiddleware**: Logs method, path, status, and duration

Well-implemented. Uses `time.perf_counter()` for accurate timing.

### 4.4 apps/api/webhooks_router.py (1,803 lines)

Comprehensive webhook management with:
- Registration, configuration, and delivery tracking
- Webhook outbox pattern for reliable delivery
- Integration mappings (Jira, GitHub, ServiceNow, Azure DevOps)
- Drift detection between configured and actual webhook state
- Signature verification for inbound webhooks

**HIGH — Unauthenticated inbound webhooks**:
```python
# ServiceNow receiver — no authentication check
@router.post("/receive/servicenow")
async def receive_servicenow(request: Request):
    body = await request.json()
    # Process directly — no signature/token verification

# Azure DevOps receiver — same problem
@router.post("/receive/azure-devops")
async def receive_azure_devops(request: Request):
    body = await request.json()
    # No authentication
```

**MEDIUM — Jira signature verification weakness**:
```python
# Verifies signature against reconstructed JSON body, not raw bytes
body = await request.json()
raw_body = json.dumps(body).encode()  # Reconstructed, not original
# Signature verification may fail for equivalent but differently-formatted JSON
```

### 4.5 apps/api/rate_limiter.py (~200 lines)

Token bucket rate limiter implementation:
- Per-IP tracking with configurable burst and refill rate
- Cleanup of stale entries
- Middleware class for FastAPI integration

**HIGH — Not wired into the app**: `RateLimitMiddleware` is defined but never added to the FastAPI application in `app.py`. The rate limiter exists but provides zero protection.

### 4.6 apps/api/upload_manager.py (245 lines)

Chunked file upload handling with:
- Path traversal protection (`resolve_within_root`)
- SHA-256 checksum verification
- Configurable max file size
- Atomic reassembly of chunks

**Well-implemented**. No security issues found.

### 4.7 apps/api/auth_router.py (~200 lines)

SSO/SAML configuration management:
- CRUD for SSO providers
- SAML metadata upload
- IdP configuration

Standard implementation. No significant issues.

### 4.8 apps/api/integrations_router.py (482 lines)

Integration management:
- CRUD for connector configurations (Jira, GitHub, Slack, etc.)
- Health check / test connectivity endpoints
- Sync triggers

**Pattern**: Maps `IntegrationType` enum to connector classes:
```python
if integration.type == IntegrationType.JIRA:
    connector = JiraConnector(integration.config)
elif integration.type == IntegrationType.GITHUB:
    connector = GitHubConnector(integration.config)
# ... etc
```

### 4.9 apps/api/normalizers.py

Input normalization for multiple security formats:
- SBOM (CycloneDX, SPDX)
- SARIF (Static Analysis Results Interchange Format)
- VEX (Vulnerability Exploitability eXchange)
- CVE records
- CNAPP (Cloud-Native Application Protection Platform)

Parses vendor-specific formats into a unified FixOps finding schema.

### 4.10 backend/app.py (13 lines)

Thin wrapper:
```python
from apps.api.app import create_app
# That's essentially it — delegates everything to suite-api
```

Exists for the `uvicorn backend.app:create_app --factory` entrypoint.

---

## 5. suite-attack — Offensive Security

**Total files**: 13 Python modules  
**Total LOC**: ~8,000+  
**Purpose**: Micro-pentest engine, DAST/SAST, attack simulation, fuzzing

### 5.1 api/mpte_router.py (726 lines)

MPTE (Micro Pen Test Engine) orchestration router.

**Architecture**:
```
POST /api/v1/mpte/test     — Trigger pen test
GET  /api/v1/mpte/status   — Check test status
GET  /api/v1/mpte/results  — Get test results
POST /api/v1/mpte/schedule — Schedule recurring test
```

**Pattern**: Dual-mode operation:
1. **Real mode**: Calls MPTE service via httpx (environment-configured URL)
2. **Demo mode**: Returns synthetic results when `FIXOPS_DEMO_MODE=true`

**Problem — SSL verification disabled**:
```python
async with httpx.AsyncClient(verify=False) as client:
    response = await client.post(mpte_url, ...)
```
All MPTE service calls disable SSL certificate verification.

### 5.2 api/micro_pentest_router.py (1,818 lines)

Enterprise micro penetration testing with 8-phase scanning:

```
Phase 1: Reconnaissance
Phase 2: Service enumeration
Phase 3: Vulnerability identification
Phase 4: Exploitation attempt
Phase 5: Post-exploitation analysis
Phase 6: MITRE ATT&CK alignment
Phase 7: Compliance validation
Phase 8: Report generation
```

**Features**:
- MITRE ATT&CK technique mapping
- Compliance framework validation (NIST, PCI-DSS, OWASP)
- Finding deduplication
- Evidence collection with screenshots

**Same dual-mode pattern**: Real MPTE service or demo/synthetic results.

### 5.3 api/dast_router.py (~45 lines)

Dynamic Application Security Testing — thin router delegating to `core.dast_engine`:
```python
@router.post("/scan")
async def dast_scan(req: DastScanRequest):
    engine = get_dast_engine()
    result = await engine.scan(target_url=req.target_url, ...)
```

Minimal. Depends on `core.dast_engine` which may not exist → `ImportError` caught by app.py's try/except loading.

### 5.4 api/sast_router.py (~80 lines)

Static Application Security Testing router:
- Scan single code snippets
- Scan multiple files
- List SAST rules
- Engine status

Delegates to `core.sast_engine`. Uses pattern-matching with CWE mapping. Supports Python, JavaScript, Java, Go, Ruby, PHP, C#.

### 5.5 Other attack routers

| Router | Lines | Purpose | Notes |
|--------|-------|---------|-------|
| `mpte_orchestrator_router.py` | ~300 | MPTE Orchestrator integration | Autonomous pen testing via AI agents |
| `cspm_router.py` | ~200 | Cloud Security Posture Management | AWS/Azure/GCP misconfig detection |
| `vuln_discovery_router.py` | ~250 | Vulnerability discovery | Nmap/Nuclei-style scanning |
| `attack_sim_router.py` | ~300 | Attack simulation | Breach & attack simulation (BAS) |
| `api_fuzzer_router.py` | ~250 | API fuzzing | OpenAPI spec-driven fuzzing |
| `secrets_router.py` | ~200 | Secret detection | Git history scanning for secrets |
| `container_router.py` | ~250 | Container security | Image scanning, Dockerfile analysis |
| `malware_router.py` | ~200 | Malware analysis | YARA rule matching, sandbox execution |

All follow the same pattern: thin FastAPI router → core engine delegation → try/except in app.py.

---

## 6. suite-feeds — Threat Intelligence

**Total files**: ~15 Python modules  
**Total LOC**: ~5,000+  
**Purpose**: Vulnerability intelligence aggregation from 55+ sources

### 6.1 feeds_service.py (3,042 lines)

The largest intelligence aggregation service, covering 8 categories:

```
1. NVD (National Vulnerability Database)
2. CISA KEV (Known Exploited Vulnerabilities)
3. EPSS (Exploit Prediction Scoring System)
4. National CERTs (US-CERT, JPCERT, BSI, ANSSI, etc.)
5. Exploit DBs (ExploitDB, PacketStorm, GitHub PoCs)
6. Threat Actors (MITRE ATT&CK groups, APT feeds)
7. Supply Chain (NPM advisories, PyPI, RubyGems)
8. Cloud/Runtime (AWS, Azure, GCP security bulletins)
```

**55+ feed source URLs** defined for comprehensive coverage.

**Features**:
- SQLite-backed with WAL mode
- Geo-weighted risk scoring (adjusts risk based on geographic threat actors)
- Feed freshness tracking with staleness alerts
- Auto-refresh with configurable intervals
- Deduplication via CVE ID normalization

**Architecture**:
```python
class FeedsService:
    def __init__(self, db_path=...):
        self._db = sqlite3.connect(db_path)
        self._init_schema()
        self._feed_sources = self._define_sources()
    
    def fetch_all(self):
        for source in self._feed_sources:
            self._fetch_source(source)
    
    def enrich_cve(self, cve_id: str) -> dict:
        # Aggregates from NVD + KEV + EPSS + vendor advisories
        ...
```

### 6.2 api/feeds_router.py (1,211 lines)

FastAPI router exposing feeds service:

```
GET  /api/v1/feeds/cve/{cve_id}     — CVE details with enrichment
GET  /api/v1/feeds/search            — Search across all feeds
GET  /api/v1/feeds/kev               — CISA KEV catalog
GET  /api/v1/feeds/epss              — EPSS scores
GET  /api/v1/feeds/sources           — List configured sources
POST /api/v1/feeds/refresh           — Trigger feed refresh
GET  /api/v1/feeds/stats             — Feed health statistics
```

**Features**:
- Thread-safe singleton with auto-refresh timer
- Knowledge Brain integration (logs enrichments to graph)
- Event Bus integration (emits `FEED_UPDATED`, `KEV_ALERT` events)
- Graceful degradation when brain/event bus unavailable

---

## 7. suite-evidence-risk — Compliance & Risk

**Total files**: ~40 Python modules  
**Total LOC**: ~12,000+  
**Purpose**: Risk scoring, compliance mapping, evidence bundles, reachability analysis, runtime protection

### 7.1 risk/enrichment.py (306 lines)

CVE enrichment combining multiple data sources:
- EPSS score lookup
- CISA KEV catalog check
- ExploitDB search
- CVSS v2/v3/v3.1 vector parsing
- CWE classification

**Quality**: Clean defensive coding with proper error handling. Parses CVSS vectors correctly using regex extraction of metric values.

### 7.2 risk/threat_model.py (378 lines)

Threat modeling engine:
- CVSS vector component analysis
- Reachability scoring (network exposure × call graph depth)
- Exposure level determination (external, internal, restricted)
- Environmental adjustment factors

**Algorithm**:
```
base_risk = cvss_base_score × 10
reachability_factor = exposure_multiplier × call_depth_weight
adjusted_risk = base_risk × reachability_factor × temporal_decay
```

Well-structured. Uses proper CVSS component weights.

### 7.3 risk/scoring.py (467 lines)

Risk profiling with multi-dimensional scoring:
- EPSS probability weighting (0.0–1.0)
- KEV binary boost (listed = +25 risk points)
- Version lag penalty (outdated deps = higher risk)
- Exposure level multiplier (external > internal > restricted)
- Temporal decay (older vulnerabilities with no exploit = lower risk)

**Features**:
- OpenTelemetry tracing on scoring operations
- Exposure alias normalization ("internet-facing" → "external")
- `FIXOPS_TEST_SEED` env var for deterministic testing
- Configurable via overlay configuration

### 7.4 compliance/mapping.py (307 lines)

CWE-to-compliance-control mapping supporting 5 frameworks:
1. **NIST 800-53**: AC-*, CM-*, SI-*, SC-* controls
2. **NIST SSDF**: PO, PS, PW, RV tasks
3. **PCI-DSS**: Requirements 2, 3, 6, 8, 10
4. **ISO 27001**: A.9, A.12, A.14 controls
5. **OWASP Top 10**: A01–A10 categories

14 CWE IDs mapped: CWE-79, 89, 78, 22, 352, 287, 918, 502, 611, 94, 400, 200, 327, 798.

Extensible via overlay configuration for custom framework mappings.

### 7.5 compliance/templates/ (5 files, ~600 lines total)

Compliance report templates:
- `base.py` — Abstract template with Jinja2 rendering
- `nist.py` — NIST 800-53 compliance report
- `owasp.py` — OWASP Top 10 assessment (210 lines)
- `pci_dss.py` — PCI-DSS compliance checklist
- `soc2.py` — SOC 2 Type II evidence mapping
- `hipaa.py` — HIPAA security rule alignment

### 7.6 evidence/packager.py (335 lines)

Evidence bundle creation for audit/compliance:

**Bundle structure**:
```
evidence-bundle-{tag}-{timestamp}.zip
├── manifest.json          — Bundle metadata, checksums
├── normalized-sbom.json   — Normalized SBOM
├── sbom-quality.json      — SBOM quality metrics
├── sbom-quality.html      — Human-readable quality report
├── risk-report.json       — Risk assessment
├── provenance/            — Build provenance attestations
├── repro-attestation.json — Reproducibility attestation
└── policy-evaluation.json — Policy gate results
```

**Policy evaluation**: Pass/warn/fail gates on:
- SBOM coverage (fail < 60%, warn < 80%)
- License coverage (fail < 50%, warn < 80%)
- Max risk score (fail > 85, warn > 70)
- Reproducibility match required
- Attestation required

### 7.7 risk/reachability/ (13 files, ~5,000+ lines)

Enterprise-grade reachability analysis — the most sophisticated subsystem:

```
ReachabilityAnalyzer
├── CodeAnalyzer           — Multi-tool static analysis (CodeQL, Semgrep, Bandit)
├── CallGraphBuilder       — Function-level call graph construction
├── DataFlowAnalyzer       — Taint propagation tracking
├── GitRepositoryAnalyzer  — Git history + blame analysis
├── ProprietaryAnalyzer    — Custom AST-based analysis (no OSS deps)
├── ProprietaryConsensus   — Multi-method consensus voting
├── ProprietaryScoring     — Scoring from design + runtime signals
└── ProprietaryThreatIntel — CVE → component mapping with threat context
```

**Design-time analysis** (like Apiiro):
1. Clone/checkout repository
2. Run CodeQL/Semgrep/Bandit
3. Build call graph from AST
4. Trace data flow from entry points
5. Determine if vulnerable functions are reachable

**Runtime analysis**:
1. IAST agent instrumentation
2. RASP rule evaluation
3. Container runtime monitoring
4. Cloud API audit log analysis

**Discrepancy detection**: Compares design-time and runtime results. If design-time says "reachable" but runtime shows "never called", flags a discrepancy with explanation.

**Supporting infrastructure**:
- `cache.py` — Analysis result caching with TTL
- `storage.py` — SQLite persistence for reachability results
- `monitoring.py` — Analysis job tracking and metrics
- `job_queue.py` — Background job scheduling for long-running analyses
- `enterprise_features.py` — Premium features (multi-repo, org-wide analysis)

### 7.8 risk/runtime/ (5 files, ~2,000 lines)

Runtime security monitoring:

| Module | Lines | Purpose |
|--------|-------|---------|
| `rasp.py` | 354 | Runtime Application Self-Protection — blocks attacks in real-time |
| `iast.py` | 400 | Interactive Application Security Testing — runtime instrumentation |
| `iast_advanced.py` | 675 | Advanced IAST with taint tracking and code coverage |
| `container.py` | 340 | Container runtime security (Falco-style) |
| `cloud.py` | 231 | Cloud workload protection (CWPP) |

**RASP engine** (`rasp.py`) detects and blocks:
- SQL injection (regex-based pattern matching)
- Command injection
- XSS
- Path traversal
- Deserialization attacks
- Rate limit violations

**IAST** (`iast_advanced.py`) provides:
- Taint source/sink tracking
- Code coverage measurement
- Vulnerability correlation with runtime behavior
- False positive elimination

### 7.9 risk/feeds/ (8 files, ~2,000 lines)

Dedicated vulnerability feed clients:

| Module | Lines | Purpose |
|--------|-------|---------|
| `orchestrator.py` | 378 | Feed refresh orchestration with scheduling |
| `nvd.py` | 233 | NVD 2.0 API client |
| `kev.py` | 135 | CISA KEV catalog client |
| `epss.py` | 146 | EPSS API client |
| `exploits.py` | 431 | ExploitDB + PacketStorm + GitHub PoC |
| `github.py` | 261 | GitHub Security Advisories (GHSA) |
| `osv.py` | 223 | OSV (Open Source Vulnerabilities) |
| `vendors.py` | 269 | Vendor-specific advisories |
| `ecosystems.py` | 352 | NPM, PyPI, RubyGems advisories |

### 7.10 Other risk/ files

| Module | Lines | Purpose |
|--------|-------|---------|
| `dependency_graph.py` | ~300 | Dependency tree analysis with NetworkX |
| `dependency_health.py` | ~250 | Package health scoring (age, maintainer count, update frequency) |
| `dependency_realtime.py` | ~200 | Real-time dependency monitoring |
| `license_compliance.py` | ~250 | License compatibility checking (GPL, MIT, Apache, etc.) |
| `secrets_detection.py` | ~300 | Secret scanning (API keys, tokens, passwords) |
| `sbom/generator.py` | 424 | SBOM generation (CycloneDX, SPDX) |
| `iac/terraform.py` | 262 | Terraform misconfiguration scanning |
| `forecasting.py` | ~200 | Risk trend forecasting |

### 7.11 api/ routers

| Router | Lines | Purpose |
|--------|-------|---------|
| `risk_router.py` | ~400 | Risk scoring, profiling, trending |
| `evidence_router.py` | ~300 | Evidence bundle management |
| `graph_router.py` | ~250 | Dependency graph visualization |
| `provenance_router.py` | ~300 | Build provenance and attestation |
| `business_context.py` | ~250 | Business impact context |
| `business_context_enhanced.py` | ~350 | Enhanced business context with AI |

---

## 8. suite-integrations — External Connectors

**Total files**: 23 Python modules  
**Total LOC**: ~6,500  
**Purpose**: Third-party tool integration, SBOM utilities, SSVC deployment

### 8.1 integrations/mpte_client.py (387 lines)

Async HTTP client for MPTE pen testing platform:

```python
class MPTEClient:
    async def create_test(target, test_type, config) -> str  # Returns test ID
    async def get_test_status(test_id) -> dict
    async def get_test_results(test_id) -> MPTETestResult
    async def cancel_test(test_id) -> bool
```

**Features**:
- httpx async client with connection pooling
- Exponential backoff retry (3 attempts)
- 300-second timeout for long-running tests
- 10 test types (web app, API, network, code, infra, cloud, container, IoT, mobile, social engineering)

**Data models**:
- `MPTEFinding` — structured finding with CWE, CVE, CVSS, evidence, remediation
- `MPTETestResult` — aggregated test results with risk score

### 8.2 integrations/mpte_service.py (469 lines)

Orchestration layer between FixOps findings and MPTE:
- Trigger pen tests from security findings
- Map vulnerability types to MPTE test types
- Track pen test requests in SQLite database
- Verify exploitability from MPTE results
- Continuous monitoring job management

### 8.3 integrations/mpte_decision_integration.py (277 lines)

Decision engine integration — connects pen test results to the FixOps decision pipeline:
- Exploitability level assessment (None, Theoretical, PoC, Weaponized, Active)
- Priority mapping from MPTE findings
- Evidence bundle creation from pen test results

### 8.4 integrations/github/adapter.py (106 lines)

GitHub CI/CD adapter:
- Handles `pull_request` and `check_suite` webhook events
- Evaluates findings through the decision engine
- Renders PR comments with verdict, confidence, evidence
- Extracts repository and PR metadata

**Dependency**: Imports `core.services.enterprise.decision_engine.DecisionEngine` which may not exist in all installations.

### 8.5 integrations/jenkins/adapter.py (82 lines)

Jenkins CI adapter — similar pattern to GitHub adapter but for Jenkins webhook events.

### 8.6 integrations/sonarqube/adapter.py (57 lines)

SonarQube integration — imports findings from SonarQube quality gate results.

### 8.7 api/ide_router.py (980 lines)

IDE integration endpoints for VS Code / JetBrains extensions:
- Real-time finding overlay in editor
- Inline fix suggestions
- Security context for current file
- One-click remediation actions

### 8.8 api/mcp_router.py (468 lines)

Model Context Protocol (MCP) router — allows AI assistants to interact with FixOps via structured prompts.

### 8.9 api/webhooks_router.py (1,802 lines)

Duplicate of the webhook router from suite-api, providing webhook management from the integrations perspective.

### 8.10 lib4sbom/normalizer.py (641 lines)

SBOM normalization utility:
- Merges multiple SBOM documents (CycloneDX + SPDX)
- Component deduplication via PURL/name/version matching  
- Hash normalization (prefers SHA-512 > SHA-384 > SHA-256)
- License set unification
- Generator tracking
- Quality scoring:
  - Coverage % (components with PURLs)
  - Hash presence %
  - License coverage %
  - Version specificity %

**Well-implemented**. Good defensive coding with proper type checking of parsed JSON.

### 8.11 lib4sbom/parser.py (54 lines)

Simple SBOM parser — loads JSON files and detects format (CycloneDX vs SPDX).

### 8.12 ssvc/plugins/deployer.py (169 lines)

SSVC (Stakeholder-Specific Vulnerability Categorization) deployment plugin:
- Decision tree execution for Exploitation, Exposure, Utility, Mission Impact
- Maps SSVC decisions to FixOps actions (remediate, mitigate, monitor, accept)

### 8.13 api/iac_router.py (242 lines)

Infrastructure as Code security scanning:
- Terraform plan analysis
- CloudFormation template validation
- Kubernetes manifest checking

### 8.14 api/oss_tools.py (205 lines)

Open-source tool integrations:
- Trivy (container scanning)
- Grype (SBOM vulnerability matching)
- Syft (SBOM generation)
- Semgrep (SAST)

---

## 9. suite-ui — React Frontend

**Total files**: 95 TypeScript/TSX files  
**Total LOC**: ~20,000+ (estimated)  
**Purpose**: Single-page application for FixOps management

### 9.1 Architecture

```
suite-ui/aldeci/
├── src/
│   ├── App.tsx              — Route definitions (285 lines)
│   ├── main.tsx             — React entry point
│   ├── lib/
│   │   ├── api.ts           — Axios API client (1,258 lines)
│   │   └── utils.ts         — Utility functions
│   ├── pages/               — 57 page components (lazy-loaded)
│   │   ├── Dashboard.tsx
│   │   ├── DataFabric/
│   │   ├── IntelligenceHub/
│   │   ├── DecisionEngine/
│   │   ├── AttackLab/
│   │   ├── RemediationCenter/
│   │   ├── EvidenceVault/
│   │   ├── Settings/
│   │   ├── Copilot/
│   │   ├── Code/            — Code security (CopilotCode, CodeVulnerabilities, etc.)
│   │   ├── Cloud/           — Cloud security (CloudDashboard, CloudCompliance, etc.)
│   │   ├── Attack/          — Attack workspace (AttackDashboard, AttackWorkspace, etc.)
│   │   └── Protect/         — Protection (IASTDashboard, RASPDashboard, etc.)
│   ├── components/
│   │   ├── ui/              — shadcn/ui primitives (Button, Card, Dialog, etc.)
│   │   └── aldeci/          — Custom components
│   ├── stores/              — State management
│   └── hooks/               — Custom React hooks
├── package.json
├── vite.config.ts
├── tailwind.config.ts
└── tsconfig.json
```

### 9.2 Tech Stack

| Library | Purpose |
|---------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool (dev server on port 3001) |
| React Router v6 | Client-side routing |
| TanStack Query | Server state management |
| Axios | HTTP client |
| Framer Motion | Animations |
| Tailwind CSS | Styling |
| shadcn/ui | Component primitives |
| Sonner | Toast notifications |
| Recharts/Victory | Charts and data visualization |
| Lucide | Icons |

### 9.3 api.ts — API Client (1,258 lines)

The central API client managing all backend communication:

```typescript
const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
    timeout: 120000,  // 2 minutes
    headers: { "Content-Type": "application/json" },
});

// Request interceptor adds X-API-Key header
api.interceptors.request.use((config) => {
    const key = getApiKey();
    if (key) config.headers["X-API-Key"] = key;
    return config;
});
```

**API namespaces**:
- `dashboardApi` — Dashboard metrics, trends
- `findingsApi` — Finding CRUD, enrichment
- `integrationsApi` — Integration management
- `pipelineApi` — Brain pipeline execution
- `feedsApi` — Threat intelligence
- `evidenceApi` — Evidence bundles
- `remediationApi` — Fix tracking
- `complianceApi` — Compliance reports
- `attackApi` — Pen testing, DAST, SAST
- `copilotApi` — AI assistant
- `settingsApi` — Configuration

**Problems**:
1. **Default API key in source**: `const DEFAULT_API_KEY = "test-token-123"` — committed to source control
2. **API key in memory only**: Key stored in a closure variable, not localStorage — lost on page refresh
3. **No token refresh**: JWT tokens expire after 24h, no automatic refresh mechanism
4. **120-second timeout**: May be too long for user experience but too short for large pen tests

### 9.4 App.tsx — Route Definitions (285 lines)

All 57 pages lazy-loaded via `React.lazy()`:

```typescript
const Dashboard = lazy(() => import("./pages/Dashboard"));
const DataFabric = lazy(() => import("./pages/DataFabric/DataFabric"));
// ... 55 more
```

**Route structure**:
```
/                          → Dashboard
/data-fabric               → DataFabric (findings, scans, assets)
/intelligence-hub          → IntelligenceHub (threat intel, feeds)
/decision-engine           → DecisionEngine (brain pipeline)
/attack-lab                → AttackLab (pen testing)
/remediation-center        → RemediationCenter (fixes)
/evidence-vault            → EvidenceVault (compliance evidence)
/settings                  → Settings (config, integrations)
/copilot                   → Copilot (AI assistant)
/code/*                    → Code security suite (4 pages)
/cloud/*                   → Cloud security suite (3 pages)
/attack/*                  → Attack workspace (5 pages)
/protect/*                 → Protection suite (6 pages)
/ai/*                      → AI engine pages
/nerve-center              → NerveCenter (ops dashboard)
/evidence/*                → Evidence sub-pages
```

### 9.5 Page Components (57 files)

Each page typically follows this pattern:
```tsx
export default function PageName() {
    const { data, isLoading } = useQuery({...});
    
    if (isLoading) return <LoadingSkeleton />;
    
    return (
        <div className="p-6 space-y-6">
            <PageHeader title="..." />
            <MetricCards data={data} />
            <DataTable data={data} />
        </div>
    );
}
```

Uses TanStack Query for server state, Framer Motion for transitions, Sonner for notifications.

---

## 10. Testing Infrastructure

### 10.1 Configuration

```toml
# pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "unit: Unit tests",
    "integration: Integration tests",
    "e2e: End-to-end tests",
]
addopts = "--cov --cov-fail-under=60"
```

### 10.2 conftest.py (308 lines)

**56 test files in `collect_ignore`**: Many tests import from `src.services.*` modules that don't exist. Rather than fixing the imports, they're excluded from collection:
```python
collect_ignore = [
    "test_risk_adjustment.py",
    "test_rl_controller.py",
    "test_all_137_endpoints_e2e.py",
    # ... 53 more (49 top-level + 7 e2e/)
]
```

This effectively means **56 of 212 test files (26%)** never run.

**Fixtures provided**:
- `sample_cve_data` — Standard CVE test payloads
- `mock_overlay_config` — Configuration with test defaults
- `temp_db` — Temporary SQLite database
- `event_bus` — Fresh event bus instance

### 10.3 Test Coverage

- **212 test files** (test_*.py) across `tests/` directory (239 total .py files including conftest, fixtures, helpers)
- **3,699 test functions** across all test files
- **84,352 lines** of test code
- **56 files excluded** from collection (26% of test files never run)
- **Coverage gate**: 60% minimum (low for a security platform)
- **No security-specific tests**: No tests for auth bypass, SSRF, injection prevention

---

## 11. Build & DevOps

### 11.1 Makefile

```makefile
bootstrap:     # Install deps, create data dirs
fmt:           # isort + black formatting
lint:          # flake8 linting (if configured)
test:          # pytest with coverage
demo:          # Full end-to-end demo pipeline
security-scan: # Bandit security scan
```

### 11.2 Docker

Multiple Docker configurations in `docker/`:
- `Dockerfile` — Standard image
- `Dockerfile.demo` — Demo with seed data
- `Dockerfile.enterprise` — Enterprise with all features
- `Dockerfile.interactive` — Interactive debugging
- `docker-compose.yml` — Full stack (API + UI + deps)
- `docker-compose.demo.yml` — Demo environment
- `docker-compose.enterprise.yml` — Enterprise deployment

### 11.3 Scripts (~60 files)

Utility scripts for operations:
- `demo_orchestrator.py` — Automated demo scenarios
- `seed_data.py` — Database seeding
- `validate_fixops.py` — Health validation
- `deploy-aws.sh` / `deploy-gcp.sh` — Cloud deployment
- `micropentest_sidecar.py` (1,868 lines) — Standalone MPTE CLI sidecar
- `enterprise-e2e-demo.sh` — Enterprise demo runner

---

## 12. Cross-Suite Data Flow

> **Detailed per-endpoint tables**: See [ROUTER_ENDPOINT_INVENTORY.md](ROUTER_ENDPOINT_INVENTORY.md) for the full endpoint-by-endpoint breakdown of all 55 unique router files.

### 12.1 Finding Lifecycle

```
           suite-attack                    suite-core
         ┌───────────────┐              ┌────────────────┐
User → │ micro_pentest  │──finding──→│ brain_pipeline  │
         │ _router.py     │             │ (12 steps)      │
         └───────────────┘              └───────┬────────┘
                                                │
                    ┌───────────────────────────┤
                    ▼                           ▼
              suite-feeds                 suite-core
         ┌───────────────┐          ┌────────────────┐
         │ feeds_service  │──enrich─→│ event_bus      │
         │ (NVD/KEV/EPSS) │          │ (emit events)   │
         └───────────────┘          └───────┬────────┘
                                            │
              ┌─────────────────────────────┤
              ▼                             ▼
       suite-evidence-risk           suite-integrations
    ┌───────────────────┐         ┌──────────────────┐
    │ scoring.py        │         │ connectors.py    │
    │ evidence/packager │         │ (Jira ticket)    │
    │ compliance/mapping│         │ (Slack alert)    │
    └───────────────────┘         └──────────────────┘
              │
              ▼
         suite-ui
    ┌───────────────────┐
    │ Dashboard.tsx      │
    │ (visualize)        │
    └───────────────────┘
```

### 12.2 Event Flow

```
Event: CVE_DISCOVERED
  → EventBus.emit()
    → knowledge_brain.log_event()      # Graph update
    → feeds_service.enrich_cve()       # Threat intel
    → scoring.calculate_risk()         # Risk score
    → connectors.create_ticket()       # Jira integration
    → evidence.create_bundle()         # Compliance evidence
    → notification.send_alert()        # Slack/email
```

**Event types emitted across all suites**:
`FINDING_CREATED`, `REMEDIATION_CREATED`, `REMEDIATION_UPDATED`, `FEED_UPDATED`, `EPSS_UPDATED`, `KEV_ALERT`, `ASSET_DISCOVERED`, `SCAN_STARTED`, `SCAN_COMPLETED`, `PENTEST_STARTED`, `PENTEST_COMPLETED`, `SECRET_FOUND`, `CVE_DISCOVERED`, `GRAPH_UPDATED`, `COPILOT_QUERY`, `COPILOT_RESPONSE`

### 12.3 Import Dependencies (Full Graph)

```
suite-api ──┬── core.analytics_db       (suite-core)
            ├── core.audit_db           (suite-core)
            ├── core.auth_db            (suite-core)
            ├── core.connectors         (suite-core) ← Jira, ServiceNow, GitLab, GitHub, AzureDevOps, Slack, Confluence
            ├── core.security_connectors(suite-core) ← Snyk, SonarQube, Dependabot, AWS Security Hub, Azure Sec Center
            ├── core.event_bus          (suite-core)
            ├── core.findings_db        (suite-core)
            ├── core.integration_db     (suite-core)
            ├── core.inventory_db       (suite-core)
            ├── core.knowledge_brain    (suite-core)
            ├── core.policy_db          (suite-core)
            ├── core.report_db          (suite-core)
            ├── core.user_db            (suite-core)
            ├── core.workflow_db        (suite-core)
            ├── core.autofix_engine     (suite-core)
            ├── core.services.*         (suite-core) ← dedup, collaboration, remediation, fuzzy_identity
            ├── feeds_service           (suite-feeds)
            └── apps.api.normalizers    (self)

suite-core ──┬── core.knowledge_brain   (self — NetworkX graph)
             ├── core.event_bus         (self — asyncio event system)
             ├── core.llm_providers     (self — OpenAI, Anthropic, Google)
             ├── core.api_learning_store(self — scikit-learn ML)
             ├── core.brain_pipeline    (self — 12-step orchestrator)
             ├── core.soc2_evidence     (self — evidence generation)
             ├── core.attack_simulation (self — BAS engine)
             ├── core.autofix_engine    (self)
             ├── core.enhanced_decision (self)
             ├── core.models.*          (self — Markov, Bayesian)
             ├── feeds_service          (suite-feeds) ← EPSS, KEV enrichment
             ├── httpx → MPTE           (suite-attack) ← pentest calls
             └── enterprise modules     (optional — importlib)

suite-attack ┬── core.micro_pentest     (suite-core)
             ├── core.real_scanner      (suite-core)
             ├── core.mpte_db           (suite-core)
             ├── core.mpte_advanced     (suite-core)
             ├── core.exploit_generator (suite-core)
             ├── core.continuous_validation (suite-core)
             ├── core.attack_sim_engine (suite-core)
             ├── core.sast_engine       (suite-core)
             ├── core.cspm_engine       (suite-core)
             ├── core.container_scanner (suite-core)
             ├── core.malware_detector  (suite-core)
             ├── core.dast_engine       (suite-core)
             ├── core.api_fuzzer        (suite-core)
             ├── core.secrets_db/scanner(suite-core)
             ├── core.llm_providers     (suite-core) ← micro_pentest PoC generation
             ├── core.event_bus         (suite-core)
             ├── core.knowledge_brain   (suite-core)
             └── feeds_service          (suite-feeds) ← vuln_discovery ML training

suite-feeds ──┬── feeds_service         (self — FeedsService singleton)
              ├── core.event_bus        (suite-core)
              └── core.knowledge_brain  (suite-core)

suite-evidence-risk ──┬── core.configuration (suite-core)
                      ├── core.event_bus     (suite-core)
                      └── risk.reachability  (self — 13 files, ~5K LOC)

suite-integrations ──┬── core.connectors    (suite-core)
                     ├── core.mpte_*        (suite-core)
                     └── risk.reachability  (suite-evidence-risk)
```

**Circular dependency risk**: suite-core → suite-feeds (for enrichment) and suite-feeds → suite-core (for event bus). Resolved via lazy imports and try/except.

### 12.4 Seven Major Inter-Endpoint Interaction Flows

These flows trace how HTTP requests chain across suites to complete real operations:

#### Flow 1: Finding → Remediation → AutoFix

```
POST /api/v1/analytics/findings         (create finding)
  → Brain.ingest_finding()
  → EventBus.emit(FINDING_CREATED)

POST /api/v1/remediation/tasks           (create remediation task)
  → Brain.ingest_remediation()
  → EventBus.emit(REMEDIATION_CREATED)

POST /api/v1/remediation/tasks/{id}/autofix  (trigger autofix)
  → AutoFixEngine.generate()
  → AutoFixEngine.apply() → creates PR
  → EventBus.emit(REMEDIATION_UPDATED)
```

#### Flow 2: Copilot → Agents → Feeds → MPTE

```
POST /api/v1/copilot/sessions           (create session)
POST /api/v1/copilot/sessions/{id}/messages  (send message → real LLM call)
  → LLMProviderManager.generate()
  → FeedsService enrichment (EPSS, KEV)
  → Brain context injection

POST /api/v1/copilot/actions             (execute agent action)
  → type=analyze → SecurityAnalystAgent
    → FeedsService.get_epss() / .get_kev()
  → type=pentest → PentestAgent
    → httpx → MPTE /api/v1/verify  (verify=False)
  → type=remediate → RemediationAgent
    → AutoFixEngine.generate()
```

#### Flow 3: Feed Refresh → Enrichment → Brain

```
POST /api/v1/feeds/refresh/all           (refresh all feeds)
  → FeedsService.refresh_epss()
  → FeedsService.refresh_kev()
  → FeedsService.refresh_nvd()
  → FeedsService.refresh_exploitdb()
  → FeedsService.refresh_osv()
  → FeedsService.refresh_github_advisories()
  → EventBus.emit(FEED_UPDATED)

POST /api/v1/feeds/enrich                (enrich findings)
  → FeedsService.enrich_findings_comprehensive()
  → Brain.ingest_cve()
  → EventBus.emit(FEED_UPDATED)
```

#### Flow 4: Micro Pentest 8-Phase → Brain → Evidence

```
POST /api/v1/micro-pentest/enterprise/scan  (8-phase scan)
  Phase 1: LLM → target analysis
  Phase 2: LLM → reconnaissance
  Phase 3: LLM → threat modeling
  Phase 4: RealVulnerabilityScanner → findings
  Phase 5: LLM → PoC generation
  Phase 6: compliance validation
  Phase 7: LLM → risk scoring
  Phase 8: attack path generation
  → EventBus.emit(SCAN_STARTED, SCAN_COMPLETED, FINDING_CREATED)
  → Brain.ingest_scan() + Brain.ingest_finding()

POST /api/v1/brain/evidence/generate     (SOC2 evidence bundle)
  → SOC2EvidenceGenerator.generate()
```

#### Flow 5: Vulnerability Discovery → CVE Contribution

```
POST /api/v1/vulns/discovered            (report discovered vuln)
  → Generate ALDECI-YYYY-NNNN ID
  → Brain.ingest_finding()
  → EventBus.emit(FINDING_CREATED)
  → [optional] _notify_vendor() background task

POST /api/v1/vulns/contribute            (submit to CVE program)
  → Validate vuln status (DRAFT/INTERNAL/REPORTED_VENDOR)
  → Update status → CVE_REQUESTED
  → Track submission (MITRE/CISA/CERT/Vendor)
```

⚠️ **Critical**: ALL discovered vulns stored entirely in-memory — lost on restart.

#### Flow 6: Nerve Center → All Suites (System Aggregation)

```
GET /api/v1/nerve-center/state           (full system state)
  → httpx → localhost:8000/api/v1/health     (self-probe)
  → httpx → localhost:8000/api/v1/ml/status  (ML status)
  → Brain.get_stats()                         (graph stats)
  → EventBus.get_recent()                    (recent events)
  → DecisionEngine.get_metrics()             (decision stats)

GET /api/v1/nerve-center/pulse           (real-time threat pulse)
  → Brain risk scoring
  → LearningStore threat assessment
  → EventBus recent alerts
```

#### Flow 7: Deduplication → Bulk → Ticket Creation

```
POST /api/v1/deduplication/batch         (batch dedup)
  → DeduplicationService.process_batch()
  → Returns clusters

GET /api/v1/bulk/clusters                (view clusters)
POST /api/v1/bulk/clusters/{id}/create-ticket  (create ticket)
  → IntegrationDB.get_by_type("jira")
  → JiraConnector.create_issue()
```

### 12.5 Data Store Map

**15+ SQLite-backed stores** (persistent, WAL mode):

| Store | Used By | Purpose |
|-------|---------|---------|
| `AnalyticsDB` | analytics_router | Findings, decisions, trends |
| `AuditDB` | audit_router | Audit logs, controls |
| `AuthDB` | auth_router, users_router | SSO configs, user auth |
| `FeedsDB` | feeds_router | NVD, KEV, EPSS cached data |
| `FindingsDB` | brain_router, dedup | Finding records |
| `IntegrationDB` | integrations_router | Connector configs |
| `InventoryDB` | inventory_router | Asset inventory |
| `MPTEDB` | mpte_integration, mpte_router | Pentest configs/results |
| `PolicyDB` | policies_router | Security policies |
| `ReportDB` | reports_router | Generated reports |
| `RemediationDB` | remediation_router | Remediation tasks |
| `SecretsDB` | secrets_router | Secret scan results |
| `UserDB` | users_router | User accounts |
| `WorkflowDB` | workflows_router | Workflow definitions |
| `CollaborationDB` | collaboration_router | Threads, comments |

**13 routers with in-memory-only state** (lost on restart):

| Router | Variable(s) | Impact |
|--------|-------------|--------|
| `bulk_router.py` | `_jobs` | Background job tracking lost |
| `copilot_router.py` | `_sessions`, `_messages`, `_actions` | Entire conversation state lost |
| `agents_router.py` | `_agent_tasks` | Agent task tracking lost |
| `inventory_router.py` | `_dependency_store`, `_service_store`, `_api_store`, `_component_store` | Components/APIs/deps lost |
| `policies_router.py` | `_violation_store` | Violation records lost |
| `users_router.py` | `_login_attempts` | Rate limiting bypassed via restart |
| `workflows_router.py` | `_sla_store`, `_execution_steps`, `_paused_executions` | SLA + workflow state lost |
| `llm_router.py` | `_settings` | LLM config reverts to defaults |
| `intelligent_engine_routes.py` | `_sessions`, `_results` | ISE session state lost |
| `vuln_discovery_router.py` | `_discovered_vulns`, `_contributions`, `_retrain_jobs` | **ALL discovered vulns lost** |
| `micro_pentest_router.py` | `enterprise_engine._scans`, `_audit_logs`, `_active_scans` | Scan results + audit trail lost |
| `nerve_center.py` | overlay config | Overlay settings revert |
| `new_backend/api.py` | decision feedback | Feedback lost |

### 12.6 Endpoint Classification

| Category | Count | Examples |
|----------|-------|---------|
| **Real LLM calls** | ~25 | copilot/*, agents/actions, micro-pentest/enterprise/scan, enhanced/* |
| **MPTE calls** | ~15 | agents pentest, mpte_router/*, micro_pentest_router/*, mpte_integration/* |
| **SQLite CRUD** | ~250 | analytics/*, audit/*, inventory/*, findings/*, policies/* |
| **In-memory only** | ~50 | copilot/sessions, agents/tasks, vuln_discovery/*, bulk/jobs |
| **Stub/hardcoded** | ~20 | mpte-orchestrator/* (6), remediation agent endpoints (7), bulk legacy (3+) |
| **Aggregation/read-only** | ~40 | nerve-center/*, health/*, stats endpoints, dashboards |
| **Feed operations** | ~30 | feeds/* (refresh, enrich, categories, health) |
| **External connector calls** | ~20 | integrations/test, webhooks/*, Jira/Slack/GitHub actions |

---

## 13. Critical Bugs & Security Vulnerabilities

### Severity: CRITICAL

| # | File | Line(s) | Issue | Impact |
|---|------|---------|-------|--------|
| 1 | `core/auth_middleware.py` | 210-215 | `has_scope()` method missing from `AuthContext` (uses `__slots__`) | Any endpoint using `require_scope()` crashes with `AttributeError` |
| 2 | `core/auth_middleware.py` | 38 | Hardcoded JWT secret `"fixops-dev-secret-change-in-production"` | Any attacker can forge JWT tokens if env var not set |
| 3 | `core/evidence.py` | 130 | Hardcoded fallback encryption key in source code | Evidence bundles can be decrypted by anyone with source access |
| 4 | `core/processing_layer.py` | 170-185 | Bayesian CPD is uniform (`[0.35]*324`) — zero discriminative power | SSVC risk decisions are effectively random — always returns "low" |

### Severity: HIGH

| # | File | Issue | Impact |
|---|------|-------|--------|
| 5 | `core/llm_providers.py` | Anthropic API: `system` role in messages array | Claude calls always fail → consensus is 2-model, not 3-model |
| 6 | `core/brain_pipeline.py` | Synthetic EPSS/KEV enrichment (deterministic from CVSS, not random) | Risk scores plausible but not grounded in real threat intel |
| 7 | `core/micro_pentest.py` | Incomplete SSRF protection (missing 169.254.x.x, fc00::, fe80::, hex) | Metadata service exposure (AWS, GCP, Azure). Note: ::1 IS blocked. |
| 8 | `apps/api/webhooks_router.py` | ServiceNow/Azure DevOps receivers have zero auth | Any internet source can inject webhook payloads |
| 9 | `apps/api/app.py` | ~3 pure in-memory dicts (`artifacts`, `archive_records`, `last_pipeline_result`) plus file/SQLite-backed stores | In-memory items lost on restart; most data persisted via file/SQLite |
| 10 | `apps/api/app.py` | No RBAC — any valid API key = full admin | No access control differentiation |
| 11 | `apps/api/rate_limiter.py` | Rate limiter exists but NOT wired into app | Zero rate limiting protection despite code existing |
| 29 | `workflows_router.py` | `http_call` action in workflow engine allows arbitrary URL requests with no validation | SSRF risk — workflows can probe internal services |
| 30 | `vuln_discovery_router.py` | ALL discovered vulnerabilities (pre-CVE intelligence) stored in-memory only | Complete data loss on restart — no persistence layer |
| 31 | 13 router files | In-memory state in copilot sessions, agent tasks, inventory stores, SLA tracking, etc. | See Section 12.5 — all lost on restart |

### Severity: MEDIUM

| # | File | Issue | Impact |
|---|------|-------|--------|
| 12 | `core/vector_store.py` | Bag-of-words hash trick in InMemoryVectorStore (not true embeddings) | Captures lexical overlap but NOT semantic similarity — two texts sharing words score high, but synonyms/paraphrases score near zero |
| ~~13~~ | ~~`core/brain_pipeline.py`~~ | ~~`asyncio.new_event_loop()` never closed~~ | **VERIFIED FALSE** — both loops call `loop.close()` in `finally` blocks |
| 14 | `core/mpte_advanced.py` | Raw vuln data in LLM prompts | Prompt injection risk |
| 15 | `core/micro_pentest.py` | `verify_ssl = False` globally | MITM vulnerability on all pentest HTTP calls |
| 16 | `attack/api/mpte_router.py` | `httpx.AsyncClient(verify=False)` | MITM vulnerability on MPTE service calls |
| 17 | `core/connectors.py` | `CircuitBreaker` not thread-safe | Race condition under concurrent load |
| ~~18~~ | ~~`core/connectors.py`~~ | ~~`ConnectorOutcome.success` only checks `"sent"`~~ | **VERIFIED FALSE** — checks `("sent", "success", "fetched")` |
| 19 | `suite-ui/lib/api.ts` | Default API key `"test-token-123"` in source | Credential in source code |
| 32 | `agents_router.py` | 7 remediation agent endpoints all return `{"status": "integration_required"}` | Stubs that appear functional but do nothing |
| 33 | `mpte_orchestrator_router.py` | 6 POST endpoints return hardcoded/synthetic responses | MPTE Orchestrator integration is entirely fake |
| 34 | `reports_router.py` | `POST /generate` report generation mostly stubbed | Reports promise but don't deliver |
| 35 | 5 router pairs | Duplicate routers in suite-api and suite-integrations (webhooks, IDE, integrations, IaC, MCP) — identical files (49 endpoints × 2) | Maintenance burden; changes to one copy not reflected in other |
| 36 | 5 routers | Prefix inconsistencies: `decisions.py` → `/decisions` (not `/api/v1/decisions`), `pipeline_router.py` → `/api/v1/brain` (conflicts with brain_router), `mpte_integration.py` → `/mpte` (conflicts with mpte_router) | Route conflicts, inconsistent API surface |

### Severity: LOW

| # | File | Issue | Impact |
|---|------|-------|--------|
| 20 | `core/auth_middleware.py` | Dev-mode bypass enabled by default | Default deployment has no authentication |
| 21 | Multiple files | `datetime.utcnow()` deprecated since Python 3.12 | Deprecation warnings, eventually removed |
| 22 | `core/stage_runner.py` | `FIXOPS_FAKE_NOW` env var in production code | Time manipulation backdoor |
| 23 | `core/event_bus.py` | Dead `_bus` variable never used | Dead code |
| 24 | `core/cli.py` | Side-effects at import time | Unexpected behavior when importing module |
| 25 | `tests/conftest.py` | 56 test files in collect_ignore | 26% of test files never execute |
| 26 | `core/knowledge_brain.py` | Loads all nodes into memory on init | Won't scale past ~100K nodes |
| 27 | `core/crypto.py` | Private keys serialized with `NoEncryption()` | Key file compromise = immediate access |
| 28 | `core/hallucination_guards.py` | Exact string citation matching | Legitimate citations flagged as hallucinated |

---

## 14. Architectural Concerns

### 14.1 Data Persistence

**Corrected**: The app uses **15+ SQLite-backed stores** (WAL mode) for persistent data: analytics, audit, auth, feeds, findings, integrations, inventory, MPTE, policies, reports, remediation, secrets, users, workflows, and collaboration.

However, **13 routers maintain critical in-memory-only state** that is lost on every restart:
- **Highest risk**: `vuln_discovery_router.py` — ALL pre-CVE intelligence in `_discovered_vulns`, `_contributions`, `_retrain_jobs` (in-memory dicts with no persistence)
- **High risk**: `copilot_router.py` — entire conversation state (`_sessions`, `_messages`, `_actions`)
- **High risk**: `inventory_router.py` — 4 separate in-memory stores for deps, services, APIs, components
- **Medium risk**: `workflows_router.py` — SLA tracking, execution steps, paused executions
- **Medium risk**: `micro_pentest_router.py` — scan results, audit logs, active scans
- **Low risk**: `app.py` — `artifacts`, `archive_records`, `last_pipeline_result` (3 dicts)

See Section 12.5 for the complete in-memory state table.

### 14.2 Monolith Scalability

The single-process architecture means:
- **No horizontal scaling**: Can't add more API servers
- **Single point of failure**: One process crash = complete outage
- **Memory pressure**: All data in one process's memory
- **CPU bottleneck**: Long-running pen tests block the event loop

### 14.3 Silent Failure Pattern

The `try/except ImportError` pattern for router loading hides real errors:
```python
try:
    from attack.api.dast_router import router as dast_router
    app.include_router(dast_router)
except ImportError:
    logger.warning("dast_router not available")  # Could be a real bug
```

A typo in an import path, a missing dependency, or a syntax error in the router file all produce the same "not available" warning. No distinction between expected and unexpected failures.

### 14.4 Testing Gaps

- **60% coverage gate** is low for a security platform handling sensitive data
- **56 test files excluded** from collection due to broken imports (26% of all test files)
- **No security-focused tests**: No tests for auth bypass, injection prevention, SSRF protection
- **No integration tests** with real external services
- **No load/stress tests** for concurrent operations

### 14.5 Duplicated Code

**5 identical router file pairs** exist between `suite-api/apps/api/` and `suite-integrations/api/`:

| Router | Endpoints | Byte-identical |
|--------|-----------|---------------|
| `webhooks_router.py` | 19 | ✅ Yes |
| `ide_router.py` | 5 | ✅ Yes |
| `integrations_router.py` | 8 | ✅ Yes |
| `iac_router.py` | 7 | ✅ Yes |
| `mcp_router.py` | 10 | ✅ Yes |
| **Total duplicated** | **49 endpoints × 2** | |

These are not symlinks — they are full file copies. A bug fix in one copy will not propagate to the other. Only `suite-api` copies are loaded in `app.py`; the `suite-integrations` copies are dead code.

Additionally, MPTE-related logic is scattered across:
- `suite-core/core/mpte_advanced.py` (engine)
- `suite-attack/api/mpte_router.py` (API)
- `suite-api/apps/mpte_integration.py` (standalone app with 25 endpoints)
- `suite-integrations/integrations/mpte_client.py` (client)
- `suite-integrations/integrations/mpte_service.py` (service wrapper)

### 14.6 Configuration Complexity

The overlay configuration system (`configuration.py` at 1,528 lines) provides powerful hierarchical merging but is itself a complexity risk:
- 4 configuration layers (defaults → environment → env vars → feature flags)
- No schema validation for configuration files
- Feature flag provider adds runtime dynamism that's hard to test

### 14.7 LLM Consensus Fragility

The multi-LLM consensus system is theoretically sound but practically fragile:
1. Anthropic provider is broken (system message in wrong location) → always falls back
2. If OpenAI key is not set → falls back to heuristic
3. If Gemini key is not set → falls back to heuristic
4. In practice, the "multi-LLM consensus" may be "single-heuristic" in most deployments

### 14.8 Frontend-Backend Contract

No OpenAPI schema validation between frontend and backend:
- Frontend API client (`api.ts`) has hardcoded endpoint URLs that must match backend routes
- No TypeScript types generated from backend Pydantic models
- Breaking backend changes silently break the frontend

---

## 15. Recommendations

### Priority 1: Security Fixes (Do Immediately)

1. **Fix `AuthContext.has_scope()`** — Add the method to the class:
   ```python
   class AuthContext:
       __slots__ = ("user_id", "email", "role", "org_id", "scopes", "auth_method")
       # ... existing __init__ ...
       
       def has_scope(self, scope: str) -> bool:
           return scope in self.scopes
   ```

2. **Remove hardcoded JWT secret** — Fail loudly if `FIXOPS_JWT_SECRET` is not set in production:
   ```python
   _JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET")
   if not _JWT_SECRET and os.getenv("FIXOPS_AUTH_MODE") == "enforced":
       raise RuntimeError("FIXOPS_JWT_SECRET must be set in enforced auth mode")
   _JWT_SECRET = _JWT_SECRET or "fixops-dev-secret-DO-NOT-USE-IN-PRODUCTION"
   ```

3. **Remove hardcoded encryption key** — Always require the key from environment or disable encryption.

4. **Fix Anthropic API call** — Move system message to top-level parameter.

5. **Extend SSRF protection** — `::1` is already blocked. Add: `169.254.x.x` (metadata), `fc00::` / `fe80::` (IPv6 private), hex/octal encoded IPs, DNS rebinding protection.

6. **Wire rate limiter** — Add `RateLimitMiddleware` to the FastAPI app.

7. **Add webhook authentication** — Require HMAC signature or bearer token for inbound webhooks.

### Priority 2: Data Integrity (Do This Sprint)

8. **Persist ALL in-memory stores** — 13 routers store critical state in-memory (see Section 12.5). Highest priority: `vuln_discovery_router.py` (pre-CVE intelligence), `copilot_router.py` (conversation state), `inventory_router.py` (4 separate stores). Migrate all to SQLite WAL, matching the pattern already used by 15+ existing stores.

9. **Fix Bayesian CPD** — Replace uniform probabilities with SSVC-accurate conditional probabilities that actually discriminate based on evidence.

10. **Connect real EPSS/KEV enrichment** — brain_pipeline step 5 currently derives synthetic EPSS/KEV from CVSS (deterministic, not random). Connect it to the actual feeds_service for real threat intel data.

11. ~~Fix `ConnectorOutcome.success`~~ — **NOT A BUG**: Already checks `("sent", "success", "fetched")`.

### Priority 3: Code Quality (This Quarter)

12. **Split app.py** — Extract remaining in-memory stores into persistent backends; extract business logic into service classes.

13. **Split cli.py** — Use Click or Typer subcommand groups to break 5,908 lines into manageable files.

14. **Fix collect_ignore** — Fix the broken imports in the 56 excluded test files (26% of all tests) or remove dead tests.

15. **Add OpenAPI schema generation** — Generate TypeScript types from Pydantic models for frontend-backend contract safety.

16. **Increase coverage gate** — Target 80%+ for security-critical code paths.

17. **Remove duplicate router files** — Delete the 5 identical copies in `suite-integrations/api/` (webhooks, IDE, integrations, IaC, MCP) — they're dead code since only `suite-api` copies load in `app.py`.

18. **Implement stub endpoints** — Either wire the ~20 stub endpoints (agents remediation, MPTE Orchestrator, bulk legacy) to real backends or remove them from the API surface to avoid confusion.

19. **Fix prefix inconsistencies** — Standardize `decisions.py` → `/api/v1/decisions`, resolve `pipeline_router` ↔ `brain_router` prefix conflict on `/api/v1/brain`.

### Priority 4: Architecture (This Quarter)

20. **Add RBAC** — Implement role-based access control using the existing `UserRole` enum and scopes.

21. **Add health checks** — `/health` and `/ready` endpoints for container orchestration.

22. ~~Close event loops~~ — **NOT A BUG**: Both `asyncio.new_event_loop()` calls already have `loop.close()` in `finally` blocks.

23. **Thread-safe circuit breaker** — Use `threading.Lock` in `CircuitBreaker`.

24. **Fix SSRF in workflows** — Add URL validation/allowlist to `http_call` action in `workflows_router.py`.

---

## 16. Big Picture — How 640 Unique Endpoints Connect

> 689 raw endpoints − 49 in 5 identical duplicate files = **640 unique endpoints**

### 16.1 System Architecture Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        REACT SPA (:3001)                           │
│  57 page components → axios → X-API-Key auth → localhost:8000      │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTP
┌────────────────────────────────▼────────────────────────────────────┐
│                   FASTAPI GATEWAY (:8000)                          │
│               apps/api/app.py — 27 routers loaded                  │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Middleware: CORS → API Key Auth (dev-mode bypass default)   │   │
│  │ No RBAC · No rate limiting (exists but not wired)           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── SUITE-API (16 routers, ~160 endpoints) ──────────────────┐   │
│  │ analytics(22) audit(14) auth(4) bulk(12)                    │   │
│  │ collaboration(21) health(4) integrations(8) inventory(19)   │   │
│  │ marketplace(12) policies(11) remediation(15) reports(14)    │   │
│  │ enhanced(4) teams(8) users(6) validation(3) workflows(13)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── SUITE-CORE (17 routers, ~125 endpoints) ─────────────────┐   │
│  │ agents(32) algorithmic(11) autofix(12) brain(22)            │   │
│  │ code-to-cloud(2) copilot(18) decisions(6) dedup(18)         │   │
│  │ exposure_case(8) fuzzy_identity(7) intelligent_engine(11)   │   │
│  │ llm_monitor(4) llm(6) ml(15) nerve_center(9)               │   │
│  │ pipeline(7) predictions(8) streaming(2)                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── SUITE-ATTACK (12 routers, ~65 endpoints) ────────────────┐   │
│  │ micro_pentest(20) mpte(22) vuln_discovery(11)               │   │
│  │ attack_sim(14) mpte_orchestrator(8*stub) secrets(8) sast(4)           │   │
│  │ cspm(4) container(3) malware(4) dast(2) api_fuzzer(3)      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── SUITE-FEEDS (1 router, 30 endpoints) ────────────────────┐   │
│  │ feeds_router(30): refresh/enrich 8 feed categories          │   │
│  │ NVD · KEV · EPSS · ExploitDB · OSV · GitHub Advisories     │   │
│  │ National CERTs · Early Signal (Mastodon/Reddit/Twitter)     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── SUITE-EVIDENCE-RISK (6 files, 31 endpoints) ────────────┐   │
│  │ risk scoring · threat modeling · compliance mapping          │   │
│  │ evidence packaging · reachability analysis · runtime mon    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── STANDALONE (3 apps, ~31 endpoints) ──────────────────────┐   │
│  │ mpte_integration(25) new_backend/api(3) collector_api(3)    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─── DEAD CODE (5 duplicate files, 49 endpoints) ────────────┐   │
│  │ suite-integrations/api/ — byte-identical copies of          │   │
│  │ webhooks, IDE, integrations, IaC, MCP routers               │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│   15+ SQLite │   │ 3 LLM Providers  │   │ External APIs    │
│   WAL DBs    │   │ OpenAI (works)   │   │ Jira · Slack     │
│              │   │ Anthropic(broken)│   │ GitHub · GitLab  │
│ analytics    │   │ Gemini (works)   │   │ ServiceNow       │
│ audit        │   │                  │   │ Azure DevOps     │
│ auth         │   │ Heuristic        │   │ Snyk · SonarQube │
│ feeds        │   │ fallback active  │   │ AWS SecHub       │
│ findings     │   │ in most deploys  │   │ NVD · KEV · EPSS │
│ integration  │   └──────────────────┘   │ ExploitDB · OSV  │
│ inventory    │                          └──────────────────┘
│ mpte         │
│ policy       │   ┌──────────────────┐
│ report       │   │ In-Memory State  │
│ remediation  │   │ (13 routers)     │
│ secrets      │   │ ⚠ Lost on restart│
│ user         │   │ vuln_discovery   │
│ workflow     │   │ copilot sessions │
│ collaboration│   │ agent tasks      │
└──────────────┘   │ inventory stores │
                   │ SLA tracking     │
                   │ etc.             │
                   └──────────────────┘
```

### 16.2 Data Flow Summary

Every HTTP request follows one of these patterns:

```
Pattern 1: CRUD (250+ endpoints)
  Client → FastAPI → SQLite DB → Response
  Example: GET /api/v1/analytics/findings → AnalyticsDB.query()

Pattern 2: LLM-Powered (25 endpoints)
  Client → FastAPI → LLMProviderManager → OpenAI/Gemini API → Brain enrichment → Response
  Example: POST /api/v1/copilot/sessions/{id}/messages → GPT-4 + FeedsService + Brain

Pattern 3: Scan/Pentest (15 endpoints)
  Client → FastAPI → MicroPentest/RealScanner → 8-phase LLM pipeline → EventBus → Brain → Response
  Example: POST /api/v1/micro-pentest/enterprise/scan → 8 phases → findings

Pattern 4: Feed Refresh (30 endpoints)
  Client → FastAPI → FeedsService → External API (NVD/KEV/EPSS) → SQLite → EventBus → Response
  Example: POST /api/v1/feeds/refresh/all → 8 feed sources → FeedsDB

Pattern 5: Integration/Webhook (20 endpoints)
  Client → FastAPI → Connector → External Service (Jira/Slack/GitHub) → Response
  External → Webhook → FastAPI → EventBus → Brain → Response

Pattern 6: Stub (20 endpoints)
  Client → FastAPI → Hardcoded response (no actual work)
  Example: POST /api/v1/mpte-orchestrator/analyze → {"status": "stub", ...}
```

### 16.3 The Complete Endpoint Count

| Category | Unique Endpoints | Notes |
|----------|-----------------|-------|
| suite-api routers | ~160 | 16 routers |
| suite-core routers | ~125 | 17 routers |
| suite-attack routers | ~65 | 12 routers |
| suite-feeds routers | ~30 | 1 router |
| suite-evidence-risk | ~31 | 6 files |
| Standalone apps | ~31 | 3 apps |
| app.py inline routes | ~23 | Main app file |
| **Unique total** | **~640** | 55 unique router files + app.py |
| Duplicate copies | 49 | 5 byte-identical files in suite-integrations |
| **Raw total (grep)** | **689** | All `@router.*` decorators |

### 16.4 What's Real vs. What's Stub

| Maturity | Endpoints | Percentage |
|----------|-----------|-----------|
| **Production-grade** (SQLite-backed CRUD) | ~250 | 39% |
| **Functional** (works but has issues — TLS, in-memory, etc.) | ~280 | 44% |
| **Stub/Hardcoded** (returns fake data or `integration_required`) | ~60 | 9% |
| **Dead code** (duplicate files never loaded) | ~49 | 8% |

> **Per-endpoint details**: See [ROUTER_ENDPOINT_INVENTORY.md](ROUTER_ENDPOINT_INVENTORY.md) for the full endpoint-by-endpoint table covering all 55 unique router files with method, path, purpose, data store, and concerns for every endpoint.

---

## Appendix A: File Inventory by Suite

### suite-core/core/ (32 files, ~25,000 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| cli.py | 5,908 | CLI interface |
| connectors.py | 3,005 | Enterprise connectors |
| micro_pentest.py | 2,007 | Core vulnerability scanner |
| configuration.py | 1,528 | Overlay configuration |
| playbook_runner.py | 1,270 | Playbook execution engine |
| stage_runner.py | 1,150 | Pipeline stage processor |
| mpte_advanced.py | 1,090 | Multi-AI pen testing |
| brain_pipeline.py | 863 | 12-step orchestration |
| knowledge_brain.py | 853 | Knowledge graph |
| probabilistic.py | 693 | Monte Carlo / Bayesian |
| llm_providers.py | 664 | Multi-LLM adapter |
| crypto.py | 571 | RSA signing |
| processing_layer.py | 462 | Bayesian networks |
| vector_store.py | 445 | Vector similarity search |
| evidence.py | 436 | Evidence bundles |
| model_registry.py | 471 | Model versioning |
| ai_agents.py | ~400 | Agent framework |
| exploit_signals.py | ~350 | Exploit scoring |
| hallucination_guards.py | 325 | LLM output validation |
| decision_tree.py | 330 | CVE analysis |
| analytics.py | ~300 | Dashboard metrics |
| compliance.py | ~300 | Compliance mappings |
| storage.py | ~250 | Abstract storage |
| feedback.py | ~250 | User feedback |
| event_bus.py | 243 | Async event bus |
| auth_middleware.py | 235 | JWT + API key auth |
| policy.py | ~200 | Policy evaluation |
| logging_config.py | ~150 | Structlog config |
| paths.py | ~100 | Path utilities |

### suite-api/ (~35 files, ~15,000 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| apps/api/app.py | 2,456 | Main FastAPI app |
| apps/api/webhooks_router.py | 1,803 | Webhook management |
| apps/api/integrations_router.py | 482 | Integration CRUD |
| apps/api/upload_manager.py | 245 | File uploads |
| apps/api/rate_limiter.py | ~200 | Rate limiting (UNUSED) |
| apps/api/auth_router.py | ~200 | Auth endpoints |
| apps/api/middleware.py | ~110 | Request middleware |
| apps/api/dependencies.py | 85 | DI helpers |
| backend/app.py | 13 | Entry point wrapper |

### suite-attack/api/ (13 files, ~8,000 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| micro_pentest_router.py | 1,818 | Enterprise pen testing |
| mpte_router.py | 726 | MPTE orchestration |
| mpte_orchestrator_router.py | ~300 | MPTE Orchestrator integration |
| attack_sim_router.py | ~300 | Attack simulation |
| vuln_discovery_router.py | ~250 | Vulnerability discovery |
| api_fuzzer_router.py | ~250 | API fuzzing |
| container_router.py | ~250 | Container security |
| cspm_router.py | ~200 | Cloud posture management |
| secrets_router.py | ~200 | Secret detection |
| malware_router.py | ~200 | Malware analysis |
| sast_router.py | ~80 | Static analysis |
| dast_router.py | ~45 | Dynamic analysis |

### suite-feeds/ (~15 files, ~5,000 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| feeds_service.py | 3,042 | Intelligence aggregation |
| api/feeds_router.py | 1,211 | Feeds REST API |

### suite-evidence-risk/ (~40 files, ~12,000 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| risk/reachability/proprietary_analyzer.py | 964 | Proprietary reachability |
| risk/reachability/analyzer.py | 810 | Enterprise reachability |
| risk/runtime/iast_advanced.py | 675 | Advanced IAST |
| risk/reachability/code_analysis.py | 553 | Code analysis |
| risk/reachability/git_integration.py | 486 | Git integration |
| risk/reachability/api.py | 492 | Reachability API |
| risk/scoring.py | 467 | Risk profiling |
| risk/sbom/generator.py | 424 | SBOM generation |
| risk/feeds/exploits.py | 431 | Exploit feeds |
| risk/runtime/iast.py | 400 | IAST engine |
| risk/threat_model.py | 378 | Threat modeling |
| risk/reachability/orchestrator.py | 378 | Feed orchestration |
| risk/runtime/rasp.py | 354 | RASP engine |
| risk/reachability/proprietary_scoring.py | 376 | Scoring engine |
| risk/reachability/proprietary_threat_intel.py | 344 | Threat intel |
| risk/runtime/container.py | 340 | Container security |
| risk/reachability/storage.py | 338 | Reachability storage |
| evidence/packager.py | 335 | Evidence bundles |
| risk/feeds/ecosystems.py | 352 | Ecosystem feeds |
| risk/feeds/base.py | 334 | Feed base class |
| risk/enrichment.py | 306 | CVE enrichment |
| compliance/mapping.py | 307 | CWE-to-control mapping |
| risk/reachability/proprietary_consensus.py | 299 | Consensus engine |
| risk/feeds/vendors.py | 269 | Vendor advisories |
| risk/iac/terraform.py | 262 | Terraform scanning |
| risk/feeds/github.py | 261 | GitHub advisories |
| risk/runtime/cloud.py | 231 | Cloud protection |
| risk/feeds/nvd.py | 233 | NVD client |
| risk/feeds/osv.py | 223 | OSV client |
| risk/reachability/call_graph.py | 213 | Call graph builder |
| compliance/templates/owasp.py | 210 | OWASP template |
| risk/reachability/monitoring.py | 246 | Analysis monitoring |
| risk/reachability/cache.py | 165 | Result caching |
| risk/reachability/data_flow.py | 149 | Data flow analysis |
| risk/feeds/epss.py | 146 | EPSS client |
| risk/feeds/kev.py | 135 | KEV client |

### suite-integrations/ (23 files, ~6,500 LOC)
| File | Lines | Purpose |
|------|-------|---------|
| api/webhooks_router.py | 1,802 | Webhook management |
| api/ide_router.py | 980 | IDE integration |
| lib4sbom/normalizer.py | 641 | SBOM normalization |
| api/integrations_router.py | 481 | Integration CRUD |
| integrations/mpte_service.py | 469 | MPTE orchestration |
| api/mcp_router.py | 468 | MCP protocol |
| integrations/mpte_client.py | 387 | MPTE HTTP client |
| integrations/mpte_decision_integration.py | 277 | Decision integration |
| api/iac_router.py | 242 | IaC scanning |
| api/oss_tools.py | 205 | OSS tool integration |
| ssvc/plugins/deployer.py | 169 | SSVC deployment |
| integrations/github/adapter.py | 106 | GitHub CI adapter |
| integrations/jenkins/adapter.py | 82 | Jenkins CI adapter |
| integrations/sonarqube/adapter.py | 57 | SonarQube adapter |
| lib4sbom/parser.py | 54 | SBOM parser |

---

## Appendix B: Database Schema Overview

FixOps uses **multiple SQLite databases** (WAL mode):

| Database | Owner | Purpose |
|----------|-------|---------|
| `knowledge_brain.db` | core/knowledge_brain.py | Node/edge graph storage |
| `feeds.db` | feeds/feeds_service.py | Vulnerability intelligence cache |
| `auth.db` | core/auth_db.py | Users, API keys, sessions |
| `mpte.db` | core/mpte_db.py | Pen test requests/results |
| `evidence.db` | core/evidence.py | Evidence bundle metadata |
| `config.db` | core/configuration.py | Dynamic configuration |
| `reachability.db` | risk/reachability/storage.py | Reachability analysis results |
| `analytics.db` | core/analytics.py | Dashboard metrics |

---

## Appendix C: Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_JWT_SECRET` | `fixops-dev-secret-...` | JWT signing key |
| `FIXOPS_AUTH_MODE` | `dev` | Auth mode: dev / enforced |
| `FIXOPS_JWT_EXPIRY_HOURS` | `24` | JWT token TTL |
| `FIXOPS_DEMO_MODE` | `false` | Enable demo/synthetic data |
| `FIXOPS_FAKE_NOW` | (unset) | Override current time |
| `FIXOPS_TEST_SEED` | (unset) | Deterministic test seed |
| `OPENAI_API_KEY` | (unset) | OpenAI provider |
| `ANTHROPIC_API_KEY` | (unset) | Anthropic provider |
| `GOOGLE_API_KEY` | (unset) | Google Gemini provider |
| `VITE_API_URL` | `http://localhost:8000` | Frontend API URL |
| `VITE_API_KEY` | (unset) | Frontend API key |

---

## Appendix D: API Surface Summary

**Total endpoints: 689** across 66 router files (27 loaded in `app.py`)

| Suite | Endpoints | HTTP Methods |
|-------|-----------|-------------|
| suite-api | 275 | GET, POST, PUT, PATCH, DELETE |
| suite-core | 200 | GET, POST, PUT, DELETE |
| suite-attack | 96 | GET, POST, PUT, DELETE |
| suite-integrations | 57 | GET, POST, PUT, DELETE |
| suite-evidence-risk | 31 | GET, POST, PUT, DELETE |
| suite-feeds | 30 | GET, POST |
| **Total** | **689** | GET: 366, POST: 266, PUT: 35, PATCH: 3, DELETE: 19 |

**Top router files by endpoint count**:

| Router File | Endpoints |
|-------------|----------|
| `suite-core/api/agents_router.py` | 32 |
| `suite-feeds/api/feeds_router.py` | 30 |
| `suite-api/apps/api/app.py` | 23 |
| `suite-core/api/brain_router.py` | 22 |
| `suite-api/apps/api/analytics_router.py` | 22 |
| `suite-api/apps/mpte_integration.py` | 21 |
| `suite-api/apps/api/collaboration_router.py` | 21 |
| `suite-integrations/api/webhooks_router.py` | 19 |
| `suite-attack/api/mpte_router.py` | 19 |
| `suite-api/apps/api/webhooks_router.py` | 19 |
| `suite-api/apps/api/inventory_router.py` | 19 |
| `suite-core/api/deduplication_router.py` | 18 |
| `suite-attack/api/micro_pentest_router.py` | 18 |

---

*End of comprehensive analysis. Document covers 428 Python files across 6 backend suites, 95 TypeScript/TSX files in the frontend, 212 test files (3,699 test functions, 84K LOC), and ~60 utility scripts. 689 API endpoints across 66 router files (640 unique, 49 duplicates). 55 unique router files fully inventoried with per-endpoint detail in [ROUTER_ENDPOINT_INVENTORY.md](ROUTER_ENDPOINT_INVENTORY.md). Identified 36 confirmed bugs/vulnerabilities (4 false positives removed), 13 in-memory state concerns, 5 prefix inconsistencies, ~20 stub endpoints, 7 cross-suite interaction flows, and 8 architectural concerns with 24 prioritized recommendations.*
