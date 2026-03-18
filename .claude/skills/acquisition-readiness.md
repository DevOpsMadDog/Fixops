# Skill: Acquisition Readiness — Due Diligence Preparation

> What acquirers and investors check, and how to make ALdeci pass with flying colors.

## The 7 Due Diligence Categories

| Category | Weight | What They Check | Current Grade |
|----------|--------|-----------------|---------------|
| **Code Quality** | 20% | Architecture, test coverage, tech debt, SAST findings | C+ |
| **Security Posture** | 20% | Auth, tenancy, dependency vulns, secrets handling, pen-test results | C |
| **IP & Legal** | 15% | License file, OSS compliance, patent claims, SBOM | D (no LICENSE) |
| **Operational Maturity** | 15% | CI/CD, deployment, monitoring, incident response | C |
| **Data Architecture** | 10% | Schema design, migration strategy, backup/restore, multi-tenancy | D+ |
| **Team & Documentation** | 10% | Architecture docs, API docs, README, onboarding time | B- |
| **Market & Product** | 10% | Competitors, differentiation, customer validation | B+ |

## Category 1: Code Quality

### What Needs to Exist
- [ ] Test coverage > 50% (currently 19%)
- [ ] Zero SAST critical/high findings in own code
- [ ] No dead code modules > 500 LOC
- [ ] Consistent coding style (black + isort enforced)
- [ ] Type hints on all public functions
- [ ] No circular imports

### Quick Wins
```bash
# Run formatter:
make fmt  # or: isort . && black .

# Count untyped public functions:
grep -rn "def [a-z].*):$" suite-core/core/ --include="*.py" | grep -v "__" | grep -v "test_" | wc -l
# (Missing return type annotations)

# Check for dead imports:
pip install autoflake
autoflake --check --remove-all-unused-imports -r suite-core/ suite-api/
```

## Category 2: Security Posture

### What Needs to Exist
- [ ] All endpoints authenticated (currently ~95%)
- [ ] Multi-tenant data isolation (currently 15/68 routers)
- [ ] Zero f-string SQL (currently 39)
- [ ] Zero bare `except Exception` in auth/crypto paths
- [ ] SBOM generated (CycloneDX 1.5 or SPDX 2.3)
- [ ] Dependencies scanned (Trivy/Grype)
- [ ] CORS properly configured (not `*`)
- [ ] Rate limiting on all mutation endpoints
- [ ] API key rotation mechanism
- [ ] Audit trail for all admin operations

### Generate SBOM
```bash
# Python dependencies:
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o sbom-python.json --format json

# JavaScript dependencies:
cd suite-ui/aldeci && npx @cyclonedx/cyclonedx-npm --output-file sbom-frontend.json

# Scan for vulnerabilities:
trivy fs --format json --output trivy-scan.json .
grype sbom:sbom-python.json --output json > grype-scan.json
```

## Category 3: IP & Legal

### LICENSE File (CRITICAL — Currently Missing)
```bash
# Create a proprietary license:
cat > LICENSE << 'EOF'
Copyright (c) 2024-2026 ALdeci Inc. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, 
distribution, modification, or use of this software, via any medium, 
is strictly prohibited.

This software is licensed, not sold. See your license agreement for 
terms and conditions of use.
EOF
```

### OSS Inventory
```bash
# List all Python dependencies and their licenses:
pip install pip-licenses
pip-licenses --format=json --output-file=oss-licenses.json

# Check for copyleft (GPL) that might taint proprietary code:
pip-licenses | grep -i "GPL"
# If any found: MUST verify usage is compatible (linking vs separate process)
```

### IP Inventory
Create `docs/IP_INVENTORY.md`:
- List all proprietary algorithms (Brain Pipeline, MPTE, FAIL Engine, etc.)
- List all trade secrets (scoring heuristics, consensus algorithm)
- List all potential patent claims
- List all third-party code included (with license)

## Category 4: Operational Maturity

### What Needs to Exist
- [ ] CI/CD pipeline (GitHub Actions — EXISTS)
- [ ] Docker deployment (EXISTS — 16 Dockerfiles)
- [ ] Kubernetes support (EXISTS — Helm chart)
- [ ] Health check endpoint (EXISTS — needs deep check)
- [ ] Prometheus metrics endpoint (MISSING)
- [ ] Log aggregation (MISSING)
- [ ] Incident runbook (MISSING)
- [ ] Backup/restore procedure (MISSING)
- [ ] Blue/green or canary deployment (MISSING)

### Minimum Viable Runbook
Create `docs/INCIDENT_RUNBOOK.md`:
```markdown
## Incident Response

### Service Down
1. Check health: `curl http://HOST:8000/health/deep`
2. Check logs: `docker logs aldeci-api --tail 100`
3. Restart: `docker compose restart api`

### Database Issues
1. Check connections: `curl http://HOST:8000/health/deep | jq '.checks.database'`
2. Check disk: `df -h /data`
3. If corrupted: Restore from latest backup

### Memory Leak
1. Check: `docker stats aldeci-api`
2. If > 2GB: `docker compose restart api`
3. File issue with heap dump
```

## Category 5: Data Architecture

### What Needs to Exist
- [ ] Single database system (currently DUAL: 185 sqlite3 + 42 PersistentDict + 37 DatabaseManager)
- [ ] Schema migrations (Alembic — EXISTS but only 2 migrations)
- [ ] Multi-tenant data model (org_id on EVERY table)
- [ ] Backup/restore tested
- [ ] Data retention policy
- [ ] PII handling documented

### Data Model Documentation
Create `docs/DATA_MODEL.md` with:
- Entity relationship diagram (Mermaid)
- Table inventory with owner (which suite)
- PII classification per table
- Retention policy per data type
- Backup frequency per criticality

## Category 6: Documentation

### What Needs to Exist
- [x] README.md (EXISTS)
- [x] Architecture overview (EXISTS — CLAUDE.md, copilot-instructions.md)
- [ ] API documentation (OpenAPI/Swagger — auto-generated but needs cleanup)
- [ ] Deployment guide (DEPLOYMENT.md EXISTS but verify accuracy)
- [ ] Developer onboarding guide
- [ ] Architecture Decision Records (ADRs)
- [ ] Security whitepaper

### API Documentation
```bash
# Verify Swagger UI works:
curl -s http://localhost:8000/docs | head -20
# Should return HTML for Swagger UI

# Export OpenAPI spec:
curl -s http://localhost:8000/openapi.json > docs/openapi.json
```

### Architecture Decision Records
Create `docs/adr/` directory with key decisions:
```
docs/adr/
├── 001-monolith-architecture.md
├── 002-sqlite-to-postgresql.md
├── 003-multi-llm-consensus.md
├── 004-air-gapped-deployment.md
├── 005-event-bus-over-mq.md
└── 006-sitecustomize-imports.md
```

## Category 7: Market & Product

### Competitive Analysis Document
Create `docs/COMPETITIVE_ANALYSIS.md`:

| Feature | ALdeci | Snyk | Wiz | Apiiro | Aikido |
|---------|--------|------|-----|--------|--------|
| Native Scanners | 8 | 1 (SCA) | 0 | 0 | 3 |
| Brain Pipeline | 12-step | N/A | N/A | Risk Graph | N/A |
| AutoFix | 10 types | 1 | 0 | 0 | 1 |
| Air-Gapped | Full | No | No | No | No |
| MCP Gateway | 650 tools | No | No | No | No |
| Multi-LLM | 3+ consensus | No | No | 1 LLM | 1 LLM |
| MPTE | 19-phase | No | No | No | No |

### Customer Validation Artifacts
- [ ] 3+ customer testimonials or case studies
- [ ] Pilot deployment metrics
- [ ] NPS or CSAT scores
- [ ] ROI calculator

## Due Diligence Checklist (Executive Summary)

```bash
# Run this to check current readiness:

echo "=== CODE QUALITY ==="
# Test coverage:
python -m pytest tests/ --cov=. --cov-report=term -q --timeout=10 2>&1 | grep "TOTAL"
# Collection errors:
python -m pytest tests/ --collect-only -q 2>&1 | grep "error" | wc -l

echo "=== SECURITY ==="
# f-string SQL:
grep -rn "f\".*SELECT\|f'.*SELECT" --include="*.py" suite-*/ | grep -v __pycache__ | wc -l
# Bare except:
grep -rn "except Exception" --include="*.py" suite-*/ | grep -v __pycache__ | wc -l
# CORS wildcard:
grep -rn "allow_origins.*\*\|allow_methods.*\*\|allow_headers.*\*" suite-api/ --include="*.py" | wc -l

echo "=== LEGAL ==="
# LICENSE file:
ls -la LICENSE 2>/dev/null || echo "MISSING: LICENSE file"
# SBOM:
ls -la sbom*.json 2>/dev/null || echo "MISSING: SBOM"

echo "=== DATABASE ==="
# Legacy sqlite3:
grep -rn "sqlite3.connect\|sqlite3.Connection" --include="*.py" suite-*/ | grep -v __pycache__ | wc -l
# Legacy PersistentDict:
grep -rn "PersistentDict" --include="*.py" suite-*/ | grep -v __pycache__ | wc -l
# New DatabaseManager:
grep -rn "DatabaseManager\|get_db_session\|AsyncSession" --include="*.py" suite-*/ | grep -v __pycache__ | wc -l

echo "=== OBSERVABILITY ==="
# Prometheus endpoint:
curl -s http://localhost:8000/metrics 2>/dev/null | head -1 || echo "MISSING: /metrics"
# Health deep:
curl -s http://localhost:8000/health/deep 2>/dev/null | head -1 || echo "MISSING: /health/deep"
```

## Score Targets

| Category | Current | Target (6 mo) | Target (12 mo) |
|----------|---------|---------------|-----------------|
| Code Quality | C+ | B+ | A- |
| Security | C | B | A |
| IP & Legal | D | B+ | A |
| Operations | C | B | A- |
| Data | D+ | B | A- |
| Documentation | B- | A- | A |
| Market | B+ | A- | A |
| **OVERALL** | **C+ (6.5/10)** | **B+ (8/10)** | **A- (9/10)** |
