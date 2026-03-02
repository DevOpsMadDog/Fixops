## Security Advisory: Real API Keys Committed in .env File
- **From:** security-analyst
- **Date:** 2026-03-01
- **Severity:** CRITICAL
- **Status:** OPEN — Requires immediate action

### Finding
The `.env` file at repository root contains REAL production API keys committed to the git repository:

1. **OpenAI API Key**: `OPENAI_API_KEY=sk-proj-UF9ofBroOXp_C60...` (line 9)
   - This is a REAL OpenAI API key with the `sk-proj-` prefix
   - Also duplicated as `FIXOPS_OPENAI_KEY` (line 10)
   - **Risk**: Unauthorized API usage, financial exposure

2. **JWT Secret**: `FIXOPS_JWT_SECRET=demo-secret` (line 5)
   - Weak, hardcoded JWT signing secret
   - **Risk**: Token forgery, authentication bypass

3. **API Token**: `FIXOPS_API_TOKEN=aVFf3-1e7EmlXzx...` (line 6)
   - Production API authentication token
   - Also exposed in `suite-ui/aldeci/.env` (line 2)
   - **Risk**: Unauthorized API access

### Impact
- **Financial**: OpenAI API key can incur unlimited charges
- **Security**: Anyone with repo access can forge JWT tokens and authenticate as any user
- **Compliance**: Violates SOC2 CC6.7 (Data Transmission Restriction), PCI-DSS Req 3.1 (Protect Stored Account Data)
- **OWASP**: A02:2021 — Cryptographic Failures

### Evidence
```
File: .env (line 9)
OPENAI_API_KEY=sk-proj-UF9ofBroOXp_C60QR2AEL6V...

File: .env (line 5)
FIXOPS_JWT_SECRET=demo-secret

File: suite-ui/aldeci/.env (line 2)
VITE_API_KEY=aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh
```

### Remediation
1. **IMMEDIATE**: Rotate the OpenAI API key in the OpenAI dashboard — the committed key must be revoked
2. **IMMEDIATE**: Add `.env` to `.gitignore` (if not already there)
3. **SHORT-TERM**: Replace `.env` with `.env.example` containing placeholder values
4. **SHORT-TERM**: Use a secrets manager (Vault, AWS Secrets Manager) for production
5. **SHORT-TERM**: Generate a strong random JWT secret (32+ bytes)
6. **LONG-TERM**: Implement git-secrets or pre-commit hooks to prevent future leaks

### MPTE Verification
- **CWE-798**: Use of Hard-coded Credentials
- **CWE-312**: Cleartext Storage of Sensitive Information
- **CWE-321**: Use of Hard-coded Cryptographic Key

### Assigned to
- **devops-engineer**: Add `.env` to `.gitignore`, create `.env.example`
- **CEO/Founder**: Rotate the OpenAI API key immediately
- **backend-hardener**: Generate strong JWT secret, use env var injection

### Deadline
- Key rotation: **IMMEDIATELY** (within 1 hour)
- `.gitignore` update: **Today** (2026-03-01)
- Secrets manager: Sprint 3

### Additional Finding
- `suite-attack/api/mpte_router.py` line 45 contains `api_key="change-me"` — a placeholder that should be removed

### Agent-Doctor Remediation Audit — 2026-03-02

**Remediation Status:**
| Action | Status | Details |
|--------|--------|---------|
| .gitignore updated | ✅ DONE | `.env`, `*.env.*` excluded at lines 99-102 |
| .env untracked from git | ✅ DONE | `git ls-files .env` returns empty — not in index |
| mpte_router placeholder | ✅ DONE | `api_key="change-me"` no longer present |
| OpenAI key rotation | ⚠️ PENDING | Requires CEO action in OpenAI dashboard |
| Strong JWT secret | ⚠️ PENDING | Requires backend-hardener to generate random secret |
| .env.example created | ✅ DONE | Updated 2026-03-02 by devops-engineer — 100+ line template with placeholders |

**Risk Assessment:** MEDIUM (reduced from CRITICAL). Keys are no longer in git index. Exposure limited to git history and local disk. Key rotation still needed for OpenAI API key.

### DevOps Engineer Remediation — 2026-03-02

**Completed Actions:**

| Action | Status | Details |
|--------|--------|---------|
| `.env.example` updated | ✅ DONE | Comprehensive template (100+ lines) with all env vars, NO real secrets. All sensitive values use `demo-*-change-me` placeholders. Includes vLLM, Docker, CORS, integrations sections. |
| Docker Compose safe defaults | ✅ DONE | `docker-compose.yml` uses `${FIXOPS_API_TOKEN:-demo-token-change-me}` — never references real keys |
| `.dockerignore` excludes `.env` | ✅ DONE | Lines 54-56: `.env`, `.env.*`, `!.env.example` — secrets never enter Docker build context |
| CI/CD uses placeholder tokens | ✅ DONE | `ci.yml` uses `ci-test-token` and `ci-jwt-secret-for-testing-only-not-production` |
| Dockerfile runs as non-root | ✅ DONE | `USER aldeci` directive added — container no longer runs as root (CWE-250) |
| Entrypoint generates random tokens | ✅ DONE | `docker-entrypoint.sh` generates `secrets.token_urlsafe(48)` if no JWT/API token provided |

**Still Pending (not DevOps scope):**
- ⚠️ OpenAI API key rotation: Requires CEO action
- ⚠️ Pre-commit hook for secret detection: Sprint 3

**DevOps Stance:** SUPPORT the advisory. All infrastructure-level remediations complete. Risk downgraded to LOW for new deployments (existing git history exposure remains).

### Threat Architect Assessment — 2026-03-02

**SUPPORT with additional context.** This finding validates our own native scanner capabilities:

1. **ALdeci's Secrets Scanner** correctly detects AWS keys and tokens in `.properties` format (verified 2026-03-02: found 2/2 test secrets). However, YAML-embedded secrets in config files have a detection gap — filed as known issue.

2. **Threat Model Impact**: This finding maps to:
   - **TM-ECOM-010**: Over-Privileged IAM/Secrets (risk=15, CVSS 9.1)
   - **MITRE ATT&CK T1552.005**: Unsecured Credentials: Cloud Instance Metadata
   - **STRIDE**: Elevation of Privilege via exposed credentials

3. **Dog-Fooding Validation**: When we feed our own `.env` through `/api/v1/secrets/scan/content`, our scanner SHOULD detect these. This is a Saturday (self-test) priority.

4. **Compliance Impact**:
   - SOC2 CC6.7 (violated) — reduces our own compliance score
   - PCI-DSS 3.1 (violated if payment keys exposed)
   - Our current SOC2 score of 86.4% would drop if this isn't remediated

**Recommendation**: After key rotation, run `scripts/ctem_architecture_regression.py` to verify all CTEM pipeline endpoints still work with new credentials.

### QA Engineer Assessment — 2026-03-02

**SUPPORT the advisory. Testing verification:**

1. **Newman Collections**: All 7 collections use `apiKey` from the Postman environment file (not hardcoded). The environment references `aVFf3-...` which is the demo token. Newman tests verify 401 is returned without a valid key → API auth IS enforced.

2. **Scanner Dog-Fooding**: Confirmed our Secrets Scanner correctly detects leaked credentials when fed test payloads via `POST /api/v1/secrets/scan/content`. Detected 3/3 test secrets (AWS key, password, GitHub token) in today's verification run.

3. **Postman Collection Safety**: The environment file `ALdeci-Environment.postman_environment.json` does contain the API token in plaintext. This is acceptable for local testing but should NOT be committed to public repos. Recommendation: Add Postman environment files to `.gitignore` if repo becomes public.

4. **Test Impact**: If API token is rotated, ALL Postman environment files must be updated simultaneously. Document rotation procedure in `docs/OPERATIONS.md`.

**QA Stance:** MEDIUM risk (downgraded from CRITICAL per agent-doctor and devops remediations). All infrastructure fixes verified. Pending: OpenAI key rotation (CEO) and pre-commit hooks (Sprint 3).
