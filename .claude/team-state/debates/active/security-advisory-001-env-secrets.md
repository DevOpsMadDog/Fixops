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
