# ALdeci Troubleshooting Guide

## Startup Issues

### "ModuleNotFoundError: No module named 'core'"
**Cause:** Python path not configured for suite imports.
**Fix:** ALdeci uses `sitecustomize.py` to set paths. Ensure you run from the repo root:
```bash
cd /path/to/Fixops
PYTHONPATH=. uvicorn suite-core.api.app:app --port 8001
```
Or run from inside the suite directory (paths are auto-configured):
```bash
cd suite-core && uvicorn api.app:app --port 8001
```

### "Address already in use" (port conflict)
**Cause:** Another process is using the port.
**Fix:**
```bash
lsof -i :8000  # find the PID
kill -9 <PID>
```

### CORS errors in browser console
**Cause:** Frontend origin not in allowed list.
**Fix:** Set the environment variable:
```bash
export FIXOPS_ALLOWED_ORIGINS="http://localhost:5173,http://localhost:3000"
```

## Authentication

### "401 Unauthorized" in enforced mode
**Cause:** `FIXOPS_AUTH_MODE=enforced` but no valid JWT or API key provided.
**Fix (dev):** Set `FIXOPS_AUTH_MODE=dev` to bypass auth.
**Fix (prod):** Include a Bearer token:
```bash
curl -H "Authorization: Bearer <jwt-token>" http://localhost:8000/api/v1/...
```
Or use an API key:
```bash
curl -H "X-API-Key: fixops_abc123.your_key_here" http://localhost:8000/api/v1/...
```

### "JWT signature verification failed"
**Cause:** `FIXOPS_JWT_SECRET` mismatch between token issuer and API server.
**Fix:** Ensure the same secret is set across all suites.

## Feeds & Data

### NVD search returns empty results
**Cause:** NVD API rate limit (5 requests/30s without key).
**Fix:** Set `NVD_API_KEY` for higher limits:
```bash
export NVD_API_KEY="your-key-from-nvd.nist.gov"
```

### EPSS scores returning 0 for all CVEs
**Cause:** EPSS API may be temporarily unavailable.
**Fix:** Check `curl https://api.first.org/data/v1/epss?cve=CVE-2021-44228`. If it fails, EPSS is down upstream.

## Brain Pipeline

### Pipeline run fails at step 3 (feed ingestion)
**Cause:** suite-feeds not running or unreachable.
**Fix:** Ensure suite-feeds is running on port 8003:
```bash
curl http://localhost:8003/health
```

### Pipeline takes > 30 seconds
**Cause:** Processing many CVEs without caching.
**Fix:** Enable Redis caching:
```bash
export FIXOPS_CACHE_URL="redis://localhost:6379/0"
```
Or reduce CVE count:
```json
{"org_id": "demo", "options": {"max_cves": 10}}
```

## Integrations

### "Connector not configured" on sync
**Cause:** Required config fields missing.
**Fix:** Check integration config:
```bash
curl http://localhost:8005/api/v1/integrations/{id}
```
Ensure required fields are present (token, base_url, etc.). See [integrations.md](integrations.md).

### Snyk sync fails with 401
**Cause:** Invalid or expired Snyk token.
**Fix:** Regenerate token at https://app.snyk.io/account and update:
```bash
export SNYK_TOKEN="your-new-token"
```

### AWS Security Hub: "boto3 not available"
**Cause:** boto3 not installed.
**Fix:**
```bash
pip install boto3
```

## UI Issues

### Blank page after `npm run dev`
**Cause:** Build error or missing dependencies.
**Fix:**
```bash
cd suite-ui/aldeci
rm -rf node_modules
npm install
npm run dev
```

### API calls failing from UI (Network Error)
**Cause:** Backend not running or wrong API URL.
**Fix:** Check the Vite proxy config in `vite.config.ts` points to correct backend port.

## Performance

### Slow graph queries
**Cause:** Large knowledge graph without indexes.
**Fix:** Indexes are auto-created on startup (Phase 14.4). Restart suite-core to apply.

### High memory usage in suite-core
**Cause:** In-memory cache growing large.
**Fix:** Set max cache size:
```bash
export FIXOPS_CACHE_MAX_SIZE=5000  # default: 10000 entries
```

## Getting Help

1. Check the [Quick Start Guide](quickstart.md)
2. Check the [Integrations Guide](integrations.md)
3. Review API docs at `http://localhost:8000/docs` (Swagger UI)
4. Open an issue: https://github.com/DevOpsMadDog/Fixops/issues

