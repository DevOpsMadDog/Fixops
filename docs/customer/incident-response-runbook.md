# ALDECI Incident Response Runbook

This runbook is for on-call engineers and ALDECI administrators responding to a production incident at 3am. Steps are ordered: check first, act second.

All `flyctl` commands assume the app name `aldeci`. Adjust if your deployment uses a different name.

---

## Step 0 — Assess Severity Before Acting

| Signal | Severity | Initial action |
|--------|----------|---------------|
| `GET /api/v1/health` returns non-200 | P1 | Jump to §1 immediately |
| API returning 5xx on >10% of requests | P1 | Jump to §1 |
| Single endpoint returning errors | P2 | Check logs, consider rollback |
| Slow responses (>5s p95) but functional | P3 | Check logs, monitor, do not roll back |
| Scheduled scan missed | P3 | Check connector health, reschedule |

---

## 1. Check Fly.io Health

```bash
# App and machine status
flyctl status --app aldeci

# Recent log stream (last 200 lines)
flyctl logs --app aldeci --no-tail | tail -200

# Live log tail
flyctl logs --app aldeci
```

Look for:
- `"Application startup complete"` — server is up
- `ImportError` / `ModuleNotFoundError` — broken deploy, roll back immediately
- `sqlite3.OperationalError` — database issue, check volume mount
- `OSError: [Errno 28] No space left on device` — volume full, expand or prune

```bash
# Check volume usage
flyctl ssh console --app aldeci -C "df -h /app/data"
```

---

## 2. Roll Back a Deploy

ALDECI uses Fly.io's rolling deploy strategy. Rolling back restores the previous machine image.

```bash
# List recent releases
flyctl releases --app aldeci

# Roll back to a specific version (e.g. v42)
flyctl deploy --app aldeci --image registry.fly.io/aldeci:deployment-01JXXXXXXX
```

If the image tag is unknown:

```bash
# List available images
flyctl releases --app aldeci --json | python3 -c "
import sys, json
releases = json.load(sys.stdin)
for r in releases[:5]:
    print(r.get('version'), r.get('image_ref'), r.get('created_at'))
"
```

After rollback, verify recovery:

```bash
curl https://aldeci.fly.dev/api/v1/health
# Expect: {"status":"ok"}
```

---

## 3. Rotate API Keys

### 3a. Rotate the primary `FIXOPS_API_TOKEN`

This is the verified procedure for key rotation on Fly.io. The new key is active within seconds; the old key is immediately rejected.

```bash
# 1. Generate a new secure key
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
echo "New key (save this): $NEW_KEY"

# 2. Set on Fly.io — takes effect on next request, no redeploy needed
flyctl secrets set FIXOPS_API_TOKEN="$NEW_KEY" --app aldeci

# 3. Verify the new key works
curl -H "X-API-Key: $NEW_KEY" https://aldeci.fly.dev/api/v1/status
```

Distribute the new key to all service accounts and integrations before revoking the old one. Fly.io secret updates do not require a redeploy — they are picked up on the next application startup or signal. If you need an immediate restart:

```bash
flyctl machine restart --app aldeci
```

### 3b. Rotate the JWT signing secret

```bash
NEW_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
flyctl secrets set FIXOPS_JWT_SECRET="$NEW_JWT_SECRET" --app aldeci
flyctl machine restart --app aldeci
```

All existing JWT sessions are immediately invalidated. Users must re-authenticate.

### 3c. Rotate per-service-account API keys

Individual API keys (not the master token) are managed via the API:

```bash
# List all API keys for your org
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/apikeys?org_id=acme"

# Revoke a specific key
curl -X DELETE -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/apikeys/KEY-ID-HERE"

# Create a replacement
curl -X POST -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  "https://aldeci.fly.dev/api/v1/apikeys" \
  -d '{"org_id":"acme","name":"ci-pipeline","role":"security_engineer"}'
```

---

## 4. Mass-Revoke API Keys

In the event of a key compromise affecting multiple service accounts:

```bash
# Revoke all non-admin keys for an org
curl -X POST -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  "https://aldeci.fly.dev/api/v1/apikeys/revoke-all" \
  -d '{"org_id":"acme","except_roles":["super_admin"]}'
```

Then issue new keys individually to each service account using `POST /api/v1/apikeys`.

The master `FIXOPS_API_TOKEN` (environment variable) is separate from per-service-account keys and is not affected by the above. Rotate it independently via `flyctl secrets set` (§3a above).

---

## 5. Export Audit Logs for Incident Disclosure

Export the full audit log for the incident window. Scope to the relevant time range:

```bash
# Export last 24 hours
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/audit?org_id=acme&from_ts=$(date -u -v-24H '+%Y-%m-%dT%H:%M:%SZ')&limit=1000" \
  | python3 -m json.tool > incident-audit-$(date +%Y%m%d-%H%M%S).json

# Export for a specific actor (e.g. a compromised service account)
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/audit?org_id=acme&actor=svc-ci-pipeline&from_ts=2026-05-30T00:00:00Z" \
  | python3 -m json.tool > actor-audit.json
```

For compliance reporting, generate a signed evidence bundle covering the incident period:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme",
    "type": "incident",
    "period_start": "2026-05-30T00:00:00Z",
    "period_end": "2026-05-31T00:00:00Z",
    "include_audit_trail": true
  }'
```

---

## 6. Database Recovery

ALDECI stores data in SQLite files on the persistent Fly.io volume at `/app/data`. If a database becomes corrupted:

```bash
# SSH into the running machine
flyctl ssh console --app aldeci

# Check database integrity
sqlite3 /app/data/findings.db "PRAGMA integrity_check;"
sqlite3 /app/data/audit.db "PRAGMA integrity_check;"

# If corrupted, restore from the latest Fly.io volume snapshot
# (Fly.io takes daily snapshots automatically)
exit
```

To restore from a volume snapshot, contact Fly.io support (`support@fly.io`) with your `volume_id` (from `flyctl volumes list --app aldeci`). ALDECI does not yet include a self-service snapshot restore endpoint.

For air-gapped deployments, maintain your own volume backup schedule (`rsync` or `sqlite3 .backup` to a separate storage location).

---

## 7. Disk Space Exhaustion

If `/app/data` is full:

```bash
# Check volume size
flyctl volumes list --app aldeci

# Extend the volume (non-destructive, may require machine restart)
flyctl volumes extend VOLUME-ID --size 20 --app aldeci

# Or prune old data within the running container
flyctl ssh console --app aldeci -C "
  sqlite3 /app/data/audit.db \"DELETE FROM audit_log WHERE created_at < datetime('now', '-90 days');\"
  sqlite3 /app/data/findings.db \"VACUUM;\"
"
```

---

## 8. Application Won't Start After Deploy

Symptom: Machine stays in `starting` state for >5 minutes.

```bash
flyctl logs --app aldeci | grep -E "ERROR|Exception|Traceback" | head -30
```

**Common causes:**

| Log message | Cause | Fix |
|-------------|-------|-----|
| `ModuleNotFoundError: No module named 'X'` | Missing dependency in Docker image | Rebuild image with `flyctl deploy --remote-only` after adding to `requirements.txt` |
| `sqlite3.OperationalError: unable to open database` | Volume not mounted | Check `flyctl volumes list` and `fly.toml` `[[mounts]]` section |
| `OSError: [Errno 98] Address already in use` | Previous process did not exit cleanly | `flyctl machine restart --app aldeci` |
| `pydantic.ValidationError` | Config schema mismatch after env var change | Check new env var values are valid types |

---

## 9. Contacting Support

| Channel | When to use | Response target |
|---------|-------------|-----------------|
| `support@devopsai.co` | All incidents | 4 hours (business hours), 24 hours (off-hours) |
| P1 emergency | Production down, data breach suspected | Call your account representative directly |

When contacting support, include:

1. `GET /api/v1/status` output (version and mode)
2. `X-Request-ID` from a failing request (in the response header)
3. `flyctl releases --app aldeci` output (last 5 releases)
4. Audit log export covering the incident window (§5 above)
5. Fly.io region and machine size (`flyctl status --app aldeci`)

---

## Quick Reference

```bash
# Is the app up?
curl https://aldeci.fly.dev/api/v1/health

# Live logs
flyctl logs --app aldeci

# Machine status
flyctl status --app aldeci

# Rotate primary key (no redeploy needed)
flyctl secrets set FIXOPS_API_TOKEN="<new-key>" --app aldeci

# Roll back to previous release
flyctl deploy --app aldeci --image registry.fly.io/aldeci:<previous-image-ref>

# SSH into the container
flyctl ssh console --app aldeci

# Check disk usage
flyctl ssh console --app aldeci -C "df -h /app/data"

# Export audit log (last 24h)
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/audit?org_id=acme&from_ts=$(date -u -v-24H '+%Y-%m-%dT%H:%M:%SZ')" \
  > audit.json
```
