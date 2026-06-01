# SPEC-005 — Air-Gap Enforced Mode

**Status:** CLOSED — all Red-Team / SCIF-Accreditor findings resolved 2026-06-01  
**Audience:** Security Engineering, DevOps, SCIF Deployment Operators  
**Threat model:** US defense / financial-institution air-gapped (SCIF) deployments where
zero outbound network egress is permissible.

---

## §1 Overview

SPEC-005 defines the contract for `FIXOPS_AIRGAP_MODE=enforced` mode. When this
env-var is set, the platform must:

1. Block ALL outbound HTTP/S channels (webhooks, Slack, feeds, OTEL exporters).
2. Disable all telemetry (Sentry, StatsD, HuggingFace hub, OTLP).
3. Route LLM inference to local backends only (Ollama / vLLM / llama.cpp).
4. Report an honest network isolation status — not one that lies about egress.

Default (non-enforced) behaviour must be completely unchanged.

---

## §2 Single Authoritative Guard

**Module:** `suite-core/core/airgap_config.py`  
**Function:** `is_airgap_enforced() -> bool`

All callers (webhooks, Slack, feeds, OTEL) must use this single function.
No inline `os.environ.get("FIXOPS_AIRGAP_MODE")` checks elsewhere.

Resolution order:
1. `FIXOPS_AIRGAP_MODE=enforced` env-var (production / systemd / k8s path)
2. `AirGapConfigEngine` persisted state == `"enforced"`
3. `fips_encryption.AirGapMode.is_enabled()` (in-process flag)

Returns `False` in all other cases — no side effects, never raises.

---

## §3 Guarded Channels

| Channel | File | Guard | Behaviour under enforced |
|---------|------|-------|--------------------------|
| Outbound webhooks | `suite-api/apps/api/outbound_webhooks_router.py` | `_is_airgap_enforced()` at top of `dispatch_outbound` | Returns `[]`, logs WARNING, no POST |
| Slack notifier | `suite-core/core/slack_notifier.py` | `_is_airgap_enforced()` at top of `_default_transport` | Returns `False`, logs WARNING, no `httpx.post` |
| Feed importers (26) | `suite-feeds/feeds/*/importer.py` + `mitre_attack/extractor.py` | `assert_feeds_egress_allowed(feed_name)` at network entry-point | Raises `RuntimeError("offline …")` |
| OTEL / OTLP | `suite-api/apps/api/app.py` `create_app()` | Skip `FastAPIInstrumentor.instrument_app` when enforced + `OTEL_EXPORTER_OTLP_ENDPOINT` set | Logs WARNING, no instrumentation |

---

## §4 Feed Egress Guard

**Module:** `suite-feeds/feeds/__init__.py`  
**Functions:** `feeds_egress_allowed() -> bool`, `assert_feeds_egress_allowed(feed_name: str)`

Two conditions block egress (either is sufficient):
- `FIXOPS_AIRGAP_MODE=enforced`
- `FIXOPS_FEEDS_OFFLINE=1` (explicit offline override, useful for partial deployments)

All 26 feed importers call `assert_feeds_egress_allowed` at their network
entry-point (the first function whose body opens an httpx client or urlopen).

---

## §5 Honest Egress Status

**Class:** `NetworkIsolationVerifier` in `suite-core/core/airgap_deployment.py`

**Previous state (DISQUALIFYING):** probed only `api.openai.com` + `pypi.org`,
reported `egress_blocked=True` regardless of enforced mode.

**Fixed state:**

- New field `egress_sample_probe: bool` — raw result of the probe run (sample only,
  documented as not comprehensive).
- Existing field `egress_blocked: bool` — now only `True` when BOTH:
  (a) the broader sample probe found no reachable external URLs, AND
  (b) `FIXOPS_AIRGAP_MODE=enforced` is active.
- Probe URL set expanded from 2 to 6:
  - `https://api.openai.com` (LLM API)
  - `https://pypi.org` (package registry)
  - `https://api.first.org` (FIRST EPSS/CVSS feeds)
  - `https://www.cisa.gov` (CISA KEV feed)
  - `https://huggingface.co` (model hub)
  - `https://github.com` (GHSA / nuclei / OSV)

---

## §6 OTEL Guard

`FastAPIInstrumentor.instrument_app(app)` is skipped when:
- `FIXOPS_AIRGAP_MODE=enforced`, AND
- `OTEL_EXPORTER_OTLP_ENDPOINT` is non-empty

When no OTLP endpoint is configured, `FastAPIInstrumentor` is safe (no exfil
risk) and is applied normally even in enforced mode.

---

## §7 Debate Log — Red-Team / SCIF Accreditor Findings

Conducted 2026-06-01. Findings and closure status:

| # | Finding | Severity | Closed |
|---|---------|----------|--------|
| 1 | Three divergent AirGapMode systems (fips_encryption.py bool, airgap_config.py enum, env-var) with no single authoritative guard — callers re-implemented the check inline | CRITICAL | YES — `is_airgap_enforced()` added to `airgap_config.py` as single source of truth |
| 2 | `outbound_webhooks_router.dispatch_outbound` ignored enforced mode and fired real HTTP POSTs — exfil channel wide open in SCIF | CRITICAL | YES — guard at top of `dispatch_outbound`, returns `[]` with WARNING log |
| 3 | `slack_notifier._default_transport` ignored enforced mode and called `httpx.post` — exfil channel | CRITICAL | YES — guard returns `False` before any httpx call |
| 4 | 26 feed importers made unconditional outbound HTTP calls with no airgap awareness — any importer invocation leaked data out of SCIF | HIGH | YES — `feeds_egress_allowed()` + `assert_feeds_egress_allowed()` added to `feeds/__init__.py`; all 26 importers patched at network entry-point |
| 5 | `NetworkIsolationVerifier` probed only 2 URLs (openai + pypi) yet set `egress_blocked=True` even when not in enforced mode — lying status disqualified the accreditation | DISQUALIFYING | YES — probe expanded to 6 URLs; `egress_blocked` only `True` when enforced+probe-clean; new honest field `egress_sample_probe` added |
| 6 | OTEL `FastAPIInstrumentor` + potential OTLP exporter active under enforced mode when `OTEL_EXPORTER_OTLP_ENDPOINT` set — telemetry exfil path | HIGH | YES — `instrument_app` skipped with log warning when enforced + OTLP endpoint set |

All 6 findings closed. Zero findings deferred.

---

## §8 Test Coverage

**File:** `tests/test_airgap_enforced.py`

New test classes added 2026-06-01 (38 tests total, all passing):

| Class | Tests | Covers |
|-------|-------|--------|
| `TestIsAirgapEnforcedHelper` | 3 | Hole 1 — single guard |
| `TestWebhookDispatchBlocked` | 2 | Hole 2 — webhook exfil |
| `TestSlackTransportBlocked` | 2 | Hole 3 — Slack exfil |
| `TestFeedImporterBlocked` | 4 | Hole 4 — feed egress |
| `TestEgressProbeHonest` | 4 | Hole 5 — lying status |
| `TestOtelSkippedWhenEnforced` | 3 | Hole 6 — OTEL exfil |

All pre-existing tests (boot path, Sentry, StatsD, LLM council, feeds service,
status endpoint, create_app) continue to pass — zero regressions.

Run:
```bash
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy" \
pytest tests/test_airgap_enforced.py -v --timeout=30
```

Expected: **38 passed**.

---

## §9 Operator Checklist — SCIF Deployment

Before deploying to an air-gapped environment:

- [ ] Set `FIXOPS_AIRGAP_MODE=enforced` in systemd unit / k8s Secret
- [ ] Leave `OTEL_EXPORTER_OTLP_ENDPOINT` unset (or set it knowing OTEL will be skipped)
- [ ] Set `FIXOPS_FEEDS_OFFLINE=1` if feeds service is running but network is absent
- [ ] Import NVD bundle via `OfflineVulnDBManager.import_from_bundle()` before first scan
- [ ] Import STIX bundle via `ThreatIntelManager.import_stix_bundle()` for threat intel
- [ ] Configure a local LLM backend (Ollama / vLLM) — council will refuse to start without one
- [ ] Run `GET /api/v1/airgap/status` and confirm `egress_blocked=true`
- [ ] Run `pytest tests/test_airgap_enforced.py` — all 38 must pass
