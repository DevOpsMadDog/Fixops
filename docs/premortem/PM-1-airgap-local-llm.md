# PM-1: Air-Gap / Local-LLM Pre-Mortem

**Scenario**: It is 2031. ALDECI was ripped out of a SCIF or lost a $100K renewal because it violated the air gap or because its "local intelligence" was not actually local.

**Method**: Read-only code audit. Every claim is grounded in a specific file and line number. No speculation.

**Date of audit**: 2026-06-01  
**Branch audited**: chore/ui-prune-plan-2026-05-24 (HEAD at time of audit)

---

## 1. What Phones Home — Categorized

### 1A. Cloud LLM API calls (CRITICAL — would break in a SCIF)

All four providers are wired and will fire whenever the matching environment variables are set. In a standard (non-airgap) deployment these are the primary intelligence path.

| Provider | File | Line(s) | Default-on? |
|---|---|---|---|
| Anthropic `api.anthropic.com` | `suite-core/core/llm_providers.py` | 410, 416 | Yes, if `ANTHROPIC_API_KEY` set |
| OpenAI `api.openai.com` | `suite-core/core/llm_providers.py` | 197 | Yes, if `OPENAI_API_KEY` set |
| OpenRouter `openrouter.ai` | `suite-core/core/llm_providers.py` | 702, 856 | Yes, if `OPENROUTER_API_KEY` set |
| MuleRouter `mulerouter.ai` | `suite-core/core/llm_providers.py` | 1911 | Yes, if `MULEROUTER_API_KEY` set |
| Anthropic escalation (council adapter) | `suite-core/core/council_pipeline_adapter.py` | 194–237 | Yes, if `ANTHROPIC_API_KEY` set |

The `CouncilFactory` in `llm_council.py:1378` instantiates `AnthropicMessagesProvider` unconditionally at construction time — the object exists and holds the key. It will fire on the first `convene()` call unless air-gap enforcement has swapped it out (see section 3).

### 1B. Threat feeds (internet-required by default — would stall in a SCIF)

Every feed importer calls out at sync time, not at import time. They do not fire silently at boot. However, the SCIF operator runs a scheduled sync; if that sync runs inside the perimeter it will hang or raise.

| Feed | File | Line | Destination |
|---|---|---|---|
| abuse.ch Feodo Tracker | `suite-core/core/ioc_enrichment_engine.py` | 76 | `https://feodotracker.abuse.ch` |
| EPSS | `suite-feeds/feeds_service.py` | 1179 | `https://api.first.org` (EPSS URL) |
| CISA KEV | `suite-feeds/feeds_service.py` | 1281 | `https://www.cisa.gov` |
| NVD CVE | `suite-feeds/feeds_service.py` | 1409 | `https://services.nvd.nist.gov` |
| MITRE ATT&CK | `suite-feeds/feeds/mitre_attack/extractor.py` | 156 | `https://raw.githubusercontent.com/mitre/cti` |
| OTX, GHSA, OSV, SigmaHQ, URLhaus, PhishTank, Tor exits, Censys, SecurityTrails, DBIR, Nuclei | `suite-feeds/feeds/*/importer.py` | various | respective external APIs |

**Key nuance**: `ioc_enrichment_engine.py` raises `IocEnrichmentError` (not a silent hang) when the feed is unreachable — line 85. The router catches it and returns HTTP 422. This is better than a silent lie, but a SCIF operator will see 422 on every IOC enrichment call until the feed path is fixed.

**There is no general `FIXOPS_FEEDS_OFFLINE` skip flag**. The only offline provision is the STIX/sneakernet import path in `suite-core/core/airgap_config.py:874` (`ThreatIntelManager.import_stix_bundle`) and the NVD SQLite mirror in `suite-core/core/airgap_deployment.py` (`CVEDatabaseManager`). Feed importers themselves have no unified air-gap bypass.

### 1C. Sentry error reporting (phones home on exceptions — SCIF-violating)

`suite-core/core/observability.py:886` reads `SENTRY_DSN` from the environment and calls `sentry_sdk.init()`. The app startup in `suite-api/apps/api/app.py:2191` calls `init_sentry()` unconditionally in the production boot path.

- **If `SENTRY_DSN` is not set**: `init_sentry()` no-ops (`resolved_dsn` is `None`, init is skipped). Safe.
- **If `SENTRY_DSN` is set in the SCIF config** (e.g., copied from a prior deployment): every unhandled exception phones home to `sentry.io`. This is a covert egress channel that would not show up in a port-scan audit because it uses port 443 to a CDN-fronted endpoint.

`TelemetryKillSwitch.disable_all()` in `airgap_deployment.py:1328` does call `sentry_sdk.init()` with no DSN to neutralize it — but only if the operator explicitly calls `disable_all()` before deployment. Nothing in the normal boot path calls this automatically.

### 1D. HuggingFace model downloads (would hang at boot in a SCIF with no internet)

`suite-core/core/services/enterprise/vector_store.py:248–251` calls `SentenceTransformer("all-MiniLM-L6-v2")` inside `__init__`. When `sentence_transformers` is installed and this class is instantiated, the library checks its local cache and, if the model is absent, downloads it from `huggingface.co`. In a SCIF with no internet this hangs until timeout or raises an `OSError`.

The main `suite-core/core/vector_store.py` is better: it gates on `FIXOPS_VECTOR_STORE` env var (line 45–46) and does not download unless opted in. The enterprise variant does not have this guard.

`airgap_deployment.py:1333–1336` calls `huggingface_hub.disable_progress_bars()` if the module is already loaded — this does not prevent the download; it only suppresses the progress bar output.

The fix is `HF_DATASETS_OFFLINE=1` + `TRANSFORMERS_OFFLINE=1` env vars (HuggingFace standard), or pre-staging the model tarball. Neither is currently enforced in code.

### 1E. License check / pip / package fetch (non-intelligence but still egress)

`airgap_deployment.py:1181` probes `https://api.openai.com` and `https://pypi.org` as part of `NetworkIsolationChecker.verify()`. This is a diagnostic-only path (called by the preflight validator), not a runtime path. It intentionally tests that those hosts are unreachable — the function is correctly designed. Not a violation.

No license-check-home or call-home on startup was found in the scanned paths.

---

## 2. The Council: Local LLM Path — Reality vs. Documentation

### What exists

The air-gap enforcement machinery in `llm_council.py:1396–1490` (`CouncilFactory._enforce_air_gap_providers`) is real code that:
1. Reads `FIXOPS_AIRGAP_MODE` via `get_air_gap_mode()` (`airgap_config.py:1784`).
2. If mode is `CONFIGURED` or `ENFORCED`, probes `localhost:11434` (Ollama), `localhost:8000` (vLLM), `localhost:8080` (llama.cpp) via `LocalLLMRouter.detect_available_backend()` (`airgap_config.py:776`).
3. If a backend responds, swaps every external provider (openai, anthropic, gemini, openrouter, mulerouter, deepseek) for `AirGapLLMProvider` instances that route through the local backend.
4. If `ENFORCED` and no backend found: raises `RuntimeError` — refuses to start. Correct behavior.
5. If `CONFIGURED` and no backend: logs CRITICAL, clears all external providers, sets `self.opus = None`. Council will use deterministic fallback only.

**The default mode is `AirGapMode.DISABLED`** (`airgap_config.py:1819`). In a fresh deployment with no `FIXOPS_AIRGAP_MODE` env var, the air-gap enforcement block at line 1417 returns immediately (`if mode not in (AirGapMode.CONFIGURED, AirGapMode.ENFORCED): return`). All cloud providers remain active.

### What is NOT built

The distilled local model (`llm_distill_router.py`) requires:
- `FIXOPS_DISTILL_ADAPTER` env var pointing to a trained LoRA adapter on disk (line 266)
- The adapter to physically exist at that path (line 160: `if not Path(self.adapter_path).exists()`)
- `transformers` and `peft` installed

There is no trained adapter shipped with the repository. The DPO training loop (`llm_learning_loop.py`) has captured 5,196 pairs (per `CLAUDE.md`) but has not reached the 10K threshold that triggers Phase 2 distillation. **No model checkpoint exists today**. `LLMDistillRouter` with no `FIXOPS_DISTILL_ADAPTER` set simply does not load a student model — `self._student` is `None`.

The `AirGapLLMProvider` routes through `LocalLLMRouter`, which routes through Ollama/vLLM/llama.cpp. **These are not bundled with ALDECI**. A SCIF operator must separately install one of these backends and pull a model (e.g., `ollama pull llama3`) before the air-gap council has any real intelligence.

### Deterministic fallback quality

When no providers are available, `llm_council.py:1011–1116` (`_derive_member_defaults`) produces verdicts driven by CVSS score + expertise role. The logic is:
- Maps `(severity_tier, expertise)` to a fixed `(action, confidence, reasoning)` tuple
- Produces divergent verdicts across council members (vulnerability analyst vs. compliance expert disagree on "high" findings)
- Grounds reasoning in CVSS thresholds and named framework references (PCI-DSS, MITRE T1190)

This is substantially better than returning `{"action": "unknown"}`. It is not a stub. However, it does not incorporate finding context (description, affected component, exploit PoC availability) beyond CVSS score and risk_level fields. A human analyst reviewing a deterministic verdict can trust its severity tier but cannot trust its contextual reasoning — the council is pattern-matching on metadata, not reading the finding.

**Verdict on the council without a local LLM**: produces defensible triage decisions for well-scored findings (CVSS >= 7.0 with correct severity field). Produces weak results for findings with no CVSS score or ambiguous severity. The "multi-LLM consensus moat" in competitive positioning collapses to a rules table in air-gap mode without Ollama/vLLM pre-staged.

---

## 3. Air-Gap Mode: The Critical Configuration Gap

The air-gap enforcement is opt-in via `FIXOPS_AIRGAP_MODE`. Default is `DISABLED`.

**Failure mode in a SCIF**: An operator deploys ALDECI, does not set `FIXOPS_AIRGAP_MODE=enforced`, has `ANTHROPIC_API_KEY` and `OPENROUTER_API_KEY` in the env (because they were copy-pasted from the pre-SCIF config). Every council `convene()` call attempts outbound HTTPS to `api.anthropic.com`. In a true air-gap this either hangs (TCP timeout ~30s) or raises a connection error. The council catches the exception (`council_pipeline_adapter.py:330`) and returns `method="deterministic"`. The operator sees results but the system has attempted 443 egress on every finding — a SCIF security violation even if the packets were dropped by the firewall.

The `BLOCKED_EXTERNAL_HOSTS` list in `airgap_deployment.py:97–107` is a documentation artifact used by `NetworkIsolationChecker.verify()` to test that hosts are unreachable. It does not configure any firewall rule or block outbound connections from within the process.

---

## 4. Telemetry and Side-Channel Egress

| Signal | Condition | SCIF risk |
|---|---|---|
| Sentry exceptions | `SENTRY_DSN` env var set | CRITICAL — call-home per exception via port 443 |
| HuggingFace model download | `enterprise/vector_store.py` instantiated without pre-cached model | HIGH — hangs at boot, then fails |
| Threat feed sync | Any scheduled feed refresh inside perimeter | MEDIUM — 422 errors, no silent data leak |
| Council LLM calls | `FIXOPS_AIRGAP_MODE` not set + API keys present | CRITICAL — attempted 443 egress per finding |

No Datadog, LaunchDarkly, Mixpanel, PostHog, or Amplitude integrations were found in the scanned paths. `secrets_manager.py:684` recognizes Datadog API key patterns for secrets scanning purposes only — it does not initialize a Datadog client.

---

## 5. Threat Feed Air-Gap Path: Partially Built

`airgap_config.py:874` has `ThreatIntelManager` for STIX 2.1 sneakernet import/export. `airgap_deployment.py:321` has `CVEDatabaseManager` for offline NVD SQLite import. These cover MITRE ATT&CK (via STIX) and CVE data.

What is NOT covered by an offline path:
- EPSS scores (exploitability probability) — no local cache mechanism
- CISA KEV (known exploited vulnerabilities) — no local cache mechanism  
- abuse.ch Feodo Tracker / URLhaus / PhishTank — no local snapshot; `IocEnrichmentError` on every enrichment call
- OTX, Censys, SecurityTrails — API-key-dependent, no air-gap variant

A SCIF deployment today gets CVE data and ATT&CK via sneakernet. It loses real-time threat intel for IOC enrichment and EPSS-based prioritization. Findings will be triaged on CVSS alone, not on "is this being actively exploited right now."

---

## 6. Blast Radius Summary

| Issue | Would break in SCIF? | Blast radius | Detection lag |
|---|---|---|---|
| Cloud LLM calls with `FIXOPS_AIRGAP_MODE` unset | YES — policy violation even if firewall drops packets | Every finding triaged by council | Immediate on first scan |
| `SENTRY_DSN` set in env | YES — covert egress on exceptions | Every application exception | Not visible in logs; only in network audit |
| HuggingFace download on boot | YES — boot failure if model not pre-staged | Full application startup | First deployment attempt |
| Threat feed sync | YES — 422 errors on IOC enrichment | IOC enrichment, feed-dependent prioritization | First sync attempt |
| Distilled local model absent | Not a violation; silent degradation | Council quality degrades to rule table | Not detected — verdicts look valid |

---

## 7. De-Risk Actions and Spec Ownership

### BLOCKER-1: Enforce air-gap mode by default in SCIF build

**Action**: Add `FIXOPS_AIRGAP_MODE=enforced` to the SCIF deployment manifest. Add a boot-time assertion in `app.py` that checks `get_air_gap_mode()` and refuses to start if API keys are set but air-gap mode is not configured.  
**File to change**: `suite-api/apps/api/app.py` (startup), `suite-core/core/council_pipeline_adapter.py` (key-presence check)  
**Spec owner**: Platform/Security team. This is a deployment configuration issue, not a feature.

### BLOCKER-2: Pre-stage Ollama or vLLM with a named model in SCIF

**Action**: The SCIF deployment package must include an Ollama or vLLM container image + a model (minimum: `llama3:8b` or equivalent). `LocalLLMRouter.detect_available_backend()` already handles this correctly once the backend is running. Without it, `FIXOPS_AIRGAP_MODE=enforced` causes a `RuntimeError` at council init.  
**Spec owner**: DevOps/Infrastructure. Requires defining the minimum acceptable model for security verdicts.

### BLOCKER-3: Gate `TelemetryKillSwitch.disable_all()` into normal boot path

**Action**: Call `TelemetryKillSwitch().disable_all()` unconditionally in `app.py` startup when `FIXOPS_AIRGAP_MODE` is `configured` or `enforced`. Currently it is only called from `AirGapDeploymentManager.deploy()` which is an explicit operator action.  
**File**: `suite-api/apps/api/app.py:2191` area, alongside `init_sentry()`.  
**Spec owner**: Platform team.

### HIGH-1: Add `HF_DATASETS_OFFLINE=1` + `TRANSFORMERS_OFFLINE=1` to SCIF env

**Action**: These are standard HuggingFace environment variables that make `from_pretrained()` look only in local cache and raise `OSError` immediately if absent, instead of attempting a download. Set them in the SCIF deployment manifest. Pre-stage the `all-MiniLM-L6-v2` model tarball in the container image.  
**Spec owner**: ML/Infrastructure.

### HIGH-2: Add `FIXOPS_FEEDS_OFFLINE` guard to feed importers

**Action**: Add a module-level check in `feeds_service.py` and each feed importer: if `FIXOPS_FEEDS_OFFLINE=1` is set, skip the HTTP fetch and load from a local snapshot path. The NVD and MITRE STIX paths already exist; extend the pattern to EPSS and CISA KEV.  
**Spec owner**: Feeds team. EPSS and KEV are the highest-value feeds for prioritization; losing them is the most customer-visible degradation.

### MEDIUM-1: Build and ship a distilled local model checkpoint

**Action**: Complete Phase 2 distillation (10K DPO pair threshold), export the Qwen 2.5 7B + LoRA adapter, include it in the SCIF deployment package, and set `FIXOPS_DISTILL_ADAPTER` to the mounted path. Until this exists, the "local intelligence" moat is a CVSS rule table.  
**Spec owner**: ML team. This is the single most important capability gap for the $100K SCIF value proposition.

---

## 8. Blunt Verdict

**Can ALDECI run today, fully air-gapped?**

Mechanically yes, with the right env vars set. The air-gap enforcement machinery is real code, not scaffolding. `FIXOPS_AIRGAP_MODE=enforced` will block cloud API calls, and the deterministic council fallback will produce triage verdicts.

**Is it worth $100K to a SCIF customer?**

No — not today — for one reason that dwarfs all others: **there is no trained local model**. The "multi-LLM consensus" and "local AI intelligence" selling points collapse to a CVSS severity lookup table in air-gap mode. The deterministic fallback in `llm_council.py:1011–1116` is well-engineered but it does not read findings contextually. A SCIF customer paying $100K/year for AI-native security intelligence will notice within the first week that every critical finding gets `remediate_critical` with identical boilerplate reasoning regardless of the actual vulnerability description.

The SCIF customer is paying for intelligence that cannot be obtained any other way inside the perimeter. Until a real local model (Ollama + a capable model, or the distilled Qwen adapter) is pre-staged and validated on representative ALDECI findings, the product does not deliver on its core air-gap promise.

The three configuration gaps (air-gap mode not default, telemetry kill-switch not auto-invoked, HuggingFace download not blocked) are fixable in a single deployment manifest update — hours of work. The missing local model is weeks to months of ML work plus infrastructure decisions about minimum hardware specs for SCIF deployment. That is the critical path item for retaining the renewal.
