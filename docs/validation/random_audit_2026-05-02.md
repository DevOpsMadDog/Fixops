# random.* Simulation Classification Audit — suite-core/
**Date:** 2026-05-02  
**Auditor:** code-analyzer agent  
**Branch:** features/intermediate-stage  
**Scope:** All `*.py` files under `suite-core/` containing `import random`, `from random`, `np.random`, `secrets.choice`, or `os.urandom`  
**Total files found:** 57  
**Total random.* call sites:** 60+  

---

## Category Tables

### LEGITIMATE — Cryptographic / Auth (18 files)

| Filename | Lines | random.* calls | Evidence Snippet |
|---|---|---|---|
| `core/crypto.py` | 2807 | 3 | `secrets.token_bytes(_AES_KEY_LENGTH)` — AES key/nonce gen |
| `core/api_key_manager.py` | 520 | 2 | `secrets.token_hex(_KEY_HEX_LEN // 2)` — API key minting |
| `core/auth_bootstrap.py` | 248 | 3 | `secrets.token_hex(length // 2)` — bootstrap secret gen |
| `core/auth_middleware.py` | 262 | 1 | `secrets.token_urlsafe(32)` — session CSRF token |
| `core/encrypted_store.py` | 371 | 3 | `secrets.token_bytes(_NONCE_LENGTH)` — AES-GCM nonce |
| `core/key_manager.py` | 474 | 2 | `secrets.token_urlsafe(_KEY_LENGTH)` — key material |
| `core/quantum_crypto.py` | 2610 | 18 | `secrets.token_bytes(64)` — PQ seed; `secrets.token_hex(8)` — KID |
| `core/rbac_engine.py` | 667 | 1 | `secrets.token_urlsafe(32)` — RBAC delegation token |
| `core/session_manager.py` | 545 | 1 | `secrets.token_hex(16)` — session ID |
| `core/utils/enterprise/crypto.py` | 968 | 10 | `secrets.choice(alphabet)` — password gen; `secrets.SystemRandom().shuffle` |
| `core/pam.py` | 585 | 1 | `secrets.token_hex(8)` — PAM credential ID |
| `core/sso_bridge.py` | 330 | 2 | `secrets.token_hex(16/24)` — SSO access/session token |
| `core/fips_encryption.py` | 232 | 0 | (import present, zero call sites — safe) |
| `core/hsm_provider.py` | 556 | 0 | (import present, zero call sites — safe) |
| `config/enterprise/settings.py` | 347 | 0 | (import present, zero call sites — safe) |
| `api/self_learning_router.py` | 836 | 0 | (import present, zero call sites — safe) |
| `core/api_gateway.py` | 1347 | 0 | (import present, zero call sites — safe) |
| `core/cli.py` | 6051 | 0 | (import present, zero call sites — safe) |

---

### LEGITIMATE — Monte Carlo / FAIR / Statistical ML (13 files)

| Filename | Lines | random.* calls | Evidence Snippet |
|---|---|---|---|
| `core/monte_carlo.py` | 571 | 1 | `np.random.default_rng(seed)` — FAIR Monte Carlo engine |
| `core/executive_dashboard.py` | 1382 | 2 | `random.Random(seed)` — FAIR simulation + seeded historical trend |
| `core/risk_quantification_engine.py` | 550 | 1 | `rng.random() < likelihood` — Monte Carlo loss sampling |
| `core/risk_quantifier.py` | 900 | 2 | `_pert_sample()` — PERT distribution; seeded per scenario |
| `core/models/markov_chain.py` | 574 | 3 | `np.random.choice(n_states, p=probs)` — Markov transition |
| `core/ml/anomaly_detector.py` | 709 | 1 | `np.random.RandomState(self.random_seed)` — sklearn compat |
| `core/ml/attack_path_gnn.py` | 922 | 1 | `np.random.RandomState(seed)` — GNN weight init |
| `core/ml/autofix_confidence.py` | 734 | 1 | `np.random.RandomState(self.random_seed)` — bootstrap CI |
| `core/ml/consensus_calibrator.py` | 560 | 1 | `np.random.RandomState(42)` — calibration split |
| `core/ml/predictive_scorer.py` | 732 | 1 | `np.random.RandomState(random_seed)` — model RNG |
| `core/ml/regression_predictor.py` | 1308 | 1 | `np.random.RandomState(self.random_seed)` — regression |
| `core/ml/risk_scorer.py` | 1289 | 1 | `np.random.RandomState(self.random_seed)` — risk ML model |
| `core/single_agent.py` | 2404 | 1 | `random.choices(confidences, k=len(confidences))` — bootstrap CI for agent confidence interval |

---

### LEGITIMATE — Jitter / Backoff / Algorithmic Sampling (4 files)

| Filename | Lines | random.* calls | Evidence Snippet |
|---|---|---|---|
| `core/integration_hub.py` | 1423 | 1 | `random.uniform(0, 0.5)` in retry loop — exponential backoff jitter |
| `core/falkordb_client.py` | 1879 | 1 | `random.sample(node_ids, min(sample_size, …))` — betweenness centrality approximation |
| `core/zero_gravity.py` | 2157 | 2 | `random.Random(42)` fixed-seed for LSH hash coefficients; `_random.random()` weighted choice |
| `core/attack_graph_gnn.py` | 744 | 1 | `np.random.default_rng(42)` — GNN layer weight init |

---

### SIMULATED DATA — Fake findings/metrics returned via live API endpoints (11 files)

| Filename | Lines | random.* calls | Classification | Evidence Snippet | Real Integration Needed |
|---|---|---|---|---|---|
| `core/devsecops_engine.py` | 1160 | 8 | **SIMULATED DATA** | `random.randint(0,8)` finding counts; `f"CVE-2024-{random.randint(1000,9999)}"` fake CVE IDs; `random.random()` severity roll — inside `_simulate_finding_severities()` | Real scanner results via SAST/SCA connector calls |
| `core/cloud_drift_engine.py` | 466 | 4 | **SIMULATED DATA** | `random.random() < 0.2` — 20% of baselines randomly flagged as drifted inside `run_drift_scan()`. Comment: *"In production this would call cloud provider APIs"* | Cloud provider API diffing (AWS Config, Azure Policy, GCP Org Policy) |
| `core/compliance_scanner_engine.py` | 673 | 1 | **SIMULATED DATA** | `random.Random()` unseeded — 70% pass/15% fail roll inside compliance scan. No real control evaluation | Real control evidence collection per framework |
| `core/config_benchmark_engine.py` | 493 | 1 | **SIMULATED DATA** | `random.Random(result_id)` seeded — 65% pass/25% fail rolls replacing real CIS benchmark checks | Real benchmark runner (Lynis, kube-bench, etc.) |
| `core/kubernetes_security_engine.py` | 440 | 2 | **SIMULATED DATA** | `rng = random.Random(cluster_id)` — fake CIS k8s category pass/fail counts; `random.Random(cluster_id + "_rbac")` — synthetic RBAC role counts | kubectl/kube-bench API + real RBAC query |
| `core/security_scorecard.py` | 599 | 2 | **SIMULATED DATA** | `_simulate_score()` with `rng.uniform(-var, var)` — all category scores (network, app, cloud, identity) are seeded-random; comment says *"In production this would query real platform data"* | Cross-engine aggregation from real scanner results |
| `core/vendor_scorecard.py` | 618 | 1 | **SIMULATED DATA** | `random.Random(hash(domain) % 2**32)` — SSL/headers/DNS scores generated without real probes; comment: *"In production these would be real probes"* | Real SSL/headers/DNS probes (ssl, dnspython, requests) |
| `core/ioc_enrichment_engine.py` | 431 | 2 | **SIMULATED DATA** | `random.Random(hash(value))` — seeded deterministic but enrichment fields (confidence, geo, campaigns) are hash-derived, not from real TI feeds | Real TI feed lookups (VirusTotal, AbuseIPDB, Shodan) |
| `core/ccm_engine.py` | 559 | 1 | **SIMULATED DATA** | `random.random()` — CCM test run outcome (80% passing, 15% failing, 5% degraded) inside `run_ccm_test()`. No real test execution | Real CCM test execution against live controls |
| `connectors/iam_sso_connector.py` | 1095 | 11 | **SIMULATED DATA** | `random.choice(["aldeci-portal","admin-cli"])`, `random.randint(10,250)` fake IPs — synthetic Keycloak login/admin event generator used when real Keycloak unavailable | Real Keycloak API polling (`/events`, `/admin/events`) |
| `core/openclaw_engine.py` | 1016 | 1 | **SIMULATED DATA** | `random.random() < success_prob` — campaign task outcome (succeeded/failed) is a probability roll, not a real attack test result | Real offensive test framework result ingestion |

---

### NEEDS REVIEW — Seeded-deterministic but scope ambiguous (4 files)

| Filename | Lines | random.* calls | Evidence Snippet | Question |
|---|---|---|---|---|
| `core/breach_simulation.py` | 688 | 1 | `random.Random(hash(f"{org_id}:{scenario.value}"))` — deterministic block/detect probability for named breach scenarios | Intentional simulation (product feature) vs fake posture metric? If surfaced in dashboard without "simulation" label, it's misleading |
| `core/red_team_engine.py` | 562 | 1 | `random.Random(seed_str)` seeded from simulation_id+org_id — detection probability rolls | Same as above — legitimate if clearly labeled as "simulated red team run" |
| `core/self_learning.py` | 1444 | 1 | `random.Random(42)  # Deterministic seed for reproducible demo` — DPO pair generation | Comment says "demo" — safe if only used in training data gen, not in live API response |
| `connectors/siem_connector.py` | 1617 | 1 | `random.Random(seed)` — seeded event generator for multi-format SIEM test data | Test harness only or live API? Confirm caller context |

---

## Summary Statistics

| Category | File Count |
|---|---|
| LEGITIMATE — Cryptographic / Auth | 18 |
| LEGITIMATE — Monte Carlo / FAIR / ML | 13 |
| LEGITIMATE — Jitter / Backoff / Algorithmic | 4 |
| SIMULATED DATA | 11 |
| NEEDS REVIEW | 4 |
| **Total** | **57** (3 files counted in import-present/zero-calls, not double-counted) |

---

## DEMO DANGER LIST — Simulated files ranked by click-in-demo likelihood

Cross-referenced with live API routers in `suite-api/apps/api/`.

| Rank | Engine File | Calling Router | Demo Screen | Danger Rationale |
|---|---|---|---|---|
| 1 | `core/devsecops_engine.py` | `devsecops_router.py` | Pipeline Runs / Security Gates | Fake CVE IDs (`CVE-2024-XXXX`) and random finding counts written to DB on every pipeline trigger. Will be the first thing a demo viewer clicks. |
| 2 | `core/security_scorecard.py` | `security_scorecard_router.py`, `security_scorecard_engine_router.py` | Executive Dashboard / Scorecard | All category scores (Network, App, Cloud, Identity) are seeded-random. High visibility, high trust expectation. |
| 3 | `core/compliance_scanner_engine.py` | `compliance_scanner_router.py`, `compliance_router.py`, `grc_app.py` | Compliance / GRC | Random pass/fail rolls masquerade as real control evaluations. Any compliance-focused buyer will scrutinize these. |
| 4 | `core/vendor_scorecard.py` | `vendor_scorecard_router.py`, `vendor_risk_router.py` | Vendor Risk | Domain-hash scores replace real SSL/DNS probes. A demo with a known vendor (Google, GitHub) will look obviously wrong. |
| 5 | `core/kubernetes_security_engine.py` | *(via `analytics_engine_router.py`, `unified_dashboard_router.py`)* | K8s Security / CIS Benchmark | Fake CIS pass/fail category counts; synthetic RBAC role totals. DevSecOps buyers will spot implausible numbers immediately. |
| 6 | `core/cloud_drift_engine.py` | `cloud_drift_router.py` | Cloud Drift / CSPM | 20% random drift flag on every scan run — numbers change on each API call. |
| 7 | `connectors/iam_sso_connector.py` | `iam_sso_router.py` | IAM / SSO Events | Synthetic Keycloak events with random IPs and event types — obvious if Keycloak is not connected. |
| 8 | `core/config_benchmark_engine.py` | *(via `analytics_engine_router.py`)* | Config Benchmarks | Seeded-random pass/fail, but result_id-seeded so stable per run — lower immediate danger, but still fake. |
| 9 | `core/ccm_engine.py` | `ccm_router.py` | CCM / Continuous Controls | Random test outcome (80/15/5 split) with no real test execution. |
| 10 | `core/openclaw_engine.py` | `openclaw_router.py` | Red Team / Campaign Tasks | Task success/failure is a probability roll. |
| 11 | `core/ioc_enrichment_engine.py` | *(via `unified_dashboard_router.py`)* | Threat Intel / IOC | Enrichment fields are hash-derived from the IOC value, not from real TI feeds. |

---

## Top-20 SIMULATED Files — Replacement Priority + Effort Estimate

| Priority | File | random.* calls | Fix Action | Effort Estimate |
|---|---|---|---|---|
| 1 | `core/devsecops_engine.py` | 8 | Replace `_simulate_finding_severities()` — call real SAST/SCA connector and parse results. Remove random finding count gen. | 3–5 days |
| 2 | `core/security_scorecard.py` | 2 | Replace `_simulate_score()` — aggregate real scanner results from existing engines per category. | 4–6 days |
| 3 | `core/compliance_scanner_engine.py` | 1 | Replace random pass/fail with real control-evidence evaluation per framework (NIST, SOC2, PCI-DSS). | 5–8 days |
| 4 | `connectors/iam_sso_connector.py` | 11 | Gate synthetic generator behind a `SYNTH_EVENTS=true` flag; in production, poll real Keycloak `/events` and `/admin/events` APIs. | 2–3 days |
| 5 | `core/vendor_scorecard.py` | 1 | Replace `_auto_assess()` — real SSL probe via `ssl`/`requests`, DNS via `dnspython`. Can run in background task. | 2–3 days |
| 6 | `core/kubernetes_security_engine.py` | 2 | Replace seeded RBAC/CIS counts with real `kubectl`/kube-bench result ingestion. | 3–5 days |
| 7 | `core/cloud_drift_engine.py` | 4 | Replace `run_drift_scan()` random flagging with real cloud provider API diffing (AWS Config Rules, Azure Policy). | 4–6 days |
| 8 | `core/config_benchmark_engine.py` | 1 | Replace seeded rolls with real benchmark runner output (Lynis for Linux, kube-bench for k8s). | 3–4 days |
| 9 | `core/ccm_engine.py` | 1 | Replace `run_ccm_test()` probability roll — invoke real control check function per control type. | 2–3 days |
| 10 | `core/ioc_enrichment_engine.py` | 2 | Add real TI feed lookup (VirusTotal API, AbuseIPDB) before falling back to seeded heuristics. | 2–3 days |
| 11 | `core/openclaw_engine.py` | 1 | Replace task success roll with real offensive test executor result ingestion. | 3–5 days |
| 12 | `core/breach_simulation.py` | 1 | Label output clearly as "simulated" in API response; add `is_simulation: true` flag. | 0.5 days |
| 13 | `core/red_team_engine.py` | 1 | Same — add `is_simulation: true` flag to all detection results. | 0.5 days |
| 14 | `core/self_learning.py` | 1 | Confirm demo-only path; gate behind `DEMO_MODE=true`. | 0.5 days |
| 15 | `connectors/siem_connector.py` | 1 | Confirm if seeded event gen is test-harness-only; if not, gate it. | 0.5 days |

*Items 12–15 are NEEDS REVIEW files — effort is labeling/gating, not full replacement.*

**Total estimated sprint to clear all 11 SIMULATED files: 35–58 engineer-days (~2 sprints at 3 engineers).**

---

## Positive Findings

- All cryptographic randomness uses `secrets.*` or `os.urandom` — no `random.random()` for key generation anywhere.
- Monte Carlo and ML modules consistently use seeded `np.random.RandomState` with configurable seeds — correct pattern.
- `integration_hub.py` jitter pattern (`random.uniform(0, 0.5)` + exponential backoff) is textbook correct.
- `falkordb_client.py` uses `random.sample` for betweenness approximation — standard graph algorithm optimization.
- Several seeded-random engines (`kubernetes_security_engine`, `config_benchmark_engine`) already produce stable (deterministic) outputs per entity — lower replay-detection risk than unseeded engines.
- `risk_quantification_engine.py` Monte Carlo is structurally correct: samples loss × likelihood, producing real percentile distributions — not fake.
