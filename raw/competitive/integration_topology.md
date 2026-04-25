# Integration Topology — TrustGraph Meta-Graph

_Generated: 2026-04-25T09:25:17.637758+00:00_

- **Tenants**: 15
- **Integration families**: 8
- **Total nodes ingested**: 160
- **Total edges ingested**: 259

## Nodes by type
- `Connector`: 120
- `FindingSource`: 8
- `FixopsEngine`: 9
- `OSSTool`: 8
- `Tenant`: 15

## Integration families
| Family | OSS Tool | Replaces | Fixops Engine | Finding Source |
|---|---|---|---|---|
| snyk_oss | Trivy | Snyk Open Source | `software_composition_analysis_engine` | `cve` |
| cspm | Prowler | Wiz / Lacework CSPM | `cspm_analyzer` | `misconfig` |
| edr_xdr | Wazuh | CrowdStrike Falcon / SentinelOne | `edr_engine` | `endpoint_alert` |
| siem | OpenSearch + Wazuh SIEM | Splunk / Sentinel | `siem_integration_engine` | `log_event` |
| container | Falco + Trivy | Sysdig Secure / Aqua | `container_runtime_security_engine` | `runtime_violation` |
| iam | Keycloak + ScoutSuite IAM | Okta / Sailpoint | `iam_policy_analyzer` | `iam_drift` |
| threat_intel | MISP + OpenCTI | Recorded Future / Mandiant | `threat_intel_fusion_engine` | `ioc` |
| dast | OWASP ZAP | Veracode DAST / Invicti | `dast_engine` | `dast` |

## Tenants
| Tenant | Vertical | Tier | Connectors |
|---|---|---|---|
| `juice-shop-corp` | fintech | enterprise | 8 |
| `dvwa-mfg` | manufacturing | enterprise | 8 |
| `webgoat-health` | healthcare | enterprise | 8 |
| `petclinic-saas` | saas | growth | 8 |
| `nodegoat-retail` | retail | growth | 8 |
| `bodgeit-edu` | education | starter | 8 |
| `vampi-gov` | government | enterprise | 8 |
| `altoro-bank` | fintech | enterprise | 8 |
| `hackazon-ecom` | retail | growth | 8 |
| `vulnado-airlines` | transport | enterprise | 8 |
| `railsgoat-media` | media | growth | 8 |
| `django-vuln-energy` | energy | enterprise | 8 |
| `graphql-pwn-telecom` | telecom | enterprise | 8 |
| `ssrf-lab-biotech` | biotech | growth | 8 |
| `log4shell-pos-grocery` | retail | starter | 8 |

## Sample shortest path (BFS over real TrustGraph edges)

Query: `tenant_juice-shop-corp` → `engine_security_event_correlation_engine`

```
  tenant_juice-shop-corp
  -> conn_juice-shop-corp__edr_xdr
  -> tool_wazuh
  -> engine_security_event_correlation_engine
```
_3 hops_

## Edge vocabulary
- `HAS_CONNECTOR` — tenant owns a connector instance
- `USES_TOOL` — connector binds to an OSS tool (replaces a paid SaaS)
- `FEEDS_ENGINE` — OSS tool emits findings into a Fixops engine
- `EMITS_TO` — Fixops engine produces a finding-source category

## Cross-link to Fixops research graph
Engines listed here are the same nodes already present in `graphify-out/graph-filtered.html` 
(the Fixops + research graph). When the new `graphify-out-integrations/graph.html` is overlaid, 
the engine nodes act as joins linking the two corpora into one federation map.
