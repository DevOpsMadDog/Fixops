# Gap Analysis Refresh — Executive Summary (2026-04-26)

**HEAD:** `a1ad41617e549766032c87cc89b62732a6dbaa61` (`features/intermediate-stage`)
**Source:** `raw/competitive/gap-matrix.md` (71 rows). **Detail:** `raw/competitive/gap-matrix-2026-04-26.md`.

## Counts

| Status | Count |
|---|---|
| DONE | 50 |
| IN-PROGRESS | 12 |
| NOT-STARTED | 6 |
| NEEDS-PRODUCT-DECISION | 2 |
| SUPERSEDED | 1 |
| **Total** | **71** |

70.4% closed. Remaining IN-PROGRESS rows mostly need follow-on UI/SDK work (Monaco for NEW-G071, typed SDKs for GAP-037, 10k-node benchmark for GAP-047). NOT-STARTED is dominated by deferred XL items (GAP-048 OSS-corpus call graphs).

## What changed since the matrix was authored

86+ commits on `features/intermediate-stage` since 2026-04-22 closed all 14 KEEP engines, 30+ MERGE engines, and executed 5 KILLs. Tonight's 19-commit session (2026-04-25/26) added eight OSS-tool integration families — `siem`, `edr_xdr`, `iam_sso`, `container_security`, `cspm`, `dast_pentest`, `threat_intel`, `snyk_oss` — totalling ~7.5K LOC of connector code, plus a critical dashboard render fix in `07994f29` that unblocks the unified-issues UX.

## Commercial vendor format realism — the honest answer

The integration topology document claims eight OSS tools "replace" eight commercial SaaS products. Audited against the connector code:

- **13 vendor formats can be ingested from a static dump** (no vendor-cloud touch): Splunk HEC, Sentinel KQL, Datadog Logs Intake, ArcSight CEF, QRadar CEF, ELK `_bulk` ECS, Wazuh, Suricata, Okta System Log, Auth0 Tenant Log, Entra sign-in/audit, Keycloak, MISP feed manifest, Trivy, Prowler, Checkov.
- **3 vendors are reachable via live REST/GraphQL only** (no offline parser): Snyk OS via `api.snyk.io`, Wiz CSPM via `api.wiz.io` GraphQL, ServiceNow.
- **Eleven SaaS products are *substituted* by an OSS family but their exported JSON cannot be ingested**: CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Sysdig Secure, Snyk Container, Veracode DAST, Invicti, Acunetix, Lacework, Chronicle, Recorded Future, Mandiant.

Investor messaging that says "we ingest CrowdStrike, SentinelOne, Defender" is **inaccurate**. Accurate framing: "Falco + osquery + Wazuh form an OSS EDR family that produces the same `endpoint_alert` finding-source category, ingested through the same Brain Pipeline." The sentence in `INVESTOR_PITCH.md` and the integration topology HTML should be rewritten.

## Tonight's biggest realism upgrade

`9705e7f8` (SIEM real via Wazuh + ELK) is the highest-leverage commit of the night. Nine genuine format adapters (`SplunkHECAdapter`, `DatadogAdapter`, `SentinelKQLAdapter`, `ELKBulkAdapter`, `WazuhAdapter`, `SuricataAdapter`, `CEFAdapter`, `SyslogAdapter`, `JSONLinesAdapter`) — 1,404 LOC, 51/51 tests passing. This moves SIEM from "we have an output connector" to "we ingest SIEM data in every common enterprise format, including Splunk HEC, Sentinel KQL, and Datadog". The IAM adapters (`d849c68d`) are a similar realism upgrade: Okta, Auth0, and Entra raw JSON normalise into the Keycloak event shape used by the existing mirror layer.

## Recommended next moves

1. **P0** — Add a Falcon Detection.Created JSON adapter beside `WazuhAdapter` in `edr_connector.py` (≈2 days). Closes the most-requested commercial-vendor format gap.
2. **P1** — Update `INVESTOR_PITCH.md` + integration topology HTML to the accurate "Y / API-LIVE / Substitute" three-tier framing.
3. **P1** — Resolve GAP-014 and GAP-058 product decisions (UNCLEAR for 4+ days).
4. **P2** — Publish typed SDK packages (PyPI, npm, Go-mod) to close GAP-037.

---

*Per-row evidence in `raw/competitive/gap-matrix-2026-04-26.md`.*
