---
source_url: internal://research-20260422
captured_at: 2026-04-22T11:34:59Z
author: competitor-sonatype-researcher-agent
contributor: claude-code-opus-4-7
---

# Competitor Deep Dive: Sonatype Lifecycle (on-prem / air-gapped)

## 0. Note on "Sonatype Sage"

The user referenced "Sonatype Sage." This is **SAGE — Sonatype Air-Gapped Environment**, not an AI/ML product. It is Sonatype's deployment bundle for classified, restricted, and regulated environments that cannot reach the internet. SAGE packages IQ Server (Lifecycle), Nexus Repository, Repository Firewall, and Auditor together with an **offline vulnerability/policy data feed** plus a mirrored Maven Central, synchronized by an administrator via daily "update tools" on an internet-connected machine that transfers signed bundles across the air gap ([Sonatype SAGE overview](https://www.sonatype.com/sonatype-air-gapped-environment-overview), [SAGE datasheet PDF](https://media.trustradius.com/product-downloadables/1L/JI/LHAEBLZC2C9N.pdf)). Sonatype's actual AI/ML branding is separate ("Sonatype AI SBOM" / behavioral-analysis features in Repository Firewall) and is not called Sage.

---

## 1. Product identity and SKUs

The umbrella platform is **Sonatype** (company) with individual SKUs. "Nexus Lifecycle" / "Nexus IQ Server" was renamed — the backend is still called **IQ Server**, but the commercial product is now **Sonatype Lifecycle** ([product page](https://www.sonatype.com/nexus/lifecycle), [help portal root](https://help.sonatype.com/en/sonatype-lifecycle.html)).

Active SKUs under the Sonatype umbrella:

| SKU | Purpose |
|---|---|
| **Sonatype Lifecycle** | SCA + policy engine + remediation (IQ Server). 18 default policies, 30+ constraint types, 20+ language ecosystems. |
| **Sonatype Repository** (formerly Nexus Repository) | Artifact manager. Editions: OSS (free), Pro, Pro+, Enterprise. |
| **Sonatype Repository Firewall** | Quarantines malicious/bad components before they land in Nexus Repository (behavioral ML analysis). |
| **Sonatype Developer** | IDE-centric / developer-seat SKU (lightweight Lifecycle for individual devs). |
| **Sonatype SBOM Manager** | SBOM ingest (CycloneDX / SPDX), continuous monitoring of third-party SBOMs. |
| **Sonatype Auditor** | Runtime/production scanning of deployed applications. |
| **SAGE** | Packaging + update-tool SKU that makes all of the above air-gap-deployable. |

Pricing is per-application or per-developer, list is obscured; mid-size bundles run $60K–$150K/yr ([TrustRadius pricing](https://www.trustradius.com/products/sonatype-nexus-platform/pricing), [Sonatype pricing](https://www.sonatype.com/products/pricing)).

---

## 2. On-prem deployment architecture

Reference: [Deployment Options](https://help.sonatype.com/en/deployment-options.html), [On-Premises Installation](https://help.sonatype.com/en/installation-on-premises.html), [Container Deployments](https://help.sonatype.com/en/container-deployments.html), [Lifecycle Deployment Best Practices](https://help.sonatype.com/en/lifecycle-deployment-best-practices.html).

**Core components:**

- **IQ Server** — Java/Jetty application, single JAR (`nexus-iq-server-*.jar`). Exposes the web UI and REST API on port `8070` (UI) and `8071` (admin). Stateful: holds scan metadata, reports, evaluation history.
- **Embedded H2 database** (default, single-node) **or external PostgreSQL** (recommended for HA/enterprise). PG is mandatory for the clustered HA deployment.
- **Data Services / Intelligence feed** — downloads vuln + component metadata from Sonatype's cloud API (or, in SAGE, from a locally mounted bundle synchronized via the update tool).
- **Shared storage** — scan results, generated reports, advanced-search index. NFS/object-store in HA.
- **Load balancer** — external L7 LB routing to IQ Server pods; sticky sessions only required briefly during login.
- **Nexus Repository** (optional but usually co-deployed) — artifact manager feeding Repository Firewall.
- **Repository Firewall** — a policy enforcement edge in front of proxy repos; calls IQ Server for the verdict.
- **CLI / CI agents** — external clients (Jenkins plugin, Nexus IQ CLI scanner, IDE plugins) authenticate to IQ Server.

**HA model**: active/active IQ Server pods behind the LB, sharing a PostgreSQL cluster and shared filesystem for blob storage; Helm charts published on Helm Hub and Docker images on Docker Hub. Sonatype recommends Kubernetes with a StatefulSet-style deployment for enterprise.

**Ports / surfaces to harden:** 8070 (UI/API), 8071 (admin/metrics), PG 5432, NFS/S3 endpoint, SMTP for notifications, LDAP/SAML/OIDC for auth.

---

## 3. UI screen map

Source: [Lifecycle Dashboard](https://help.sonatype.com/en/lifecycle-dashboard.html), [Waivers Explorer](https://help.sonatype.com/en/waivers-explorer.html), [Application Management](https://help.sonatype.com/en/application-management.html), [Policy Concepts](https://help.sonatype.com/iqserver/managing/policy-management/policy-concepts).

- **Dashboard (root)** — tabs: *Violations*, *Waivers*, *Components*, *Applications*, *SBOM*. Filterable by organization, stage, severity, policy. Export buttons on every tab.
- **Applications view** — per-app summary card showing latest scan per stage (Develop / Build / Stage / Release / Operate). Drill-in links to the latest report.
- **Organizations view** — hierarchical tree (Root Org → Org → App). Policies and waivers inherit downward.
- **Application Composition Report** — the core report per scan: tabs for *Policy Violations*, *Security Issues*, *License Analysis*, *Bill of Materials (SBOM)*, *Legal*, *Architecture*, *Labels*. Violations are grouped by threat level (0–10).
- **Component Details Page / Information Panel** — per-component: identity (PURL/hash/ABF), versions graph ("version explorer"), known CVEs, license data, integrity/popularity/age, recommended upgrade path ("Next-no-violation" / "Safest-no-change").
- **Policy editor** — list + builder for policies, constraints, conditions; inheritance toggle; action matrix (Warn / Fail per stage).
- **Waivers Explorer** — all waivers org-wide, filterable by scope, expiry, policy, creator. Supports bulk revoke.
- **Advanced Search** — search across all scans for a component/CVE/license.
- **User management / Role management / Access control** — RBAC UI.
- **System Preferences** — SMTP, LDAP/SAML/OIDC, proxy, data-retention, feature toggles, license upload.
- **SBOM Manager views** — imported-SBOM list, BOM comparison, continuous-monitoring status.

---

## 4. REST API surface

Full index: [IQ API Reference](https://help.sonatype.com/en/iq-api-reference.html). Base path `/api/v2/`. Auth = HTTP Basic with either the login user/password or a **User Token** (preferred for CI/service accounts — a disposable code/passcode pair scoped to the user's roles; [User Tokens](https://help.sonatype.com/en/iq-server-user-tokens.html), [User Token REST API](https://help.sonatype.com/en/user-token-rest-api.html)). There is no separate "API key" concept; Sonatype calls tokens the API credential. SAML/OIDC/LDAP drive UI login; tokens are what you use for machine access.

Key endpoints:

| Area | Endpoint (v2) |
|---|---|
| Applications | `GET/POST/PUT /applications`, `GET /applications/{publicId}` ([Application REST API](https://help.sonatype.com/en/application-rest-api.html)) |
| Organizations | `GET/POST/PUT /organizations` ([Organizations REST API](https://help.sonatype.com/en/organizations-rest-api.html)) |
| Evaluation (scan) | `POST /evaluation/applications/{appInternalId}` with component list → returns `statusUrl` for polling; `GET /evaluation/applications/{id}/status/{ticket}` ([Component Evaluation REST API](https://help.sonatype.com/en/component-evaluation-rest-api.html)) |
| Component details | `POST /components/details`, `POST /components/versions`, `POST /components/remediation/application/{id}` |
| Policies | `GET /policies`, `GET /policies/{id}` (policies primarily edited in the UI/import-export JSON) |
| Violations | `GET /policyViolations?p=*` ([Policy Violation REST API](https://help.sonatype.com/en/policy-violation-rest-api.html)) |
| Waivers | `POST /policyWaivers/{ownerType}/{ownerId}`, `GET /policyWaivers/...`, `DELETE /policyWaivers/{id}` ([Policy Waiver REST API](https://help.sonatype.com/en/policy-waiver-rest-api.html)); plus waiver-request and auto-waiver APIs. |
| Reports | `GET /applications/{publicId}/reports`, `GET /applications/{publicId}/reports/{reportId}/raw`, `/policy`, `/sbom/cyclonedx/1.6`, `/sbom/spdx/2.3` ([Report REST API](https://help.sonatype.com/en/report-rest-api.html)) |
| Users | `POST/PUT/DELETE /users` (when internal realm is used) |
| Roles / RBAC | `GET /roles`, `GET/PUT /roleMemberships/organization/{id}`, `…/application/{id}` ([Role REST API](https://help.sonatype.com/en/role-rest-api.html), [Authorization Configuration REST API](https://help.sonatype.com/en/authorization-configuration-rest-api.html)) |
| Audit log | `GET /auditLog` |
| Source control | `POST /sourceControl/application/{id}` |

---

## 5. Policy model

Hierarchy: **Policy → Constraint(s) → Condition(s) → Action(s) per Stage** ([Policy Concepts](https://help.sonatype.com/iqserver/managing/policy-management/policy-concepts), [Policy Constraints](https://help.sonatype.com/en/policy-constraints.html)).

- **Condition** = single `if` clause, e.g. `Security-VulnerabilitySeverity >= 7`, `License is GPL-3.0`, `Age > 3 years`, `Match State = exact`, `Component unknown = true`.
- **Constraint** = AND/OR group of conditions.
- **Policy** = OR of constraints, plus threat level (0–10), plus per-stage actions.
- **Stages**: `Develop` (IDE), `Build` (CI), `Stage Release`, `Release`, `Operate` (runtime/Auditor). Each stage independently configurable to **Warn** or **Fail**.
- Inheritance: policies attach at Root Org / Org / App level and cascade down; children can be restricted from overriding.

**Example 1 — Critical CVE blocker:**
```
Policy: "Security-Critical"
  Threat: 10
  Constraint "Any critical CVSS":
    Condition: Security Vulnerability Severity >= 9
    Condition: Security Vulnerability Status = Open
  Actions: Build=Fail, Stage=Fail, Release=Fail, Operate=Warn
```

**Example 2 — Copyleft license gate:**
```
Policy: "Copyleft-Forbidden"
  Threat: 8
  Constraint "Copyleft license":
    Condition: License Threat Group = Copyleft
    Condition: License Status != Overridden
  Actions: Develop=Warn, Build=Warn, Release=Fail
```

**Example 3 — Architectural hygiene (old components):**
```
Policy: "Ancient-Component"
  Threat: 3
  Constraint:
    Condition: Age > 4 years
    Condition: Relative Popularity < 20
    Condition: Newer version available
  Actions: Develop=Warn only
```

---

## 6. Component intelligence — where the data comes from

- **Sonatype Intelligence / Advanced Dev Pack** — the curated, human-reviewed dataset. CVEs mapped+enriched, false-positive suppression, reachability hints, "no-violation" upgrade paths. This is the paid differentiator ([Sonatype Intelligence](https://www.sonatype.com/products/intelligence)).
- **OSS Index** — the free public tier, mostly NVD-mapped data; surfaced via [ossindex.sonatype.org](https://ossindex.sonatype.org/) and also consumed by OWASP Dependency-Check, Dependency-Track, etc. Less enriched.
- **Repository Firewall intelligence** — behavioral/ML signals on new releases: typosquats, maintainer anomalies, install-script exfiltration, protestware. Sonatype reports 870K+ malicious packages catalogued ([OSS Malware Index Q2 2025](https://www.sonatype.com/blog/open-source-malware-index-q2-2025)).
- **Advanced Binary Fingerprint (ABF)** — cryptographic + structural hash so renamed / shaded / repackaged components are still identified.

Data categories ingested per component: **CVEs (NVD + Sonatype-proprietary IDs), license declarations + observed, integrity (malicious/tampered), architectural (age, popularity, maintainers, release cadence), legal (license-threat-group, obligations), behavioral (install-time network calls, obfuscation, namespace confusion)**.

---

## 7. Integrations

[Sonatype Integrations hub](https://help.sonatype.com/en/sonatype-integrations.html), [CI and CLI Integrations](https://help.sonatype.com/en/ci-and-cli-integrations.html).

- **IDE**: IntelliJ IDEA, VS Code, Visual Studio 2022, Eclipse.
- **CI**: Jenkins ([Sonatype Platform Plugin for Jenkins](https://help.sonatype.com/en/sonatype-platform-plugin-for-jenkins.html)), Bamboo (Data Center), Azure DevOps ([Sonatype for Azure DevOps](https://help.sonatype.com/en/sonatype-for-azure-devops.html)), GitLab CI, GitHub Actions, CircleCI.
- **SCM**: GitHub, GitLab, Bitbucket — pushes violations as PR checks / Bitbucket Code Insights.
- **CLI**: Nexus IQ CLI (`nexus-iq-cli` jar), also a native scan CLI. Scans Maven/Gradle/npm/PyPI/NuGet/Go/etc. and Docker images via container scanner.
- **Container**: [Sonatype Container Security](https://help.sonatype.com/en/sonatype-container-security.html) scans OCI images.
- **Chat/Ticketing**: ServiceNow, Jira, Slack, MS Teams webhooks (via notification rules on policies).
- **Auth**: LDAP, SAML (including Auth0), OIDC, Crowd.

---

## 8. Remediation workflow

Reference: [Creating a Lifecycle Remediation Plan](https://help.sonatype.com/en/creating-a-lifecycle-remediation-plan.html), [Remediation Best Practices](https://help.sonatype.com/iqserver/lifecycle-best-practices/remediation-best-practices), [Waivers](https://help.sonatype.com/en/waivers.html), [Automated Waivers](https://help.sonatype.com/en/automated-waivers.html).

Priority order Sonatype pushes to developers:

1. **Upgrade** to a non-violating version — the UI surfaces "Next-no-violation" and "Safest-no-change" recommended versions per component. One-click copy of the new coordinate.
2. **Migrate** to an alternate component of similar function.
3. **Request a waiver** — developer clicks *Request Waiver* → routed to policy owner for approval; waiver can be scoped to app / org / root and time-bound.
4. **Automated waiver** — IQ auto-grants waivers for violations that are (a) low-threat with no upgrade path, or (b) not reachable per call-graph analysis. Waivers roll off automatically when an upgrade path appears.
5. **Claim/label** — mark a component as internal/proprietary or attach labels changing its evaluation.

The **Remediation Plan** screen aggregates all violations for an app into a grouped action list and shows projected violation-count reduction per fix.

---

## 9. Multi-tenancy & RBAC

[Role-Based Access Control](https://help.sonatype.com/en/role-based-access-control.html), [Authorization and Authentication Concepts](https://help.sonatype.com/en/authorization-and-authentication-concepts.html).

- Hierarchy: **Root Organization → Organization(s) → Application(s)**. Policies, waivers, role mappings all inherit down.
- Built-in roles: *System Administrator*, *Policy Administrator*, *Owner*, *Developer*, *Application Evaluator*. Custom roles are supported.
- Role assignment is **contextual**: the same user can be Developer on App A and Owner on Org B. Groups from LDAP/SAML can be mapped to roles.
- Permissions cover: view/edit apps, view/edit orgs, evaluate, change policies, waive violations, manage users, read audit log, claim components.

---

## 10. Reports & export

- **Application Composition Report** — HTML in UI; exports as PDF and JSON.
- **Policy Violation export** — CSV/JSON from the Dashboard tab.
- **SBOM** — [CycloneDX 1.4/1.5/1.6 and SPDX 2.3](https://help.sonatype.com/en/cyclonedx.html), both JSON and XML, UI button or via `/api/v2/applications/{publicId}/reports/{reportId}/sbom/...` ([SBOM docs](https://help.sonatype.com/en/software-bill-of-materials-sbom.html)). SBOM-Manager also ingests third-party SBOMs and continuously re-evaluates them.
- **Success Metrics** — JSON/CSV time-series of MTTR, violation rates, waiver counts, per-org trending ([Success Metrics REST API]).
- **Audit log** — JSON export of every RBAC, policy, waiver, evaluation event (required for FedRAMP/IL-class deployments) — [Audit Log REST API](https://help.sonatype.com/en/audit-log-rest-api.html).
- **Raw report** — `reports/{id}/raw` returns the full component+violation tree, suitable for BI pipelines.

---

## What Fixops should absorb — top 5 for on-prem / air-gapped customers

1. **A genuine offline data-sync story (SAGE-equivalent).** Sonatype's single biggest win with defense/classified buyers is the *update tool* pattern: signed daily intelligence bundles produced on an internet side, sneakernet-transferred, applied with a CLI. Fixops should ship a first-class `fixops-offline-bundle` signed tarball and a documented two-machine workflow — not "we support an HTTPS proxy."

2. **Hierarchical org/app model with inherited policies + inherited waivers.** The `Root Org → Org → App` tree with role scoping and downward policy/waiver inheritance is the reason Sonatype scales to 500+ apps without the admin console becoming unusable. Flat tagging will not compete.

3. **Per-stage enforcement verdicts (Develop / Build / Stage / Release / Operate) with Warn-vs-Fail per stage.** This is table-stakes for regulated customers — it lets them run loose in dev, strict at release — and it is how the IDE, CI plugin, and CLI all share one policy engine. Fixops's policy engine should emit a verdict *per stage* on every evaluation.

4. **Auto-waivers tied to reachability + upgrade-path analysis.** Sonatype's auto-waiver removes the biggest developer complaint ("I have 400 violations and can't fix any of them"). Pairing Fixops's reachability signal with automatic, auto-expiring waivers — that roll off the moment an upgrade path appears — would be a concrete differentiator, because most SCA vendors still make waivers purely manual.

5. **First-class RBAC with User Tokens + full audit log REST API.** Air-gapped/regulated buyers require (a) no shared passwords in CI, (b) per-user disposable machine credentials, (c) exportable tamper-evident audit trails for every policy, waiver, and evaluation event. Fixops should match Sonatype's User Token + audit-log API 1:1; these are checklist items on every federal RFP.

---

Sources:
- [Sonatype Lifecycle product page](https://www.sonatype.com/nexus/lifecycle)
- [Sonatype Lifecycle help root](https://help.sonatype.com/en/sonatype-lifecycle.html)
- [Deployment Options](https://help.sonatype.com/en/deployment-options.html)
- [Installation On-Premises](https://help.sonatype.com/en/installation-on-premises.html)
- [Container Deployments](https://help.sonatype.com/en/container-deployments.html)
- [Lifecycle Deployment Best Practices](https://help.sonatype.com/en/lifecycle-deployment-best-practices.html)
- [SAGE overview](https://www.sonatype.com/sonatype-air-gapped-environment-overview)
- [SAGE datasheet (PDF)](https://media.trustradius.com/product-downloadables/1L/JI/LHAEBLZC2C9N.pdf)
- [Software Governance in Air-Gapped Environments](https://www.sonatype.com/blog/mastering-software-governance-in-air-gapped-critical-mission-environments)
- [Policy Concepts](https://help.sonatype.com/iqserver/managing/policy-management/policy-concepts)
- [Policy Constraints](https://help.sonatype.com/en/policy-constraints.html)
- [Lifecycle Dashboard](https://help.sonatype.com/en/lifecycle-dashboard.html)
- [Waivers](https://help.sonatype.com/en/waivers.html)
- [Waivers Explorer](https://help.sonatype.com/en/waivers-explorer.html)
- [Automated Waivers](https://help.sonatype.com/en/automated-waivers.html)
- [Creating a Lifecycle Remediation Plan](https://help.sonatype.com/en/creating-a-lifecycle-remediation-plan.html)
- [IQ API Reference](https://help.sonatype.com/en/iq-api-reference.html)
- [Component Evaluation REST API](https://help.sonatype.com/en/component-evaluation-rest-api.html)
- [Organizations REST API](https://help.sonatype.com/en/organizations-rest-api.html)
- [Role REST API](https://help.sonatype.com/en/role-rest-api.html)
- [User Token REST API](https://help.sonatype.com/en/user-token-rest-api.html)
- [IQ Server User Tokens](https://help.sonatype.com/en/iq-server-user-tokens.html)
- [Role-Based Access Control](https://help.sonatype.com/en/role-based-access-control.html)
- [Report REST APIs](https://help.sonatype.com/en/report-rest-api.html)
- [CycloneDX Application Analysis](https://help.sonatype.com/en/cyclonedx.html)
- [SBOM docs](https://help.sonatype.com/en/software-bill-of-materials-sbom.html)
- [Sonatype Integrations](https://help.sonatype.com/en/sonatype-integrations.html)
- [CI and CLI Integrations](https://help.sonatype.com/en/ci-and-cli-integrations.html)
- [Sonatype Platform Plugin for Jenkins](https://help.sonatype.com/en/sonatype-platform-plugin-for-jenkins.html)
- [Sonatype for Azure DevOps](https://help.sonatype.com/en/sonatype-for-azure-devops.html)
- [Sonatype Container Security](https://help.sonatype.com/en/sonatype-container-security.html)
- [Sonatype Intelligence](https://www.sonatype.com/products/intelligence)
- [OSS Index](https://ossindex.sonatype.org/)
- [OSS Malware Index Q2 2025](https://www.sonatype.com/blog/open-source-malware-index-q2-2025)
- [Sonatype Pricing](https://www.sonatype.com/products/pricing)
- [TrustRadius pricing](https://www.trustradius.com/products/sonatype-nexus-platform/pricing)
