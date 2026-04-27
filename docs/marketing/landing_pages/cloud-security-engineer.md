---
persona: Cloud Security Engineer
seo_keyword: "CSPM attack path graph multi-cloud security platform"
seo_meta: "ALdeci maps attack paths across AWS, GCP, and Azure with open-source CSPM engines, Edmonds-Karp choke-point detection, and CIEM — no per-cloud agent required."
---

# Landing Page — Cloud Security Engineer

## Hero Headline

Attack Paths, Choke Points, and Cloud Posture — One Graph, Three Clouds

## Sub-Hero

ALdeci correlates CSPM findings, IAM misconfigurations, and container vulnerabilities into a single attack-path graph with Edmonds-Karp choke-point detection — showing you which single fix cuts the most attacker routes.

---

## Three Proof Bullets

- **Choke-point detection via Edmonds-Karp min-cut on the attack graph — industry-first in open CTEM.** attack_path_engine.py runs min-cut analysis to identify the nodes whose removal maximally reduces attacker reachability. Instead of a list of 500 misconfigurations, you get a ranked list of 5 choke points that, when fixed, sever the most attack paths simultaneously. XM Cyber built their entire company around this concept; ALdeci ships it as one engine inside a unified CTEM+ platform. (Source: docs/competitive_validation_2026-04-26.md §B)
- **CSPM covers Terraform, CloudFormation, and Kubernetes YAML — with CIS benchmarks and drift analysis.** The native CSPM/IaC engine wraps Checkov and tfsec and adds ALdeci's own misconfiguration rules. Findings feed into the same 12-step Brain Pipeline as application vulnerabilities — so a public S3 bucket and an SQLi in the app that reads from it appear in the same risk context, not separate dashboards. iac_scanner_engine.py is in production. (Source: docs/CTEM_PLUS_IDENTITY.md Native Security Engines)
- **CIEM (over-permissive IAM) and toxic-combo correlation shipped.** ciem_engine.py covers AWS IAM and Azure AD/Entra over-permission detection (GAP-032/033 done). toxic_combo_rules.py implements 5 toxic combination rules with 53 passing tests — flagging the combinations of misconfigurations (e.g., public endpoint + wildcard IAM role + unrotated secret) that signal real blast radius, not individual findings in isolation. (Source: docs/competitive_validation_2026-04-26.md §A)

---

## Pain vs. Outcome

| Before ALdeci | With ALdeci |
|---|---|
| Wiz shows 800 cloud issues; Prisma shows 600 more; your CSPM and your AppSec team share no data model | ALdeci ingests Wiz, Prisma, Orca, and AWS Security Hub output — normalizes to one Universal Finding Format — then correlates cloud and app findings in the same knowledge graph |
| You know the misconfiguration exists; you do not know if any attack path actually reaches your crown jewels | Blast-radius scoring (GAP-027) and crown-jewel tagging (asset_tagging_engine) quantify how many downstream assets and users a given cloud misconfiguration puts at risk |
| Remediation means opening Jira tickets; cloud engineers argue priority with AppSec engineers for weeks | AutoFix generates IaC patches (Terraform/CloudFormation/K8s) at MEDIUM confidence for human review; choke-point ranking tells both teams which fix to prioritize first |

---

## Primary CTA

Book 30-Min Cloud Attack Path Demo

## Secondary CTA

See the CSPM + AppSec Correlation Architecture

---

## Quote Placeholder

> "[Customer logo] — '[One sentence from a cloud security engineer on how choke-point detection or toxic-combo alerts changed their remediation prioritization.]'"

---

## SEO Meta Description

ALdeci maps attack paths across AWS, GCP, and Azure with open-source CSPM engines, Edmonds-Karp choke-point detection, and CIEM — no per-cloud agent required.
