---
persona: Identity & Access (IAM) Engineer
seo_keyword: "identity risk engine privilege escalation detection PAM"
seo_meta: "ALdeci's identity_risk_engine maps privilege escalation paths, scores IAM policy drift, and integrates with Keycloak, Okta, Auth0, and Entra — continuously, not quarterly."
---

# Landing Page — IAM Engineer

## Hero Headline

Find Privilege Escalation Paths Before Attackers Do

## Sub-Hero

ALdeci's identity risk engine continuously analyzes IAM policies, detects privilege escalation chains, and integrates with Keycloak, Okta, Auth0, and Microsoft Entra — scoring identity exposure with the same rigor applied to code vulnerabilities.

---

## Three Proof Bullets

- **Identity risk scoring purpose-built for IAM engineers.** identity_risk_engine.py scores every identity, role, and permission assignment for exposure — factoring in privilege escalation potential, over-provisioning, dormant accounts, and PAM control gaps. identity_governance_engine.py tracks access certifications and SoD violations; identity_analytics_engine.py produces behavioral baselines for anomaly detection. (Source: suite-core/core/identity_risk_engine.py, identity_governance_engine.py, identity_analytics_engine.py)
- **Native adapters for Keycloak, Okta, Auth0, and Microsoft Entra.** cloud_identity_engine.py and digital_identity_engine.py provide connector-level integration with the four most common enterprise identity providers — pulling role assignments, OAuth scopes, group memberships, and conditional access policies into the Brain Pipeline for continuous posture analysis. privileged_identity_engine.py specifically targets PAM controls and just-in-time access gaps. (Source: suite-core/core/cloud_identity_engine.py, privileged_identity_engine.py)
- **Privilege escalation detection piped to the same 12-step Brain Pipeline.** iam_policy_analyzer.py identifies misconfigured IAM policies (AWS, Azure, GCP, Kubernetes RBAC) that enable privilege escalation — findings flow through the same triage, AI consensus, MPTE verification, and AutoFix workflow as application vulnerabilities. Permission Fix is a supported AutoFix type with MEDIUM confidence → PR for review. (Source: suite-core/core/iam_policy_analyzer.py, docs/CTEM_PLUS_IDENTITY.md §AutoFix Fix Types)

---

## Pain vs. Outcome

| Before ALdeci | With ALdeci |
|---|---|
| IAM posture review is a quarterly manual exercise — stale within a sprint | identity_risk_engine runs continuously; every role change and policy drift is scored immediately |
| Privilege escalation paths require specialist graph analysis tools | iam_policy_analyzer maps escalation chains and feeds them through MPTE for bounded exploit verification |
| Identity findings live in a separate system, disconnected from AppSec and CloudSec | ALdeci unifies identity risk alongside SAST, DAST, container, and CSPM findings — single risk score per application |

---

## Primary CTA

Book Identity Risk Engine Demo

## Secondary CTA

Read: How ALdeci Maps Privilege Escalation Chains

---

## Quote Placeholder

> "[Customer logo] — '[One sentence on how ALdeci surfaced an over-privileged service account that had gone undetected through three quarterly IAM reviews.]'"

---

## SEO Meta Description

ALdeci's identity_risk_engine maps privilege escalation paths, scores IAM policy drift, and integrates with Keycloak, Okta, Auth0, and Entra — continuously, not quarterly.
