# Data Processing Addendum (DPA)

**[CUSTOMIZE BEFORE COMMERCIAL USE — this is boilerplate only, not legal advice. Have a qualified attorney review, and align with your actual sub-processor list and technical measures before use in B2B contracts.]**

**Version:** 1.0
**Effective Date:** 2026-05-06

This Data Processing Addendum ("DPA") is incorporated into and forms part of the agreement ("Agreement") between [COMPANY LEGAL NAME] ("Processor") and the Customer ("Controller") for the use of the ALDECI platform.

---

## 1. Definitions

- **"Personal Data"** has the meaning given in applicable Data Protection Law.
- **"Data Protection Law"** means GDPR, UK GDPR, CCPA, and any other applicable privacy regulation.
- **"Processing"** has the meaning given in applicable Data Protection Law.
- **"Sub-processor"** means any third party engaged by Processor to process Personal Data on Controller's behalf.

## 2. Roles

The parties agree that, with respect to the processing of Personal Data under the Agreement:
- **Customer** is the Data Controller.
- **Company** is the Data Processor.

## 3. Instructions

3.1 Processor will process Personal Data only on documented instructions from Controller, including as set out in the Agreement and this DPA.

3.2 Processor will promptly inform Controller if, in its opinion, an instruction infringes Data Protection Law.

## 4. Confidentiality

Processor will ensure that personnel authorized to process Personal Data are bound by appropriate confidentiality obligations.

## 5. Security

Processor will implement and maintain appropriate technical and organizational measures to protect Personal Data, including:

| Measure | Implementation |
|---------|---------------|
| Encryption at rest | AES-256 |
| Encryption in transit | TLS 1.2+ |
| Access control | Role-based, least-privilege, MFA for admin access |
| Audit logging | All data access and configuration changes logged |
| Vulnerability management | Regular scanning, 90-day CVE remediation SLA |
| Incident response | 72-hour breach notification to Controller |
| Backup | Daily encrypted backups, 30-day retention |

## 6. Sub-processors

6.1 Controller provides general authorization for Processor to engage Sub-processors.

6.2 Processor will maintain an up-to-date list of Sub-processors at [COMPANY WEBSITE]/sub-processors.

6.3 Processor will notify Controller of any intended changes to Sub-processors at least 30 days in advance. Controller may object within 14 days; if unresolved, Controller may terminate the Agreement without penalty.

6.4 Processor will impose data protection obligations on Sub-processors equivalent to those in this DPA.

## 7. Data Subject Rights

Processor will assist Controller in responding to Data Subject requests, to the extent technically feasible, including:
- Providing data export functionality for portability requests.
- Deleting Customer Data upon verified erasure requests.
- Providing access to audit logs relevant to a Data Subject's activities.

Processor will forward any Data Subject requests it receives directly from Data Subjects to Controller without undue delay.

## 8. Data Protection Impact Assessments

Processor will provide reasonable assistance to Controller in conducting Data Protection Impact Assessments (DPIAs) and prior consultations with supervisory authorities, where required.

## 9. Deletion and Return

9.1 Upon termination of the Agreement, Processor will, at Controller's choice:
- Return all Personal Data in a standard machine-readable format (JSON or CSV), within 30 days; or
- Securely delete all Personal Data within 30 days.

9.2 Processor may retain Personal Data where required by applicable law, subject to confidentiality obligations.

## 10. Audits

10.1 Processor will provide all information reasonably necessary to demonstrate compliance with this DPA.

10.2 Processor will allow and contribute to audits conducted by Controller or a mandated auditor, provided:
- Controller gives at least 30 days' written notice.
- Audits occur no more than once per calendar year (unless a breach has occurred).
- Auditors are bound by appropriate confidentiality obligations.

10.3 As an alternative, Processor may provide a current SOC 2 Type II report or ISO 27001 certificate to satisfy audit requirements.

## 11. International Transfers

If Personal Data is transferred outside the EEA, the parties agree to rely on:
- EU Standard Contractual Clauses (Module 2: Controller to Processor), incorporated by reference; or
- Any alternative transfer mechanism approved under applicable Data Protection Law.

## 12. Liability

Each party's liability under this DPA is subject to the limitations set out in the Agreement.

## 13. Governing Law

This DPA is governed by the same law as the Agreement.

## 14. Order of Precedence

In the event of a conflict between this DPA and the Agreement, this DPA takes precedence with respect to data protection matters.

---

**[COMPANY LEGAL NAME]**
Signed: ______________________ Date: __________
Name/Title: ___________________

**[CUSTOMER LEGAL NAME]**
Signed: ______________________ Date: __________
Name/Title: ___________________
