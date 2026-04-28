# CSPM — Cloud Security Posture Management

> **Generated:** 2026-04-28T11:41:10Z
> **Endpoint count:** 1236
> **Tags:** `CSPM`, `Cloud Security`, `Network Security`, `Identity`, `Zero Trust`, `IAM`

## Overview

Endpoints covering cloud posture across AWS/Azure/GCP: resource inventory, misconfiguration detection, CIS benchmark compliance, drift detection, network security (NDR/WAF/firewall), identity & access management, zero-trust enforcement, Kubernetes security, and cryptographic key lifecycle.

## Authentication

All endpoints (unless marked **Public**) require:

```
X-API-Key: <your-api-token>
```

Tokens are managed via **Admin > API Tokens** in the UI or `POST /api/v1/auth/token`.

Some endpoints require additional OAuth2-style scopes (`read:findings`, `write:findings`, `admin:all`).
The required scope is noted in each endpoint's **Auth** field.

## Error Response Format

All error responses follow:

```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE",
  "request_id": "uuid-v4"
}
```

## Pagination

List endpoints that support pagination accept:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | 1-based page number |
| `page_size` | integer | 50 | Items per page (max 500) |
| `cursor` | string | — | Cursor token for cursor-based pagination |

Paginated responses include:

```json
{
  "items": [...],
  "total": 1234,
  "page": 1,
  "page_size": 50,
  "next_cursor": "opaque-token"
}
```

---

## Endpoints


### 1. `POST` `/api/v1/network/assets`

**Summary:** Register a network asset

**Tags:** network-security

**Auth:** API Key required

**Description:**

Register or update a network asset (subnet, VLAN, gateway, DNS server, etc.).  Assets are upserted
by ID. To update a known asset, include its ID in the request body.

**Request Body:** `RegisterAssetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Human-readable asset name |
| `asset_type` | AssetType | Yes |  | Type of network asset |
| `address` | str | Yes |  | IP address, CIDR, or descriptive address |
| `org_id` | str | No | default | Organisation ID |
| `vlan_id` | Optional | No | None | VLAN identifier |
| `description` | Optional | No | None | Asset description |
| `tags` | List | No | PydanticUndefined | Tags e.g. ['pci-cde', 'internet-facing'] |
| `metadata` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `NetworkAsset`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  |  |
| `asset_type` | AssetType | Yes |  |  |
| `name` | str | Yes |  |  |
| `address` | str | Yes |  |  |
| `vlan_id` | Optional | No | None |  |
| `description` | Optional | No | None |  |
| `tags` | List | No | PydanticUndefined |  |
| `discovered_at` | datetime | No | PydanticUndefined |  |
| `last_seen` | datetime | No | PydanticUndefined |  |
| `metadata` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 2. `GET` `/api/v1/network/assets`

**Summary:** List network assets

**Tags:** network-security

**Auth:** API Key required

**Description:**

List all registered network assets, optionally filtered by type.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `asset_type` | query | Optional | No | Filter by asset type |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 3. `GET` `/api/v1/network/topology`

**Summary:** Network topology map

**Tags:** network-security

**Auth:** API Key required

**Description:**

Build and return a topology map from registered assets.  Returns assets grouped by VLAN or asset
type, with total asset count.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 4. `POST` `/api/v1/network/segmentation/scan`

**Summary:** Run segmentation analysis

**Tags:** network-security

**Auth:** API Key required

**Description:**

Analyse registered assets for segmentation violations.  Checks PCI CDE isolation, HIPAA ePHI
separation, DMZ configuration, and flat network detection. Findings are persisted and returned.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 5. `GET` `/api/v1/network/segmentation`

**Summary:** List segmentation findings

**Tags:** network-security

**Auth:** API Key required

**Description:**

Retrieve all persisted segmentation findings for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 6. `POST` `/api/v1/network/firewall/rules`

**Summary:** Add a firewall rule

**Tags:** network-security

**Auth:** API Key required

**Description:**

Register a firewall rule for audit analysis.

**Request Body:** `AddFirewallRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | Yes |  | Descriptive rule name |
| `src` | str | Yes |  | Source CIDR or 'any' |
| `dst` | str | Yes |  | Destination CIDR or 'any' |
| `port` | str | Yes |  | Port number, range, or 'any' |
| `protocol` | str | No | tcp | Protocol: tcp, udp, or any |
| `action` | str | No | allow | allow or deny |
| `org_id` | str | No | default |  |
| `bidirectional` | bool | No | False |  |
| `expiry` | Optional | No | None | Optional expiry timestamp for temporary rules |
| `metadata` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `FirewallRule`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  |  |
| `rule_name` | str | Yes |  |  |
| `src` | str | Yes |  |  |
| `dst` | str | Yes |  |  |
| `port` | str | Yes |  |  |
| `protocol` | str | Yes |  |  |
| `action` | str | Yes |  |  |
| `bidirectional` | bool | No | False |  |
| `expiry` | Optional | No | None |  |
| `hit_count` | int | No | 0 |  |
| `created_at` | datetime | No | PydanticUndefined |  |
| `metadata` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 7. `POST` `/api/v1/network/firewall/audit`

**Summary:** Audit firewall rules

**Tags:** network-security

**Auth:** API Key required

**Description:**

Audit all registered firewall rules for: - Overly permissive (any-any-any allow) - Shadowed rules
(never evaluated) - Expired temporary rules - Unnecessary bidirectional access

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 8. `POST` `/api/v1/network/dns/analyse`

**Summary:** Analyse a DNS query for threats

**Tags:** network-security

**Auth:** API Key required

**Description:**

Analyse a DNS domain for tunneling, DGA, and unauthorized resolver threats.  Returns a list of
detected threats (empty list if none found).

**Request Body:** `AnalyseDNSRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  | DNS domain to analyse |
| `resolver_ip` | Optional | No | None | IP of the DNS resolver used |
| `query_size_bytes` | int | No | 0 | Size of the DNS query payload in bytes |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 9. `POST` `/api/v1/network/dns/rebinding`

**Summary:** Report a DNS rebinding attempt

**Tags:** network-security

**Auth:** API Key required

**Description:**

Report a DNS rebinding event: a public domain resolved to a private IP.  Returns the threat record
if the resolved IP is private, null otherwise.

**Request Body:** `ReportDNSRebindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  | Public domain that was resolved |
| `resolved_ip` | str | Yes |  | IP address the domain resolved to |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `Optional`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 10. `GET` `/api/v1/network/dns/threats`

**Summary:** List DNS threats

**Tags:** network-security

**Auth:** API Key required

**Description:**

Retrieve all persisted DNS threat records for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 11. `POST` `/api/v1/network/tls/certificates`

**Summary:** Register a TLS certificate

**Tags:** network-security

**Auth:** API Key required

**Description:**

Register a TLS certificate observed in the environment.  Issues (expiry, weak ciphers, deprecated
protocols, missing CT) are automatically detected and persisted.

**Request Body:** `RegisterCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | str | Yes |  | Hostname |
| `port` | int | No | 443 | TLS port |
| `subject_cn` | str | Yes |  | Certificate CN |
| `issuer` | str | Yes |  | Certificate issuer |
| `not_before` | datetime | Yes |  | Certificate validity start |
| `not_after` | datetime | Yes |  | Certificate expiry |
| `protocol_version` | str | No | TLSv1.3 | TLS protocol version negotiated |
| `cipher_suite` | str | No |  | Cipher suite in use |
| `ct_logged` | bool | No | True | Whether cert appears in CT logs |
| `san_domains` | List | No | PydanticUndefined | SAN domain list |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `TLSCertificate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  |  |
| `host` | str | Yes |  |  |
| `port` | int | No | 443 |  |
| `subject_cn` | str | Yes |  |  |
| `issuer` | str | Yes |  |  |
| `not_before` | datetime | Yes |  |  |
| `not_after` | datetime | Yes |  |  |
| `protocol_version` | str | No | TLSv1.3 |  |
| `cipher_suite` | str | No |  |  |
| `ct_logged` | bool | No | True |  |
| `san_domains` | List | No | PydanticUndefined |  |
| `observed_at` | datetime | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 12. `GET` `/api/v1/network/tls/certificates`

**Summary:** List TLS certificates

**Tags:** network-security

**Auth:** API Key required

**Description:**

Return all registered TLS certificates for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 13. `GET` `/api/v1/network/tls/issues`

**Summary:** List TLS issues

**Tags:** network-security

**Auth:** API Key required

**Description:**

Return all detected TLS/SSL issues for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 14. `POST` `/api/v1/network/flows`

**Summary:** Record a network flow

**Tags:** network-security

**Auth:** API Key required

**Description:**

Persist a network flow observation for baseline and anomaly analysis.

**Request Body:** `RecordFlowRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `src_ip` | str | Yes |  | Source IP address |
| `dst_ip` | str | Yes |  | Destination IP address |
| `src_port` | int | Yes |  | Source port |
| `dst_port` | int | Yes |  | Destination port |
| `protocol` | str | No | tcp | Protocol: tcp or udp |
| `bytes_sent` | int | No | 0 | Bytes from source to destination |
| `bytes_recv` | int | No | 0 | Bytes from destination to source |
| `packet_count` | int | No | 0 |  |
| `duration_ms` | int | No | 0 |  |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `NetworkFlow`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  |  |
| `src_ip` | str | Yes |  |  |
| `dst_ip` | str | Yes |  |  |
| `src_port` | int | Yes |  |  |
| `dst_port` | int | Yes |  |  |
| `protocol` | str | Yes |  |  |
| `bytes_sent` | int | No | 0 |  |
| `bytes_recv` | int | No | 0 |  |
| `packet_count` | int | No | 0 |  |
| `duration_ms` | int | No | 0 |  |
| `observed_at` | datetime | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 15. `POST` `/api/v1/network/flows/analyse`

**Summary:** Analyse network flows for anomalies

**Tags:** network-security

**Auth:** API Key required

**Description:**

Analyse network flows recorded in the look-back window for: - Unusual traffic volume (> 3x baseline
for a src/dst pair) - Beaconing (regular periodic connections) - Lateral movement (host connecting
to many internal targets) - Data exfiltration (large internal-to-external transfer)

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `window_hours` | query | int | No | Look-back window in hours |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 16. `GET` `/api/v1/network/flows/anomalies`

**Summary:** List flow anomalies

**Tags:** network-security

**Auth:** API Key required

**Description:**

Return all persisted network flow anomalies for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 17. `POST` `/api/v1/network/zerotrust/score`

**Summary:** Compute Zero Trust score for a segment

**Tags:** network-security

**Auth:** API Key required

**Description:**

Score Zero Trust implementation for a network segment across five dimensions: Device Posture, User
Identity, Network Context, Application, and Data.  Returns an overall score (0–100) with letter
grade and per-dimension breakdown.

**Request Body:** `ZeroTrustScoreRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `segment` | str | Yes |  | Network segment name to score |
| `org_id` | str | No | default |  |
| `device_posture_score` | float | No | 1.0 | Device posture ratio 0–1 |
| `identity_verified` | bool | No | True | All users authenticated via IdP |
| `mfa_enabled` | bool | No | True | MFA enforced for all users |
| `network_microsegmented` | bool | No | True | Micro-segmentation implemented |
| `app_least_privilege` | bool | No | True | App-level least privilege enforced |
| `data_classified` | bool | No | True | Data classification implemented |

**Responses:**

**200 OK** — `ZeroTrustScore`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  |  |
| `segment` | str | Yes |  |  |
| `overall_score` | float | Yes |  |  |
| `grade` | str | Yes |  |  |
| `dimensions` | List | No | PydanticUndefined |  |
| `recommendations` | List | No | PydanticUndefined |  |
| `computed_at` | datetime | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 18. `GET` `/api/v1/network/zerotrust/scores`

**Summary:** List Zero Trust scores

**Tags:** network-security

**Auth:** API Key required

**Description:**

Return all computed Zero Trust scores for the org, newest first.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 19. `GET` `/api/v1/network/summary`

**Summary:** NDR health summary

**Tags:** network-security

**Auth:** API Key required

**Description:**

Return a high-level NDR health summary: asset count, segmentation violations, firewall issue count,
DNS threats, TLS issues, flow anomalies, and latest Zero Trust score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `NDRSummary`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `total_assets` | int | Yes |  |  |
| `segmentation_violations` | int | Yes |  |  |
| `firewall_issues` | int | Yes |  |  |
| `dns_threats` | int | Yes |  |  |
| `tls_issues` | int | Yes |  |  |
| `flow_anomalies` | int | Yes |  |  |
| `zero_trust_score` | Optional | Yes |  |  |
| `computed_at` | datetime | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 20. `POST` `/api/v1/cloud/discover/aws`

**Summary:** Discover AWS assets

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Enumerate AWS resources and store them in the inventory.

**Request Body:** `DiscoverRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `DiscoverResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `discovered` | int | Yes |  |  |
| `assets` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 21. `POST` `/api/v1/cloud/discover/azure`

**Summary:** Discover Azure assets

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Enumerate Azure resources and store them in the inventory.

**Request Body:** `DiscoverRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `DiscoverResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `discovered` | int | Yes |  |  |
| `assets` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 22. `POST` `/api/v1/cloud/discover/gcp`

**Summary:** Discover GCP assets

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Enumerate GCP resources and store them in the inventory.

**Request Body:** `DiscoverRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `DiscoverResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `discovered` | int | Yes |  |  |
| `assets` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 23. `POST` `/api/v1/cloud/discover/all`

**Summary:** Discover assets across all cloud providers

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Trigger discovery across AWS, Azure, and GCP simultaneously.

**Request Body:** `DiscoverRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 24. `GET` `/api/v1/cloud/inventory`

**Summary:** Get full cloud asset inventory

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return full asset inventory with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `provider` | query | Optional | No | Filter by provider: aws \| azure \| gcp |
| `asset_type` | query | Optional | No | Filter by asset type |
| `region` | query | Optional | No | Filter by region |
| `account_id` | query | Optional | No | Filter by account/subscription/project ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 25. `GET` `/api/v1/cloud/assets/unmanaged`

**Summary:** Get unmanaged (shadow IT) assets

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return assets not present in the CMDB.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 26. `GET` `/api/v1/cloud/assets/public`

**Summary:** Get internet-exposed assets

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return assets with a public IP address.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 27. `GET` `/api/v1/cloud/assets/drift`

**Summary:** Get asset drift

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return new and removed assets within the lookback window.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `days` | query | int | No | Lookback window in days |

**Responses:**

**200 OK** — `DriftResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `lookback_days` | int | Yes |  |  |
| `new_count` | int | Yes |  |  |
| `removed_count` | int | Yes |  |  |
| `new_assets` | List | Yes |  |  |
| `removed_assets` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 28. `GET` `/api/v1/cloud/stats`

**Summary:** Get discovery statistics

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregated discovery stats by provider, asset type, and region.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 29. `POST` `/api/v1/cloud/cmdb/register`

**Summary:** Register asset as managed in CMDB

**Tags:** cloud-discovery

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a cloud resource as known/managed so it no longer appears as unmanaged.

**Request Body:** `RegisterCMDBRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  | Cloud resource ID to mark as managed |
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 30. `GET` `/api/v1/scan/aws-security-hub/status`

**Summary:** Check AWS Security Hub configuration

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Return whether AWS credentials are configured.  When unconfigured all endpoints return mock data so
the pipeline can be exercised without real AWS credentials.

**Responses:**

**200 OK** — `AWSStatusResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `configured` | bool | Yes |  |  |
| `region` | str | Yes |  |  |
| `message` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 31. `GET` `/api/v1/scan/aws-security-hub/findings`

**Summary:** Pull raw ASFF findings from Security Hub

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.  Supports optional filtering
by severity and workflow status. Returns mock data when AWS credentials are not configured.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `severity` | query | Optional | No | Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| `workflow_status` | query | Optional | No | Filter by workflow status: NEW, NOTIFIED, RESOLVED, SUPPRESSED |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 32. `GET` `/api/v1/scan/aws-security-hub/insights`

**Summary:** Get Security Hub insights

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Retrieve Security Hub insights.  Returns mock data when AWS credentials are not configured.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 33. `GET` `/api/v1/scan/aws-security-hub/standards`

**Summary:** Get enabled compliance standards status

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their pass/fail control counts.
Returns mock data when AWS credentials are not configured.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 34. `POST` `/api/v1/scan/aws-security-hub/import`

**Summary:** Import Security Hub findings into ALDECI

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Pull findings from AWS Security Hub, normalize from ASFF to UnifiedFinding format, store in history,
and ingest into the Brain Pipeline.  Returns mock data when AWS credentials are not configured.

**Request Body:** `ImportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `ImportResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `import_id` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `started_at` | str | Yes |  |  |
| `completed_at` | str | Yes |  |  |
| `status` | str | Yes |  |  |
| `is_mock` | bool | Yes |  |  |
| `findings_count` | int | Yes |  |  |
| `severity_breakdown` | Dict | Yes |  |  |
| `findings` | List | Yes |  |  |
| `error` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 35. `GET` `/api/v1/scan/aws-security-hub/history`

**Summary:** List Security Hub import history

**Tags:** aws-security-hub

**Auth:** API Key required

**Description:**

Return the import history for the given organisation, most recent first.  Findings are omitted from
the summary; re-run an import to get full results.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 36. `GET` `/api/v1/scan/azure-defender/status`

**Summary:** Check Azure Defender configuration

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Return whether Azure credentials are configured.  When unconfigured all endpoints return mock data
so the pipeline can be exercised without real Azure credentials.

**Responses:**

**200 OK** — `AzureStatusResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `configured` | bool | Yes |  |  |
| `subscription_id` | str | Yes |  |  |
| `message` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 37. `GET` `/api/v1/scan/azure-defender/alerts`

**Summary:** Pull security alerts from Microsoft Defender for Cloud

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Pull security alerts from Microsoft Defender for Cloud.  Supports optional filtering by severity.
Returns mock data when Azure credentials are not configured.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `severity` | query | Optional | No | Filter by severity: Critical, High, Medium, Low |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 38. `GET` `/api/v1/scan/azure-defender/secure-score`

**Summary:** Get Azure Secure Score

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Retrieve the Azure Secure Score for the configured subscription.  Returns mock data when Azure
credentials are not configured.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 39. `GET` `/api/v1/scan/azure-defender/recommendations`

**Summary:** Get security recommendations from Microsoft Defender for Cloud

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Retrieve security recommendations from Microsoft Defender for Cloud.  Supports optional filtering by
category. Returns mock data when Azure credentials are not configured.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `category` | query | Optional | No | Filter by category: IdentityAndAccess, Compute, Data, Networking |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 40. `POST` `/api/v1/scan/azure-defender/import`

**Summary:** Import Azure Defender findings into ALDECI

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Pull alerts from Microsoft Defender for Cloud, normalize to UnifiedFinding format, store in history,
and ingest into the Brain Pipeline.  Returns mock data when Azure credentials are not configured.

**Request Body:** `ImportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `ImportResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `import_id` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `started_at` | str | Yes |  |  |
| `completed_at` | str | Yes |  |  |
| `status` | str | Yes |  |  |
| `is_mock` | bool | Yes |  |  |
| `findings_count` | int | Yes |  |  |
| `severity_breakdown` | Dict | Yes |  |  |
| `findings` | List | Yes |  |  |
| `error` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 41. `GET` `/api/v1/scan/azure-defender/history`

**Summary:** List Azure Defender import history

**Tags:** azure-defender

**Auth:** API Key required

**Description:**

Return the import history for the given organisation, most recent first.  Findings are omitted from
the summary; re-run an import to get full results.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 42. `POST` `/api/v1/agentless-snapshot/enqueue`

**Summary:** POST /api/v1/agentless-snapshot/enqueue

**Tags:** Agentless Snapshot Scan

**Auth:** API Key required

**Description:**

Discover snapshots for (provider, account_id) and queue them.

**Request Body:** `EnqueueRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `provider` | str | Yes |  |  |
| `account_id` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 43. `POST` `/api/v1/agentless-snapshot/{snapshot_db_id}/scan`

**Summary:** POST /api/v1/agentless-snapshot/{snapshot_db_id}/scan

**Tags:** Agentless Snapshot Scan

**Auth:** API Key required

**Description:**

Synchronously execute a scan for the given snapshot row.  For v0 this is synchronous so demos and
curl flows are deterministic. A production build would hand this off to a background worker and
return a job id immediately.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `snapshot_db_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 44. `GET` `/api/v1/agentless-snapshot/snapshots`

**Summary:** GET /api/v1/agentless-snapshot/snapshots

**Tags:** Agentless Snapshot Scan

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `scan_status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 45. `GET` `/api/v1/agentless-snapshot/findings`

**Summary:** GET /api/v1/agentless-snapshot/findings

**Tags:** Agentless Snapshot Scan

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `severity` | query | Optional | No | None |
| `min_severity` | query | Optional | No | None |
| `finding_type` | query | Optional | No | None |
| `snapshot_db_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 46. `GET` `/api/v1/agentless-snapshot/stats`

**Summary:** GET /api/v1/agentless-snapshot/stats

**Tags:** Agentless Snapshot Scan

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 47. `POST` `/api/v1/certificates/`

**Summary:** Add certificate to inventory

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AddCertRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `domain` | str | Yes |  | Primary domain |
| `issuer` | str | No |  | Certificate issuer CN/O |
| `serial` | str | No |  | Serial number |
| `not_before` | str | No |  | Validity start (ISO-8601) |
| `not_after` | str | No |  | Validity end (ISO-8601) |
| `algorithm` | str | No |  | Signature algorithm (e.g. sha256WithRSAEncryption) |
| `key_size` | int | No | 0 | Public key size in bits |
| `san_list` | List | No | PydanticUndefined | Subject Alternative Names |
| `wildcard` | bool | No | False | Wildcard certificate flag |

**Responses:**

**200 OK** — `AddCertResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cert_id` | str | Yes |  |  |
| `message` | str | No | Certificate added |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 48. `GET` `/api/v1/certificates/`

**Summary:** List certificates

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `expired_only` | query | bool | No | False |
| `expiring_days` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 49. `GET` `/api/v1/certificates/alerts/expiry`

**Summary:** Get expiry alert groups

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 50. `GET` `/api/v1/certificates/weak`

**Summary:** List weak certificates

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 51. `GET` `/api/v1/certificates/stats`

**Summary:** Certificate statistics

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 52. `POST` `/api/v1/certificates/check`

**Summary:** Live-probe a domain TLS cert

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CheckDomainRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  | Domain to probe |
| `port` | int | No | 443 | TLS port (default 443) |
| `timeout` | int | No | 5 | Socket timeout in seconds |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 53. `GET` `/api/v1/certificates/{cert_id}`

**Summary:** Get a certificate by ID

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 54. `PUT` `/api/v1/certificates/{cert_id}`

**Summary:** Update certificate fields

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdateCertRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | Optional | No | None |  |
| `issuer` | Optional | No | None |  |
| `serial` | Optional | No | None |  |
| `not_before` | Optional | No | None |  |
| `not_after` | Optional | No | None |  |
| `algorithm` | Optional | No | None |  |
| `key_size` | Optional | No | None |  |
| `san_list` | Optional | No | None |  |
| `wildcard` | Optional | No | None |  |
| `self_signed` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 55. `DELETE` `/api/v1/certificates/{cert_id}`

**Summary:** Delete a certificate

**Tags:** certificates

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `DeleteResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `deleted` | bool | Yes |  |  |
| `message` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 56. `POST` `/api/v1/firewall/firewalls`

**Summary:** Add a firewall

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AddFirewallRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `name` | str | Yes |  | Friendly name for the firewall |
| `vendor` | str | No | unknown | Vendor: palo_alto/cisco/fortinet/checkpoint/aws_sg/azure_nsg |
| `ip_address` | str | No |  | Management IP address |
| `status` | str | No | active | active or inactive |
| `rule_count` | int | No | 0 | Known rule count (metadata only) |
| `last_audited` | Optional | No | None | ISO-8601 timestamp of last audit |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 57. `GET` `/api/v1/firewall/firewalls`

**Summary:** List firewalls

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 58. `GET` `/api/v1/firewall/firewalls/{firewall_id}`

**Summary:** Get a firewall

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 59. `POST` `/api/v1/firewall/firewalls/{firewall_id}/analyze`

**Summary:** Analyze all rules for a firewall

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 60. `GET` `/api/v1/firewall/rules`

**Summary:** List firewall rules

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `firewall_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 61. `POST` `/api/v1/firewall/rules`

**Summary:** Add a firewall rule

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AddRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `firewall_id` | str | Yes |  | Parent firewall ID |
| `rule_number` | int | No | 0 | Rule sequence number (lower = higher priority) |
| `src_zone` | str | No |  | Source security zone |
| `dst_zone` | str | No |  | Destination security zone |
| `src_ip` | str | No | any | Source IP / CIDR / 'any' |
| `dst_ip` | str | No | any | Destination IP / CIDR / 'any' |
| `port` | str | No | any | Port or range, e.g. '443', '1024-65535', 'any' |
| `protocol` | str | No | any | Protocol: tcp/udp/icmp/any |
| `action` | str | No | allow | allow / deny / drop |
| `enabled` | bool | No | True | Whether the rule is active |
| `hit_count` | int | No | 0 | Hit counter (imported from device) |
| `last_hit` | Optional | No | None | ISO-8601 timestamp of last match |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 62. `GET` `/api/v1/firewall/findings`

**Summary:** List rule findings

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `firewall_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 63. `POST` `/api/v1/firewall/findings`

**Summary:** Create a finding manually

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `firewall_id` | str | Yes |  | Associated firewall ID |
| `rule_id` | Optional | No | None | Associated rule ID |
| `finding_type` | str | Yes |  | Type label, e.g. overly_permissive |
| `severity` | str | No | medium | critical/high/medium/low/info |
| `description` | str | No |  | Human-readable description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 64. `POST` `/api/v1/firewall/findings/{finding_id}/resolve`

**Summary:** Resolve a finding

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 65. `GET` `/api/v1/firewall/stats`

**Summary:** Firewall aggregate statistics

**Tags:** firewall

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 66. `GET` `/api/v1/pam/accounts`

**Summary:** GET /api/v1/pam/accounts

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List privileged accounts for the current org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_type` | query | Optional | No | Filter by account type |
| `account_status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 67. `POST` `/api/v1/pam/accounts`

**Summary:** POST /api/v1/pam/accounts

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a privileged account in the PAM vault.

**Request Body:** `RegisterAccountRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | str | Yes |  |  |
| `account_type` | str | No | admin | One of: service, admin, root, sa, shared, emergency |
| `system` | str | No |  |  |
| `department` | str | No |  |  |
| `owner` | str | No |  |  |
| `is_vaulted` | bool | No | False |  |
| `rotation_days` | int | No | 90 |  |
| `last_rotated` | Optional | No | None |  |
| `risk_score` | int | No | 50 |  |
| `status` | str | No | active |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 68. `GET` `/api/v1/pam/sessions`

**Summary:** GET /api/v1/pam/sessions

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List PAM sessions for the current org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `approval_status` | query | Optional | No | Filter by approval status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 69. `POST` `/api/v1/pam/sessions`

**Summary:** POST /api/v1/pam/sessions

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a PAM session request (requires approval unless policy allows).

**Request Body:** `CreateSessionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `requester` | str | No |  |  |
| `justification` | str | No |  |  |
| `session_type` | str | No | interactive | One of: interactive, api, scheduled |
| `target_system` | str | No |  |  |
| `requested_duration_minutes` | int | No | 60 |  |
| `started_at` | Optional | No | None |  |
| `recording_enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 70. `POST` `/api/v1/pam/sessions/{session_id}/approve`

**Summary:** POST /api/v1/pam/sessions/{session_id}/approve

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Approve or deny a pending PAM session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |

**Request Body:** `ApproveSessionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  |  |
| `approved` | bool | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 71. `POST` `/api/v1/pam/sessions/{session_id}/end`

**Summary:** POST /api/v1/pam/sessions/{session_id}/end

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

End an active PAM session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 72. `GET` `/api/v1/pam/policies`

**Summary:** GET /api/v1/pam/policies

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List PAM policies for the current org.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 73. `POST` `/api/v1/pam/policies`

**Summary:** POST /api/v1/pam/policies

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a new PAM policy.

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `require_approval` | bool | No | True |  |
| `max_session_minutes` | int | No | 60 |  |
| `allowed_hours` | List | No | PydanticUndefined |  |
| `mfa_required` | bool | No | True |  |
| `recording_required` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 74. `GET` `/api/v1/pam/stats`

**Summary:** GET /api/v1/pam/stats

**Tags:** pam

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return PAM summary statistics for the current org.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 75. `POST` `/api/v1/posture-score/compute`

**Summary:** Compute security posture score

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Calculate weighted posture score from current component values.

**Request Body:** `ComputeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `save` | bool | No | True | Persist score after computing |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 76. `GET` `/api/v1/posture-score/current`

**Summary:** Get current posture score

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the most recently saved posture score for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 77. `GET` `/api/v1/posture-score/history`

**Summary:** Get score history

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return posture score snapshots for the last N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `days` | query | int | No | 30 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 78. `POST` `/api/v1/posture-score/components/{name}`

**Summary:** Update a component score

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Upsert a single security domain component score (0-100).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `name` | path | str | Yes | — |

**Request Body:** `ComponentUpdateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `score` | int | Yes |  |  |
| `source` | str | No | manual |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 79. `GET` `/api/v1/posture-score/components`

**Summary:** List component scores

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List all component scores and weights for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 80. `GET` `/api/v1/posture-score/benchmarks`

**Summary:** List benchmarks

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List industry benchmarks for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 81. `POST` `/api/v1/posture-score/benchmarks`

**Summary:** Add a benchmark

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add an industry benchmark record for comparison.

**Request Body:** `BenchmarkRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `industry` | str | No |  | Industry sector |
| `company_size` | str | No |  | e.g. small / medium / large / enterprise |
| `avg_score` | float | No | 0.0 |  |
| `percentile_rank` | int | No | 50 |  |
| `source` | str | No |  | Benchmark source (e.g. CIS, Gartner) |
| `as_of_date` | str | No |  | ISO-8601 date |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 82. `GET` `/api/v1/posture-score/stats`

**Summary:** Get posture stats

**Tags:** posture-score

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return summary statistics: current score, grade, 30d trend, days at risk.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 83. `POST` `/api/v1/cwp/workloads`

**Summary:** POST /api/v1/cwp/workloads

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `WorkloadCreateReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `workload_name` | str | Yes |  |  |
| `workload_type` | str | No | vm |  |
| `cloud_provider` | str | No | aws |  |
| `region` | Optional | No | None |  |
| `account_id` | Optional | No | None |  |
| `risk_score` | float | No | 50.0 |  |
| `risk_level` | str | No | medium |  |
| `last_assessed` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 84. `GET` `/api/v1/cwp/workloads`

**Summary:** GET /api/v1/cwp/workloads

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `workload_type` | query | Optional | No | None |
| `cloud_provider` | query | Optional | No | None |
| `risk_level` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 85. `GET` `/api/v1/cwp/workloads/{workload_id}`

**Summary:** GET /api/v1/cwp/workloads/{workload_id}

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 86. `PUT` `/api/v1/cwp/workloads/{workload_id}/protection`

**Summary:** PUT /api/v1/cwp/workloads/{workload_id}/protection

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |

**Request Body:** `WorkloadProtectionReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `protection_status` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 87. `POST` `/api/v1/cwp/threats`

**Summary:** POST /api/v1/cwp/threats

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `ThreatCreateReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `workload_id` | str | Yes |  |  |
| `threat_type` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `detection_source` | str | No | runtime |  |
| `detected_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 88. `GET` `/api/v1/cwp/threats`

**Summary:** GET /api/v1/cwp/threats

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `workload_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 89. `PUT` `/api/v1/cwp/threats/{threat_id}/status`

**Summary:** PUT /api/v1/cwp/threats/{threat_id}/status

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |

**Request Body:** `ThreatStatusReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `status` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 90. `POST` `/api/v1/cwp/policies`

**Summary:** POST /api/v1/cwp/policies

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `PolicyCreateReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `policy_name` | str | Yes |  |  |
| `workload_types` | List | No | PydanticUndefined |  |
| `controls` | List | No | PydanticUndefined |  |
| `enforcement` | str | No | alert |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 91. `GET` `/api/v1/cwp/policies`

**Summary:** GET /api/v1/cwp/policies

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 92. `GET` `/api/v1/cwp/stats`

**Summary:** GET /api/v1/cwp/stats

**Tags:** Cloud Workload Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 93. `GET` `/api/v1/zero-trust/policies`

**Summary:** GET /api/v1/zero-trust/policies

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List Zero Trust policies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `resource_type` | query | Optional | No | None |
| `enabled` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 94. `POST` `/api/v1/zero-trust/policies`

**Summary:** POST /api/v1/zero-trust/policies

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a new Zero Trust access policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  | Human-readable policy name |
| `resource_type` | str | No | application | application \| api \| database \| network_segment \| cloud_service |
| `action` | str | Yes |  | allow \| deny \| mfa_required \| device_check_required |
| `principal_type` | str | No | user | user \| group \| service_account \| device |
| `conditions` | Dict | No | PydanticUndefined | Conditions: min_trust_score, require_mfa, allowed_locations, allowed_device_types, time_restrictions |
| `priority` | int | No | 50 | 1=highest, 100=lowest |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 95. `GET` `/api/v1/zero-trust/policies/{policy_id}`

**Summary:** GET /api/v1/zero-trust/policies/{policy_id}

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single Zero Trust policy by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 96. `PATCH` `/api/v1/zero-trust/policies/{policy_id}`

**Summary:** PATCH /api/v1/zero-trust/policies/{policy_id}

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Update a Zero Trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | Optional | No | None |  |
| `resource_type` | Optional | No | None |  |
| `action` | Optional | No | None |  |
| `principal_type` | Optional | No | None |  |
| `conditions` | Optional | No | None |  |
| `priority` | Optional | No | None |  |
| `enabled` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 97. `DELETE` `/api/v1/zero-trust/policies/{policy_id}`

**Summary:** DELETE /api/v1/zero-trust/policies/{policy_id}

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Delete a Zero Trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 98. `POST` `/api/v1/zero-trust/evaluate`

**Summary:** POST /api/v1/zero-trust/evaluate

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Evaluate an access request against all active Zero Trust policies.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `EvaluateAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `principal_id` | str | Yes |  |  |
| `principal_type` | str | No | user |  |
| `resource_id` | str | Yes |  |  |
| `resource_type` | str | No | application |  |
| `action_requested` | str | No | read |  |
| `source_ip` | str | No |  |  |
| `device_trust_score` | float | No | 50.0 |  |
| `user_trust_score` | float | No | 50.0 |  |
| `mfa_verified` | bool | No | False |  |
| `location` | str | No |  |  |
| `device_type` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 99. `GET` `/api/v1/zero-trust/trust-scores`

**Summary:** GET /api/v1/zero-trust/trust-scores

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List trust scores with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `entity_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 100. `POST` `/api/v1/zero-trust/trust-scores`

**Summary:** POST /api/v1/zero-trust/trust-scores

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create or update a trust score for an entity.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `SetTrustScoreRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `entity_id` | str | Yes |  |  |
| `entity_type` | str | No | user | user \| device \| service |
| `trust_score` | float | Yes |  |  |
| `score_factors` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 101. `GET` `/api/v1/zero-trust/trust-scores/{entity_id}`

**Summary:** GET /api/v1/zero-trust/trust-scores/{entity_id}

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get trust score for a specific entity.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 102. `GET` `/api/v1/zero-trust/sessions`

**Summary:** GET /api/v1/zero-trust/sessions

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List Zero Trust sessions with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `principal_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 103. `POST` `/api/v1/zero-trust/sessions`

**Summary:** POST /api/v1/zero-trust/sessions

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a new Zero Trust session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateSessionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `principal_id` | str | Yes |  |  |
| `resource_id` | str | Yes |  |  |
| `duration_hours` | int | No | 8 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 104. `POST` `/api/v1/zero-trust/sessions/{session_id}/revoke`

**Summary:** POST /api/v1/zero-trust/sessions/{session_id}/revoke

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Revoke an active session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 105. `GET` `/api/v1/zero-trust/access-log`

**Summary:** GET /api/v1/zero-trust/access-log

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Query the Zero Trust access evaluation log.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `decision` | query | Optional | No | None |
| `resource_type` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 106. `GET` `/api/v1/zero-trust/stats`

**Summary:** GET /api/v1/zero-trust/stats

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return Zero Trust stats: request rates, active sessions, trust scores.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 107. `GET` `/api/v1/zero-trust/compliance`

**Summary:** GET /api/v1/zero-trust/compliance

**Tags:** Zero Trust Enforcement

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return Zero Trust maturity score, pillar breakdown, and recommendations.  Scores each ZT pillar
(identity, device, network, application, data) based on active policy coverage and entity trust
health. Aligned with NIST SP 800-207.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 108. `GET` `/api/v1/zero-trust-policy/policies`

**Summary:** GET /api/v1/zero-trust-policy/policies

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List Zero Trust policies for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `policy_type` | query | Optional | No | None |
| `enabled` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 109. `POST` `/api/v1/zero-trust-policy/policies`

**Summary:** POST /api/v1/zero-trust-policy/policies

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a Zero Trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Human-readable policy name |
| `description` | str | No |  | Optional description |
| `policy_type` | str | No | network | network \| identity \| device \| application |
| `action` | str | No | deny | allow \| deny \| mfa_required |
| `source_conditions` | Dict | No | PydanticUndefined | Source-side match conditions (user, device, source_ip) |
| `destination_conditions` | Dict | No | PydanticUndefined | Destination-side match conditions (resource, destination) |
| `priority` | int | No | 50 | Lower = higher priority |
| `enabled` | bool | No | True | Whether this policy is active |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 110. `GET` `/api/v1/zero-trust-policy/policies/{policy_id}`

**Summary:** GET /api/v1/zero-trust-policy/policies/{policy_id}

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single Zero Trust policy by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 111. `PUT` `/api/v1/zero-trust-policy/policies/{policy_id}`

**Summary:** PUT /api/v1/zero-trust-policy/policies/{policy_id}

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Update a Zero Trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | Optional | No | None |  |
| `description` | Optional | No | None |  |
| `policy_type` | Optional | No | None |  |
| `action` | Optional | No | None |  |
| `source_conditions` | Optional | No | None |  |
| `destination_conditions` | Optional | No | None |  |
| `priority` | Optional | No | None |  |
| `enabled` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 112. `DELETE` `/api/v1/zero-trust-policy/policies/{policy_id}`

**Summary:** DELETE /api/v1/zero-trust-policy/policies/{policy_id}

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Delete a Zero Trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 113. `POST` `/api/v1/zero-trust-policy/evaluate`

**Summary:** POST /api/v1/zero-trust-policy/evaluate

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Evaluate an access request against active Zero Trust policies.

**Request Body:** `EvaluateAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user` | str | No |  | User identifier |
| `device` | str | No |  | Device identifier |
| `source_ip` | str | No |  | Source IP address |
| `destination` | str | No |  | Destination resource or host |
| `resource` | str | No |  | Resource being accessed |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 114. `GET` `/api/v1/zero-trust-policy/access-events`

**Summary:** GET /api/v1/zero-trust-policy/access-events

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List access events for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `decision` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 115. `POST` `/api/v1/zero-trust-policy/access-events`

**Summary:** POST /api/v1/zero-trust-policy/access-events

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record an access event manually.

**Request Body:** `RecordAccessEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user` | str | No |  | User identifier |
| `device` | str | No |  | Device identifier |
| `resource` | str | No |  | Resource accessed |
| `decision` | str | No | allow | allow \| deny \| mfa_required |
| `policy_id` | Optional | No | None | Policy that matched |
| `source_ip` | str | No |  | Source IP address |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 116. `GET` `/api/v1/zero-trust-policy/stats`

**Summary:** GET /api/v1/zero-trust-policy/stats

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return policy and access event statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 117. `GET` `/api/v1/zero-trust-policy/compliance`

**Summary:** GET /api/v1/zero-trust-policy/compliance

**Tags:** zero-trust-policy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return Zero Trust maturity score, pillar breakdown, and recommendations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 118. `POST` `/api/v1/cloud-security-engine/accounts`

**Summary:** Register a cloud account

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AccountIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `account_name` | str | No |  |  |
| `provider` | str | No | aws |  |
| `region` | str | No |  |  |
| `status` | str | No | healthy |  |
| `resource_count` | int | No | 0 |  |
| `finding_count` | int | No | 0 |  |
| `risk_score` | float | No | 0.0 |  |
| `last_scanned` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 119. `GET` `/api/v1/cloud-security-engine/accounts`

**Summary:** List cloud accounts

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `provider` | query | Optional | No | Filter by provider |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 120. `POST` `/api/v1/cloud-security-engine/findings`

**Summary:** Create a cloud security finding

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `FindingIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `resource_id` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `region` | str | No |  |  |
| `severity` | str | No | medium |  |
| `category` | str | No | compliance |  |
| `title` | str | No |  |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |
| `status` | str | No | open |  |
| `cis_control` | str | No |  |  |
| `compliance_frameworks` | List | No | PydanticUndefined |  |
| `risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 121. `GET` `/api/v1/cloud-security-engine/findings`

**Summary:** List cloud security findings

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `account_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `category` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 122. `PATCH` `/api/v1/cloud-security-engine/findings/{finding_id}/resolve`

**Summary:** Resolve a cloud finding

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 123. `POST` `/api/v1/cloud-security-engine/resources`

**Summary:** Register a cloud resource

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `ResourceIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `resource_id` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `region` | str | No |  |  |
| `tags` | Dict | No | PydanticUndefined |  |
| `security_score` | float | No | 100.0 |  |
| `finding_count` | int | No | 0 |  |
| `is_public` | bool | No | False |  |
| `is_encrypted` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 124. `GET` `/api/v1/cloud-security-engine/resources`

**Summary:** List cloud resources

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `account_id` | query | Optional | No | None |
| `is_public` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 125. `POST` `/api/v1/cloud-security-engine/benchmarks`

**Summary:** Save a benchmark run result

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `BenchmarkIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `benchmark` | str | No | cis_aws_v1.5 |  |
| `pass_count` | int | No | 0 |  |
| `fail_count` | int | No | 0 |  |
| `score` | Optional | No | None |  |
| `last_run` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 126. `GET` `/api/v1/cloud-security-engine/benchmarks`

**Summary:** List benchmark results

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `account_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 127. `GET` `/api/v1/cloud-security-engine/stats`

**Summary:** Get cloud security stats for org

**Tags:** cloud-security-engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 128. `POST` `/api/v1/network-traffic/flows`

**Summary:** Record a network flow

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `FlowIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `src_ip` | str | No |  |  |
| `src_port` | int | No | 0 |  |
| `dst_ip` | str | No |  |  |
| `dst_port` | int | No | 0 |  |
| `protocol` | str | No | tcp |  |
| `bytes_sent` | int | No | 0 |  |
| `bytes_received` | int | No | 0 |  |
| `packets` | int | No | 0 |  |
| `duration_ms` | int | No | 0 |  |
| `direction` | str | No | outbound |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 129. `GET` `/api/v1/network-traffic/flows`

**Summary:** List network flows

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `flagged` | query | Optional | No | None |
| `anomaly_type` | query | Optional | No | None |
| `src_ip` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 130. `GET` `/api/v1/network-traffic/flows/{flow_id}`

**Summary:** Get a single flow

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `flow_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 131. `GET` `/api/v1/network-traffic/anomalies`

**Summary:** List traffic anomalies

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 132. `POST` `/api/v1/network-traffic/anomalies/{anomaly_id}/resolve`

**Summary:** Resolve an anomaly

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 133. `POST` `/api/v1/network-traffic/rules`

**Summary:** Create a traffic rule

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `RuleIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | Yes |  |  |
| `src_cidr` | str | No |  |  |
| `dst_cidr` | str | No |  |  |
| `port_range` | str | No |  |  |
| `protocol` | str | No | tcp |  |
| `action` | str | No | monitor |  |
| `priority` | int | No | 100 |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 134. `GET` `/api/v1/network-traffic/rules`

**Summary:** List traffic rules

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 135. `GET` `/api/v1/network-traffic/stats`

**Summary:** Get traffic statistics

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 136. `GET` `/api/v1/network-traffic/top-talkers`

**Summary:** Get top talkers by bytes

**Tags:** network-traffic

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `limit` | query | int | No | 10 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 137. `POST` `/api/v1/firewall-mgmt/firewalls`

**Summary:** POST /api/v1/firewall-mgmt/firewalls

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Register a new firewall device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `FirewallCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `vendor` | str | No | generic |  |
| `model` | str | No |  |  |
| `fw_type` | str | No | perimeter |  |
| `ip_address` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 138. `GET` `/api/v1/firewall-mgmt/firewalls`

**Summary:** GET /api/v1/firewall-mgmt/firewalls

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

List registered firewalls, optionally filtered by status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 139. `GET` `/api/v1/firewall-mgmt/firewalls/{firewall_id}`

**Summary:** GET /api/v1/firewall-mgmt/firewalls/{firewall_id}

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Get a single firewall by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 140. `POST` `/api/v1/firewall-mgmt/firewalls/{firewall_id}/rules`

**Summary:** POST /api/v1/firewall-mgmt/firewalls/{firewall_id}/rules

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Add a firewall rule. Risk level is automatically assessed.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RuleCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | No |  |  |
| `src_zone` | str | No |  |  |
| `dst_zone` | str | No |  |  |
| `src_address` | str | No | any |  |
| `dst_address` | str | No | any |  |
| `service` | List | No | PydanticUndefined |  |
| `action` | str | No | deny |  |
| `expires_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 141. `GET` `/api/v1/firewall-mgmt/rules`

**Summary:** GET /api/v1/firewall-mgmt/rules

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

List firewall rules with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `firewall_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `risk_level` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 142. `POST` `/api/v1/firewall-mgmt/rules/{rule_id}/disable`

**Summary:** POST /api/v1/firewall-mgmt/rules/{rule_id}/disable

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Disable a firewall rule.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 143. `POST` `/api/v1/firewall-mgmt/firewalls/{firewall_id}/detect-shadows`

**Summary:** POST /api/v1/firewall-mgmt/firewalls/{firewall_id}/detect-shadows

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Detect and mark shadowed rules for a firewall.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 144. `POST` `/api/v1/firewall-mgmt/change-requests`

**Summary:** POST /api/v1/firewall-mgmt/change-requests

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Create a firewall rule change request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ChangeRequestCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `firewall_id` | str | Yes |  |  |
| `change_type` | str | No | add |  |
| `requester` | str | No |  |  |
| `business_justification` | str | No |  |  |
| `rules_json` | List | No | PydanticUndefined |  |
| `expiry_date` | Optional | No | None |  |
| `risk_assessment` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 145. `GET` `/api/v1/firewall-mgmt/change-requests`

**Summary:** GET /api/v1/firewall-mgmt/change-requests

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

List change requests with optional status filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 146. `POST` `/api/v1/firewall-mgmt/change-requests/{request_id}/approve`

**Summary:** POST /api/v1/firewall-mgmt/change-requests/{request_id}/approve

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Approve a pending change request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ApproveRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 147. `POST` `/api/v1/firewall-mgmt/change-requests/{request_id}/reject`

**Summary:** POST /api/v1/firewall-mgmt/change-requests/{request_id}/reject

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Reject a pending change request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RejectRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 148. `POST` `/api/v1/firewall-mgmt/change-requests/{request_id}/implement`

**Summary:** POST /api/v1/firewall-mgmt/change-requests/{request_id}/implement

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Mark an approved change request as implemented.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 149. `POST` `/api/v1/firewall-mgmt/firewalls/{firewall_id}/scan`

**Summary:** POST /api/v1/firewall-mgmt/firewalls/{firewall_id}/scan

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Run a compliance scan on all rules for a firewall. Creates violation records.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 150. `GET` `/api/v1/firewall-mgmt/violations`

**Summary:** GET /api/v1/firewall-mgmt/violations

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

List compliance violations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `firewall_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 151. `POST` `/api/v1/firewall-mgmt/violations/{violation_id}/resolve`

**Summary:** POST /api/v1/firewall-mgmt/violations/{violation_id}/resolve

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Mark a compliance violation as resolved.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `violation_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 152. `GET` `/api/v1/firewall-mgmt/stats`

**Summary:** GET /api/v1/firewall-mgmt/stats

**Tags:** firewall-mgmt

**Auth:** API Key required

**Description:**

Return aggregated firewall management stats for org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 153. `POST` `/api/v1/cloud-cost/snapshots`

**Summary:** Record cost snapshot

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

Record a cloud cost snapshot. Anomaly detection runs automatically.

**Request Body:** `SnapshotCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `account_id` | str | No |  |  |
| `provider` | str | No | aws |  |
| `service_name` | str | No |  |  |
| `region` | str | No |  |  |
| `cost_usd` | float | No | 0.0 |  |
| `previous_cost_usd` | float | No | 0.0 |  |
| `change_pct` | float | No | 0.0 |  |
| `snapshot_date` | str | No |  |  |
| `last_used` | Optional | No | None |  |
| `has_public_ip` | bool | No | False |  |
| `is_idle` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 154. `GET` `/api/v1/cloud-cost/snapshots`

**Summary:** List cost snapshots

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `account_id` | query | Optional | No | None |
| `anomaly` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 155. `POST` `/api/v1/cloud-cost/abandoned-resources`

**Summary:** Register abandoned resource

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AbandonedResourceCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `account_id` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `region` | str | No |  |  |
| `provider` | str | No | aws |  |
| `last_used` | Optional | No | None |  |
| `monthly_cost_usd` | float | No | 0.0 |  |
| `security_risk` | bool | No | False |  |
| `risk_reason` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 156. `GET` `/api/v1/cloud-cost/abandoned-resources`

**Summary:** List abandoned resources

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 157. `POST` `/api/v1/cloud-cost/abandoned-resources/{resource_id}/terminate`

**Summary:** Terminate resource

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 158. `POST` `/api/v1/cloud-cost/budgets`

**Summary:** Create cost budget

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `BudgetCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `account_id` | str | No |  |  |
| `budget_name` | str | Yes |  |  |
| `period` | str | No | monthly |  |
| `limit_usd` | float | No | 0.0 |  |
| `current_spend_usd` | float | No | 0.0 |  |
| `alert_threshold_pct` | int | No | 80 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 159. `GET` `/api/v1/cloud-cost/budgets`

**Summary:** List cost budgets

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 160. `POST` `/api/v1/cloud-cost/anomalies`

**Summary:** Record cost anomaly

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AnomalyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `account_id` | str | No |  |  |
| `service_name` | str | No |  |  |
| `cost_usd` | float | No | 0.0 |  |
| `expected_usd` | float | No | 0.0 |  |
| `deviation_pct` | float | No | 0.0 |  |
| `anomaly_type` | str | No | spike |  |
| `severity` | str | No | medium |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 161. `GET` `/api/v1/cloud-cost/anomalies`

**Summary:** List cost anomalies

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 162. `POST` `/api/v1/cloud-cost/anomalies/{anomaly_id}/resolve`

**Summary:** Resolve anomaly

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 163. `GET` `/api/v1/cloud-cost/stats`

**Summary:** Cloud cost security stats

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 164. `POST` `/api/v1/cloud-cost/items`

**Summary:** Record cost item

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

Record a cloud resource cost item with security relevance tagging.

**Request Body:** `CostItemCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `cloud_provider` | str | No | aws |  |
| `service` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `monthly_cost_usd` | float | No | 0.0 |  |
| `security_relevance` | str | No | low |  |
| `tags` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 165. `GET` `/api/v1/cloud-cost/items`

**Summary:** List cost items

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `cloud_provider` | query | Optional | No | None |
| `security_relevance` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 166. `POST` `/api/v1/cloud-cost/items/flag`

**Summary:** Flag unused resource

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

Flag a resource for decommission review.

**Request Body:** `FlagResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  |  |
| `reason` | str | Yes |  |  |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 167. `GET` `/api/v1/cloud-cost/items/spend-breakdown`

**Summary:** Security spend breakdown

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 168. `GET` `/api/v1/cloud-cost/items/anomalies`

**Summary:** Detect cost anomalies (MoM >50%)

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 169. `POST` `/api/v1/cloud-cost/policies`

**Summary:** Create cost policy

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CostPolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  |  |
| `max_monthly_usd` | float | No | 0.0 |  |
| `resource_type` | str | No |  |  |
| `action` | str | No | alert |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 170. `GET` `/api/v1/cloud-cost/policies`

**Summary:** List cost policies

**Tags:** cloud-cost

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 171. `GET` `/api/v1/nac/devices`

**Summary:** GET /api/v1/nac/devices

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 172. `POST` `/api/v1/nac/devices`

**Summary:** POST /api/v1/nac/devices

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `DeviceCreateReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `hostname` | str | Yes |  |  |
| `device_type` | str | No | laptop |  |
| `owner` | Optional | No | None |  |
| `ip_address` | Optional | No | None |  |
| `mac_address` | Optional | No | None |  |
| `os_type` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 173. `GET` `/api/v1/nac/devices/{device_id}`

**Summary:** GET /api/v1/nac/devices/{device_id}

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 174. `POST` `/api/v1/nac/devices/{device_id}/posture-check`

**Summary:** POST /api/v1/nac/devices/{device_id}/posture-check

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 175. `PUT` `/api/v1/nac/devices/{device_id}/status`

**Summary:** PUT /api/v1/nac/devices/{device_id}/status

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |

**Request Body:** `DeviceStatusReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `status` | str | Yes |  |  |
| `reason` | str | Yes |  |  |
| `updated_by` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 176. `POST` `/api/v1/nac/devices/{device_id}/apply-policy`

**Summary:** POST /api/v1/nac/devices/{device_id}/apply-policy

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |

**Request Body:** `ApplyPolicyReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `policy_id` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 177. `GET` `/api/v1/nac/policies`

**Summary:** GET /api/v1/nac/policies

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 178. `POST` `/api/v1/nac/policies`

**Summary:** POST /api/v1/nac/policies

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `PolicyCreateReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `name` | str | Yes |  |  |
| `device_types` | List | No | PydanticUndefined |  |
| `required_checks` | List | No | PydanticUndefined |  |
| `vlan_on_pass` | Optional | No | None |  |
| `vlan_on_fail` | Optional | No | None |  |
| `action_on_fail` | str | No | quarantine |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 179. `GET` `/api/v1/nac/events`

**Summary:** GET /api/v1/nac/events

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_id` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 180. `POST` `/api/v1/nac/events`

**Summary:** POST /api/v1/nac/events

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AccessEventReq`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `device_id` | str | Yes |  |  |
| `event_type` | str | Yes |  |  |
| `location` | Optional | No | None |  |
| `switch_port` | Optional | No | None |  |
| `details` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 181. `GET` `/api/v1/nac/stats`

**Summary:** GET /api/v1/nac/stats

**Tags:** Network Access Control

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 182. `GET` `/api/v1/waf-engine/rules`

**Summary:** GET /api/v1/waf-engine/rules

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `rule_type` | query | Optional | No | None |
| `enabled` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 183. `POST` `/api/v1/waf-engine/rules`

**Summary:** POST /api/v1/waf-engine/rules

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | Yes |  |  |
| `rule_type` | str | No | block |  |
| `pattern` | str | No |  |  |
| `target` | str | No | uri |  |
| `action` | str | No | block |  |
| `severity` | str | No | high |  |
| `enabled` | bool | No | True |  |
| `description` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 184. `PUT` `/api/v1/waf-engine/rules/{rule_id}`

**Summary:** PUT /api/v1/waf-engine/rules/{rule_id}

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdateRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | Optional | No | None |  |
| `rule_type` | Optional | No | None |  |
| `pattern` | Optional | No | None |  |
| `target` | Optional | No | None |  |
| `action` | Optional | No | None |  |
| `severity` | Optional | No | None |  |
| `enabled` | Optional | No | None |  |
| `description` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 185. `DELETE` `/api/v1/waf-engine/rules/{rule_id}`

**Summary:** DELETE /api/v1/waf-engine/rules/{rule_id}

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 186. `GET` `/api/v1/waf-engine/blocked-requests`

**Summary:** GET /api/v1/waf-engine/blocked-requests

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `attack_type` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `limit` | query | int | No | 100 |
| `hours` | query | int | No | 24 |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 187. `POST` `/api/v1/waf-engine/blocked-requests`

**Summary:** POST /api/v1/waf-engine/blocked-requests

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BlockedRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_id` | str | No |  |  |
| `source_ip` | str | No |  |  |
| `uri` | str | No |  |  |
| `method` | str | No | GET |  |
| `user_agent` | str | No |  |  |
| `attack_type` | str | No | xss |  |
| `severity` | str | No | high |  |
| `request_headers` | Dict | No | PydanticUndefined |  |
| `blocked_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 188. `GET` `/api/v1/waf-engine/virtual-patches`

**Summary:** GET /api/v1/waf-engine/virtual-patches

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `active_only` | query | bool | No | True |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 189. `POST` `/api/v1/waf-engine/virtual-patches`

**Summary:** POST /api/v1/waf-engine/virtual-patches

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `VirtualPatchBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cve_id` | str | Yes |  |  |
| `title` | str | Yes |  |  |
| `rule_pattern` | str | No |  |  |
| `expires_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 190. `GET` `/api/v1/waf-engine/rate-limits`

**Summary:** GET /api/v1/waf-engine/rate-limits

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 191. `POST` `/api/v1/waf-engine/rate-limits`

**Summary:** POST /api/v1/waf-engine/rate-limits

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RateLimitBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoint_pattern` | str | No | /* |  |
| `requests_per_minute` | int | No | 60 |  |
| `burst_size` | int | No | 10 |  |
| `action` | str | No | block |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 192. `GET` `/api/v1/waf-engine/stats`

**Summary:** GET /api/v1/waf-engine/stats

**Tags:** WAF Engine

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 193. `POST` `/api/v1/mdm/devices`

**Summary:** POST /api/v1/mdm/devices

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Enroll a new mobile device into MDM.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `DeviceEnroll`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_name` | str | No |  |  |
| `platform` | str | No | ios |  |
| `model` | str | No |  |  |
| `serial_number` | str | No |  |  |
| `owner_email` | str | No |  |  |
| `enrollment_type` | str | No | corporate |  |
| `os_version` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 194. `GET` `/api/v1/mdm/devices`

**Summary:** GET /api/v1/mdm/devices

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

List enrolled devices, optionally filtered by platform and/or compliance_status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `platform` | query | Optional | No | None |
| `compliance_status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 195. `GET` `/api/v1/mdm/devices/{device_id}`

**Summary:** GET /api/v1/mdm/devices/{device_id}

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Get a single device by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 196. `POST` `/api/v1/mdm/devices/{device_id}/compliance-check`

**Summary:** POST /api/v1/mdm/devices/{device_id}/compliance-check

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Run a compliance check on the device and persist the result.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 197. `PUT` `/api/v1/mdm/devices/{device_id}/compliance`

**Summary:** PUT /api/v1/mdm/devices/{device_id}/compliance

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Manually update device compliance status and issues.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ComplianceUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |
| `issues` | List | No | PydanticUndefined |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 198. `POST` `/api/v1/mdm/devices/{device_id}/wipe`

**Summary:** POST /api/v1/mdm/devices/{device_id}/wipe

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Queue a remote wipe request for the device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `WipeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `wiped_by` | str | Yes |  |  |
| `wipe_type` | str | No | full |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 199. `GET` `/api/v1/mdm/devices/{device_id}/apps`

**Summary:** GET /api/v1/mdm/devices/{device_id}/apps

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

List all apps recorded on a device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 200. `POST` `/api/v1/mdm/devices/{device_id}/apps`

**Summary:** POST /api/v1/mdm/devices/{device_id}/apps

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Record an app installation on a device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AppInstall`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app_name` | str | Yes |  |  |
| `app_version` | str | No |  |  |
| `is_approved` | bool | No | True |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 201. `GET` `/api/v1/mdm/policies`

**Summary:** GET /api/v1/mdm/policies

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

List MDM policies, optionally filtered by platform.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `platform` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 202. `POST` `/api/v1/mdm/policies`

**Summary:** POST /api/v1/mdm/policies

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Create a new MDM policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `platform` | str | No | ios |  |
| `requirements` | PolicyRequirements | No | PydanticUndefined |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 203. `GET` `/api/v1/mdm/wipe-requests`

**Summary:** GET /api/v1/mdm/wipe-requests

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

List all pending and completed wipe requests for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 204. `GET` `/api/v1/mdm/stats`

**Summary:** GET /api/v1/mdm/stats

**Tags:** MDM Engine

**Auth:** API Key required

**Description:**

Return aggregated MDM statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 205. `GET` `/api/v1/casb/apps`

**Summary:** List cloud apps

**Tags:** casb

**Auth:** API Key required

**Description:**

List discovered cloud applications with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `category` | query | Optional | No | Filter by app category |
| `is_sanctioned` | query | Optional | No | Filter by sanction status |
| `risk_level` | query | Optional | No | Filter by risk level |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 206. `POST` `/api/v1/casb/apps`

**Summary:** Discover/register a cloud app

**Tags:** casb

**Auth:** API Key required

**Description:**

Register or update a discovered cloud application.

**Request Body:** `DiscoverAppRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `app_name` | str | Yes |  | Cloud application name (e.g. 'Dropbox') |
| `app_category` | str | No | other | Category: productivity/collaboration/storage/crm/devtools/social/other |
| `risk_level` | str | No | medium | Risk level: critical/high/medium/low |
| `users_count` | int | No | 0 | Number of users using the app |
| `data_uploaded_gb` | float | No | 0.0 | Data uploaded in GB |
| `is_sanctioned` | bool | No | False | Whether the app is sanctioned |
| `oauth_scopes` | List | No | PydanticUndefined | OAuth permission scopes granted |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 207. `POST` `/api/v1/casb/apps/{app_id}/sanction`

**Summary:** Sanction a cloud app

**Tags:** casb

**Auth:** API Key required

**Description:**

Mark a cloud app as sanctioned (approved for use).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |

**Request Body:** `SanctionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `sanctioned_by` | str | Yes |  | Identity of approver |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 208. `POST` `/api/v1/casb/apps/{app_id}/unsanction`

**Summary:** Unsanction a cloud app

**Tags:** casb

**Auth:** API Key required

**Description:**

Mark a cloud app as unsanctioned (shadow IT / blocked).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |

**Request Body:** `UnsanctionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `reason` | str | Yes |  | Reason for unsanctioning (blocking) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 209. `GET` `/api/v1/casb/data-activities`

**Summary:** List data activities

**Tags:** casb

**Auth:** API Key required

**Description:**

List cloud data activities with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `app_name` | query | Optional | No | Filter by app name |
| `data_classification` | query | Optional | No | Filter by data classification |
| `limit` | query | int | No | Max records to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 210. `POST` `/api/v1/casb/data-activities`

**Summary:** Record a data activity

**Tags:** casb

**Auth:** API Key required

**Description:**

Record a data activity event (upload/download/share/delete).

**Request Body:** `RecordActivityRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `app_name` | str | Yes |  | Cloud application name |
| `user` | str | Yes |  | User identifier (email or username) |
| `activity_type` | str | Yes |  | Activity type: upload/download/share/delete |
| `file_type` | str | No |  | File MIME type or extension |
| `size_bytes` | int | No | 0 | Size of data transferred in bytes |
| `destination` | str | No | internal | Destination: internal/external/public |
| `data_classification` | str | No | internal | Data classification: public/internal/confidential/secret |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 211. `GET` `/api/v1/casb/policies`

**Summary:** List CASB policies

**Tags:** casb

**Auth:** API Key required

**Description:**

List all CASB policies for the organisation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 212. `POST` `/api/v1/casb/policies`

**Summary:** Create a CASB policy

**Tags:** casb

**Auth:** API Key required

**Description:**

Create a new CASB policy (data_loss/app_block/oauth_restrict).

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `name` | str | Yes |  | Policy name |
| `policy_type` | str | Yes |  | Policy type: data_loss/app_block/oauth_restrict |
| `conditions` | Dict | No | PydanticUndefined | Policy condition parameters |
| `action` | str | No | alert | Enforcement action: block/alert/encrypt |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 213. `GET` `/api/v1/casb/violations`

**Summary:** List policy violations

**Tags:** casb

**Auth:** API Key required

**Description:**

List CASB policy violations with optional severity filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `severity` | query | Optional | No | Filter by severity |
| `limit` | query | int | No | Max records to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 214. `POST` `/api/v1/casb/violations`

**Summary:** Record a policy violation

**Tags:** casb

**Auth:** API Key required

**Description:**

Record a CASB policy violation event.

**Request Body:** `RecordViolationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `policy_id` | str | Yes |  | ID of the violated policy |
| `user` | str | Yes |  | User who triggered the violation |
| `app_name` | str | Yes |  | App involved in the violation |
| `violation_detail` | str | No |  | Detailed description of violation |
| `severity` | str | No | medium | Severity: critical/high/medium/low/info |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 215. `GET` `/api/v1/casb/shadow-it-report`

**Summary:** Shadow IT discovery report

**Tags:** casb

**Auth:** API Key required

**Description:**

Return shadow IT discovery report: total apps, sanctioned/unsanctioned breakdown, high-risk apps,
and top data uploaders.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 216. `GET` `/api/v1/casb/stats`

**Summary:** CASB statistics

**Tags:** casb

**Auth:** API Key required

**Description:**

Return aggregated CASB statistics: shadow IT %, 24h activity/violations, risk distribution, and
policy count.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 217. `GET` `/api/v1/iam-policy/policies`

**Summary:** GET /api/v1/iam-policy/policies

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `policy_type` | query | Optional | No | None |
| `principal_type` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 218. `POST` `/api/v1/iam-policy/policies`

**Summary:** POST /api/v1/iam-policy/policies

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  | Human-readable policy name |
| `policy_type` | str | No | aws_iam | aws_iam / azure_rbac / gcp_iam |
| `principal_type` | str | No | user | user / group / service_account / role |
| `principal_id` | str | No |  | Principal identifier (ARN, email, etc.) |
| `permissions` | List | No | PydanticUndefined | List of permission actions |
| `resources` | List | No | PydanticUndefined | List of resource ARNs / URIs |
| `conditions` | Dict | No | PydanticUndefined | Policy conditions |
| `is_managed` | bool | No | True | Whether this is a managed (vs inline) policy |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 219. `GET` `/api/v1/iam-policy/policies/{policy_id}/analyze`

**Summary:** GET /api/v1/iam-policy/policies/{policy_id}/analyze

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 220. `POST` `/api/v1/iam-policy/analyze-all`

**Summary:** POST /api/v1/iam-policy/analyze-all

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 221. `GET` `/api/v1/iam-policy/access-reviews`

**Summary:** GET /api/v1/iam-policy/access-reviews

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 222. `POST` `/api/v1/iam-policy/access-reviews`

**Summary:** POST /api/v1/iam-policy/access-reviews

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Request Body:** `AccessReviewCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_id` | str | Yes |  | Policy being reviewed |
| `reviewer` | str | Yes |  | Reviewer identity |
| `outcome` | str | No | approved | approved / revoked / modified |
| `action_taken` | str | No |  | Description of action taken |
| `review_date` | Optional | No | None | ISO 8601 review date (defaults to now) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 223. `GET` `/api/v1/iam-policy/stats`

**Summary:** GET /api/v1/iam-policy/stats

**Tags:** iam-policy

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 224. `GET` `/api/v1/cloud-drift/baselines`

**Summary:** GET /api/v1/cloud-drift/baselines

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `environment` | query | Optional | No | Filter by environment |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 225. `POST` `/api/v1/cloud-drift/baselines`

**Summary:** POST /api/v1/cloud-drift/baselines

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Request Body:** `BaselineCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  | Cloud resource identifier |
| `resource_type` | str | No | ec2 | ec2 / s3 / rds / lambda / sg / vpc |
| `resource_name` | str | No |  | Human-readable resource name |
| `expected_config` | Dict | No | PydanticUndefined | Expected configuration from IaC |
| `source` | str | No | terraform | terraform / cloudformation / manual |
| `environment` | str | No | prod | prod / staging / dev |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 226. `GET` `/api/v1/cloud-drift/drifts`

**Summary:** GET /api/v1/cloud-drift/drifts

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `severity` | query | Optional | No | None |
| `drift_type` | query | Optional | No | None |
| `status` | query | Optional | No | open / acknowledged / remediated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 227. `POST` `/api/v1/cloud-drift/drifts`

**Summary:** POST /api/v1/cloud-drift/drifts

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Request Body:** `DriftCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  | Cloud resource identifier |
| `drift_type` | str | No | config_changed | config_changed / resource_deleted / new_resource / tag_missing / permission_widened |
| `severity` | str | No | medium | critical / high / medium / low |
| `expected_value` | str | No |  | Expected configuration value |
| `actual_value` | str | No |  | Actual observed configuration value |
| `detected_at` | Optional | No | None | ISO 8601 detection timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 228. `POST` `/api/v1/cloud-drift/drifts/{drift_id}/acknowledge`

**Summary:** POST /api/v1/cloud-drift/drifts/{drift_id}/acknowledge

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `drift_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Request Body:** `AcknowledgeBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `acknowledged_by` | str | Yes |  | Identity of acknowledger |
| `notes` | str | No |  | Acknowledgement notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 229. `POST` `/api/v1/cloud-drift/drifts/{drift_id}/remediate`

**Summary:** POST /api/v1/cloud-drift/drifts/{drift_id}/remediate

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `drift_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Request Body:** `RemediateBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `remediated_by` | str | Yes |  | Identity of remediator |
| `method` | str | No | manual | manual / automated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 230. `POST` `/api/v1/cloud-drift/scan`

**Summary:** POST /api/v1/cloud-drift/scan

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `environment` | query | Optional | No | Filter scan to environment |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 231. `GET` `/api/v1/cloud-drift/stats`

**Summary:** GET /api/v1/cloud-drift/stats

**Tags:** cloud-drift

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 232. `GET` `/api/v1/cloud-native/accounts`

**Summary:** GET /api/v1/cloud-native/accounts

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud accounts for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 233. `POST` `/api/v1/cloud-native/accounts`

**Summary:** POST /api/v1/cloud-native/accounts

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a new cloud account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `RegisterAccountRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | No | aws |  |
| `account_id` | str | No |  |  |
| `account_name` | str | No |  |  |
| `region` | str | No | us-east-1 |  |
| `environment` | str | No | prod |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 234. `GET` `/api/v1/cloud-native/misconfigurations`

**Summary:** GET /api/v1/cloud-native/misconfigurations

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List misconfigurations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |
| `provider` | query | Optional | No | None |
| `service` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `include_compliant` | query | bool | No | Include already-compliant findings |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 235. `POST` `/api/v1/cloud-native/misconfigurations`

**Summary:** POST /api/v1/cloud-native/misconfigurations

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record a cloud misconfiguration finding.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `RecordMisconfigRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `provider` | str | No | aws |  |
| `service` | str | No | s3 |  |
| `check_name` | str | No |  |  |
| `severity` | str | No | medium |  |
| `resource_id` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |
| `compliant` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 236. `POST` `/api/v1/cloud-native/misconfigurations/{finding_id}/mark-compliant`

**Summary:** POST /api/v1/cloud-native/misconfigurations/{finding_id}/mark-compliant

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a misconfiguration as remediated.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `MarkCompliantRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `fixed_by` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 237. `POST` `/api/v1/cloud-native/accounts/{account_id}/posture-check`

**Summary:** POST /api/v1/cloud-native/accounts/{account_id}/posture-check

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Run a cloud posture check against an account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 238. `GET` `/api/v1/cloud-native/stats`

**Summary:** GET /api/v1/cloud-native/stats

**Tags:** cloud-native

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get aggregate cloud security stats for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 239. `GET` `/api/v1/kubernetes-security/clusters`

**Summary:** GET /api/v1/kubernetes-security/clusters

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List Kubernetes clusters for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 240. `POST` `/api/v1/kubernetes-security/clusters`

**Summary:** POST /api/v1/kubernetes-security/clusters

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a Kubernetes cluster.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `RegisterClusterRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster_name` | str | No | unnamed-cluster |  |
| `provider` | str | No | eks |  |
| `k8s_version` | str | No | 1.28 |  |
| `node_count` | int | No | 1 |  |
| `namespace_count` | int | No | 1 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 241. `POST` `/api/v1/kubernetes-security/clusters/{cluster_id}/cis-benchmark`

**Summary:** POST /api/v1/kubernetes-security/clusters/{cluster_id}/cis-benchmark

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Run CIS Kubernetes Benchmark v1.8 against a cluster.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cluster_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 242. `GET` `/api/v1/kubernetes-security/clusters/{cluster_id}/rbac-analysis`

**Summary:** GET /api/v1/kubernetes-security/clusters/{cluster_id}/rbac-analysis

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get RBAC analysis for a cluster.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cluster_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 243. `GET` `/api/v1/kubernetes-security/findings`

**Summary:** GET /api/v1/kubernetes-security/findings

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List security findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |
| `cluster_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `finding_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 244. `POST` `/api/v1/kubernetes-security/findings`

**Summary:** POST /api/v1/kubernetes-security/findings

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record a Kubernetes security finding.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `RecordFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster_id` | str | Yes |  |  |
| `finding_type` | str | No | no_resource_limits |  |
| `severity` | str | No | medium |  |
| `namespace` | str | No | default |  |
| `resource_name` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 245. `POST` `/api/v1/kubernetes-security/findings/{finding_id}/resolve`

**Summary:** POST /api/v1/kubernetes-security/findings/{finding_id}/resolve

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a finding as resolved.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `ResolveFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolved_by` | str | Yes |  |  |
| `resolution_notes` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 246. `GET` `/api/v1/kubernetes-security/stats`

**Summary:** GET /api/v1/kubernetes-security/stats

**Tags:** kubernetes-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get aggregate Kubernetes security stats for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 247. `POST` `/api/v1/network-monitoring/interfaces`

**Summary:** Register a network interface

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Register a network interface (WAN/LAN/DMZ) for monitoring.

**Request Body:** `RegisterInterfaceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `name` | str | Yes |  | Interface name, e.g. eth0 |
| `ip` | str | No |  | Interface IP address |
| `if_type` | str | No | lan | Interface type: wan/lan/dmz |
| `description` | str | No |  | Optional description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 248. `GET` `/api/v1/network-monitoring/interfaces`

**Summary:** List network interfaces

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

List registered interfaces for an org with optional type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `if_type` | query | Optional | No | Filter by type: wan/lan/dmz |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 249. `POST` `/api/v1/network-monitoring/interfaces/{interface_id}/samples`

**Summary:** Record a traffic sample

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Record a traffic sample (bytes/packets) for a specific interface.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `interface_id` | path | str | Yes | — |

**Request Body:** `TrafficSampleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `bytes_in` | int | No | 0 | Bytes received |
| `bytes_out` | int | No | 0 | Bytes transmitted |
| `packets_in` | int | No | 0 | Packets received |
| `packets_out` | int | No | 0 | Packets transmitted |
| `timestamp` | Optional | No | None | ISO-8601 sample timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 250. `GET` `/api/v1/network-monitoring/interfaces/{interface_id}/stats`

**Summary:** Get traffic statistics

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Return avg_bps, peak_bps, and total_bytes for an interface over N hours.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `interface_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |
| `hours` | query | int | No | Lookback window in hours |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 251. `POST` `/api/v1/network-monitoring/alert-rules`

**Summary:** Create an alert rule

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Create an alert rule that triggers when a metric exceeds a threshold.

**Request Body:** `AlertRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `interface_id` | str | Yes |  | Target interface ID |
| `metric` | str | No | bytes_in | Metric to monitor |
| `threshold` | float | No | 0.0 | Alert threshold value |
| `severity` | str | No | medium | Severity: critical/high/medium/low |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 252. `GET` `/api/v1/network-monitoring/alert-rules`

**Summary:** List alert rules

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

List all alert rules for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 253. `POST` `/api/v1/network-monitoring/alert-rules/{rule_id}/trigger`

**Summary:** Trigger an alert for a rule

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Manually trigger an alert for a rule with an observed metric value.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Request Body:** `TriggerAlertRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `value` | float | Yes |  | Observed metric value that triggered the rule |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 254. `GET` `/api/v1/network-monitoring/alerts`

**Summary:** List triggered alerts

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

List triggered alerts for an org with optional severity filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `severity` | query | Optional | No | Filter by severity: critical/high/medium/low |
| `limit` | query | int | No | Max results |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 255. `GET` `/api/v1/network-monitoring/stats`

**Summary:** Get monitoring stats

**Tags:** network-monitoring

**Auth:** API Key required

**Description:**

Return aggregate monitoring stats: interface count, sample count, alert count.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 256. `POST` `/api/v1/bandwidth-analysis/links`

**Summary:** Register a network link

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Register a network link (fiber/VPN/internet/MPLS) for bandwidth analysis.

**Request Body:** `RegisterLinkRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `name` | str | Yes |  | Link name, e.g. WAN-Primary |
| `capacity_mbps` | float | No | 0.0 | Link capacity in Mbps |
| `link_type` | str | No | internet | Link type: fiber/vpn/internet/mpls |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 257. `GET` `/api/v1/bandwidth-analysis/links`

**Summary:** List network links

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

List all registered links for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 258. `POST` `/api/v1/bandwidth-analysis/links/{link_id}/utilization`

**Summary:** Record utilization sample

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Record a utilization sample (0-100%) for a specific link.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `link_id` | path | str | Yes | — |

**Request Body:** `RecordUtilizationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `utilization_pct` | float | No | 0.0 | Utilization percentage 0-100 |
| `direction` | str | No | both | Traffic direction: inbound/outbound/both |
| `recorded_at` | Optional | No | None | ISO-8601 timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 259. `GET` `/api/v1/bandwidth-analysis/links/{link_id}/trend`

**Summary:** Get utilization trend

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Return avg_pct, peak_pct, and per-sample data for a link over N hours.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `link_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |
| `hours` | query | int | No | Lookback window in hours |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 260. `GET` `/api/v1/bandwidth-analysis/links/{link_id}/anomaly`

**Summary:** Detect bandwidth anomaly

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Detect utilization anomaly for a link using z-score against historical baseline.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `link_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 261. `POST` `/api/v1/bandwidth-analysis/qos-policies`

**Summary:** Create a QoS policy

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Create a QoS policy for traffic prioritisation and bandwidth capping.

**Request Body:** `QoSPolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `name` | str | Yes |  | Policy name |
| `priority` | int | No | 4 | QoS priority 1 (highest) to 8 (lowest) |
| `traffic_class` | str | No |  | Traffic class, e.g. 'voice', 'bulk', 'critical' |
| `bandwidth_limit_pct` | float | No | 100.0 | Bandwidth cap 0-100% |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 262. `GET` `/api/v1/bandwidth-analysis/qos-policies`

**Summary:** List QoS policies

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

List QoS policies for an org ordered by priority.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 263. `GET` `/api/v1/bandwidth-analysis/stats`

**Summary:** Get bandwidth stats

**Tags:** bandwidth-analysis

**Auth:** API Key required

**Description:**

Return aggregate bandwidth stats: total links, avg utilization, high-util links.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 264. `POST` `/api/v1/service-account-auditor/accounts`

**Summary:** Register a service account for auditing

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Register a new service account and compute its initial risk score.

**Request Body:** `RegisterAccountRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organization identifier |
| `name` | str | Yes |  | Service account name or identifier |
| `system` | str | Yes |  | Platform: k8s, aws, gcp, azure, linux |
| `permissions` | List | No | PydanticUndefined | List of permissions/roles |
| `last_used_days_ago` | int | No | 0 | Days since last use |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 265. `GET` `/api/v1/service-account-auditor/accounts`

**Summary:** List service accounts for an org

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

List all service accounts, optionally filtered by system.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |
| `system` | query | Optional | No | Filter by system (k8s/aws/gcp/azure/linux) |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 266. `GET` `/api/v1/service-account-auditor/accounts/unused`

**Summary:** Get unused service accounts

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Return service accounts not used in the last N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |
| `days_threshold` | query | int | No | Days of inactivity threshold |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 267. `GET` `/api/v1/service-account-auditor/accounts/overprivileged`

**Summary:** Get overprivileged service accounts

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Return service accounts with risk_score > 70.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 268. `POST` `/api/v1/service-account-auditor/accounts/{account_id}/audit`

**Summary:** Run a security audit on a service account

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Audit a specific service account and return findings with risk score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |

**Request Body:** `RunAuditRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organization identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 269. `POST` `/api/v1/service-account-auditor/accounts/{account_id}/rotate`

**Summary:** Record a credential rotation event

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Record that credentials for a service account were rotated.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |

**Request Body:** `RotateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organization identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 270. `GET` `/api/v1/service-account-auditor/accounts/{account_id}/rotation-history`

**Summary:** Get credential rotation history

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Return all credential rotation events for a service account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 271. `GET` `/api/v1/service-account-auditor/stats`

**Summary:** Get service account audit statistics

**Tags:** service-account-auditor

**Auth:** API Key required

**Description:**

Return aggregate stats: total accounts, high-risk count, overdue rotations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 272. `POST` `/api/v1/privilege-escalation/events`

**Summary:** Record a privilege escalation event

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

Record a privilege escalation event and compute its anomaly score.

**Request Body:** `RecordEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organization identifier |
| `user_id` | str | Yes |  | User or service account identifier |
| `from_role` | str | Yes |  | Role/permission level before escalation |
| `to_role` | str | Yes |  | Role/permission level after escalation |
| `method` | str | No | other | Escalation method: sudo/setuid/token/exploit/impersonation/suid/other |
| `source_ip` | str | No |  | Source IP address of the escalation event |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 273. `GET` `/api/v1/privilege-escalation/events`

**Summary:** List privilege escalation events

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

List privilege escalation events, optionally filtered by user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |
| `user_id` | query | Optional | No | Filter by user ID |
| `limit` | query | int | No | Max results |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 274. `GET` `/api/v1/privilege-escalation/events/{event_id}/detect`

**Summary:** Detect anomaly for a specific escalation event

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

Analyze a specific escalation event and return its anomaly assessment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `event_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 275. `POST` `/api/v1/privilege-escalation/rules`

**Summary:** Create a privilege escalation detection rule

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

Create a regex-based detection rule for privilege escalation patterns.

**Request Body:** `CreateRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organization identifier |
| `name` | str | Yes |  | Rule name |
| `pattern` | str | Yes |  | Regex pattern to match against event strings |
| `severity` | str | No | medium | critical/high/medium/low |
| `action` | str | No | alert | alert/block/log |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 276. `GET` `/api/v1/privilege-escalation/rules`

**Summary:** List detection rules for an org

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

List all privilege escalation detection rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 277. `GET` `/api/v1/privilege-escalation/heatmap`

**Summary:** Get escalation activity heatmap

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

Return escalation heatmap: top users, top methods, events by hour.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |
| `hours` | query | int | No | Time window in hours (max 7 days) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 278. `GET` `/api/v1/privilege-escalation/stats`

**Summary:** Get privilege escalation detection statistics

**Tags:** privilege-escalation

**Auth:** API Key required

**Description:**

Return aggregate stats: total events, anomalies detected, blocked attempts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 279. `POST` `/api/v1/firewall-policy/firewalls`

**Summary:** POST /api/v1/firewall-policy/firewalls

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Register a new firewall device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `FirewallCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `fw_type` | str | Yes |  |  |
| `management_ip` | str | No |  |  |
| `description` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 280. `GET` `/api/v1/firewall-policy/firewalls`

**Summary:** GET /api/v1/firewall-policy/firewalls

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

List all firewalls for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 281. `POST` `/api/v1/firewall-policy/firewalls/{firewall_id}/rules`

**Summary:** POST /api/v1/firewall-policy/firewalls/{firewall_id}/rules

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Add a rule to a firewall.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RuleCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `action` | str | Yes |  |  |
| `src_zones` | List | No | [] |  |
| `dst_zones` | List | No | [] |  |
| `src_ips` | List | No | [] |  |
| `dst_ips` | List | No | [] |  |
| `ports` | List | No | [] |  |
| `protocol` | str | No | any |  |
| `enabled` | bool | No | True |  |
| `order_num` | int | No | 0 |  |
| `hit_count` | int | No | 0 |  |
| `last_hit_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 282. `GET` `/api/v1/firewall-policy/firewalls/{firewall_id}/rules`

**Summary:** GET /api/v1/firewall-policy/firewalls/{firewall_id}/rules

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

List rules for a firewall with optional action filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `action` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 283. `GET` `/api/v1/firewall-policy/firewalls/{firewall_id}/conflicts`

**Summary:** GET /api/v1/firewall-policy/firewalls/{firewall_id}/conflicts

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Find rules that shadow or conflict with each other.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 284. `GET` `/api/v1/firewall-policy/firewalls/{firewall_id}/unused`

**Summary:** GET /api/v1/firewall-policy/firewalls/{firewall_id}/unused

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Find rules with zero hits or no recent hits.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `days_threshold` | query | int | No | 90 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 285. `GET` `/api/v1/firewall-policy/firewalls/{firewall_id}/gaps`

**Summary:** GET /api/v1/firewall-policy/firewalls/{firewall_id}/gaps

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Analyze coverage gaps and risky configurations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `firewall_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 286. `GET` `/api/v1/firewall-policy/stats`

**Summary:** GET /api/v1/firewall-policy/stats

**Tags:** Firewall Policy

**Auth:** API Key required

**Description:**

Return aggregated firewall statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 287. `POST` `/api/v1/network-segmentation/segments`

**Summary:** POST /api/v1/network-segmentation/segments

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Create a network segment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `SegmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `cidr` | str | No |  |  |
| `segment_type` | str | Yes |  |  |
| `trust_level` | int | No | 5 |  |
| `description` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 288. `GET` `/api/v1/network-segmentation/segments`

**Summary:** GET /api/v1/network-segmentation/segments

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

List segments with optional type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `segment_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 289. `POST` `/api/v1/network-segmentation/flow-policies`

**Summary:** POST /api/v1/network-segmentation/flow-policies

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Add a flow policy between two segments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `FlowPolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `src_segment_id` | str | Yes |  |  |
| `dst_segment_id` | str | Yes |  |  |
| `action` | str | Yes |  |  |
| `ports` | List | No | [] |  |
| `justification` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 290. `GET` `/api/v1/network-segmentation/flow-policies`

**Summary:** GET /api/v1/network-segmentation/flow-policies

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

List all flow policies for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 291. `POST` `/api/v1/network-segmentation/check-flow`

**Summary:** POST /api/v1/network-segmentation/check-flow

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Check whether traffic between two segments on a given port is allowed.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `FlowCheckRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `src_segment_id` | str | Yes |  |  |
| `dst_segment_id` | str | Yes |  |  |
| `port` | int | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 292. `GET` `/api/v1/network-segmentation/lateral-movement-risk`

**Summary:** GET /api/v1/network-segmentation/lateral-movement-risk

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Detect segment pairs with risky allow-all flows between different trust levels.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 293. `GET` `/api/v1/network-segmentation/score`

**Summary:** GET /api/v1/network-segmentation/score

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Return segmentation score (0-100), grade (A-F), and findings.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 294. `GET` `/api/v1/network-segmentation/stats`

**Summary:** GET /api/v1/network-segmentation/stats

**Tags:** Network Segmentation

**Auth:** API Key required

**Description:**

Return aggregated segmentation statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 295. `POST` `/api/v1/crypto-keys/`

**Summary:** POST /api/v1/crypto-keys/

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Create a new cryptographic key for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateKeyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | No |  | Human-readable key name |
| `key_type` | str | No | aes256 | Key algorithm: aes256 \| rsa2048 \| rsa4096 \| ecdsa256 \| ed25519 |
| `purpose` | str | No | encryption | Key purpose: encryption \| signing \| authentication |
| `expiry_days` | int | No | 365 | Days until the key expires |
| `tags` | List | No | PydanticUndefined | Arbitrary classification tags |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 296. `GET` `/api/v1/crypto-keys/expiring`

**Summary:** GET /api/v1/crypto-keys/expiring

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Return active keys expiring within the next N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `days_ahead` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 297. `GET` `/api/v1/crypto-keys/stats`

**Summary:** GET /api/v1/crypto-keys/stats

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Return aggregated key statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 298. `GET` `/api/v1/crypto-keys/`

**Summary:** GET /api/v1/crypto-keys/

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

List keys for an org, optionally filtered by key_type and/or purpose.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `key_type` | query | Optional | No | None |
| `purpose` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 299. `GET` `/api/v1/crypto-keys/{key_id}`

**Summary:** GET /api/v1/crypto-keys/{key_id}

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Fetch a single key by ID (org-scoped).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `key_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 300. `POST` `/api/v1/crypto-keys/{key_id}/rotate`

**Summary:** POST /api/v1/crypto-keys/{key_id}/rotate

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Rotate a key: mark old as 'rotating', create new version.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `key_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 301. `POST` `/api/v1/crypto-keys/{key_id}/revoke`

**Summary:** POST /api/v1/crypto-keys/{key_id}/revoke

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Revoke a key with a stated reason.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `key_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeKeyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Reason for revocation |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 302. `POST` `/api/v1/crypto-keys/{key_id}/usage`

**Summary:** POST /api/v1/crypto-keys/{key_id}/usage

**Tags:** Crypto Key Management

**Auth:** API Key required

**Description:**

Record a key usage event for the audit trail.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `key_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RecordUsageRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `usage_type` | str | Yes |  | Type of usage event (e.g. encrypt, decrypt, sign) |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 303. `POST` `/api/v1/certificates/`

**Summary:** POST /api/v1/certificates/

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Register a new certificate for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | No |  | Primary domain / subject CN |
| `issuer` | str | No |  | Certificate Authority name |
| `cert_type` | str | No | ssl | Certificate type: ssl \| code_signing \| client \| ca |
| `expiry_date` | str | No |  | Expiry timestamp in ISO 8601 format (e.g. 2027-01-01T00:00:00+00:00) |
| `san_list` | List | No | PydanticUndefined | Subject Alternative Names |
| `auto_renew` | bool | No | False | Whether to auto-renew before expiry |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 304. `GET` `/api/v1/certificates/expiring`

**Summary:** GET /api/v1/certificates/expiring

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Return non-revoked certificates expiring within the next N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `days_ahead` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 305. `GET` `/api/v1/certificates/stats`

**Summary:** GET /api/v1/certificates/stats

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Return aggregated certificate statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 306. `GET` `/api/v1/certificates/`

**Summary:** GET /api/v1/certificates/

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

List certificates for an org, optionally filtered by cert_type and/or status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `cert_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 307. `GET` `/api/v1/certificates/{cert_id}`

**Summary:** GET /api/v1/certificates/{cert_id}

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Fetch a single certificate by ID (org-scoped).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 308. `POST` `/api/v1/certificates/{cert_id}/renew`

**Summary:** POST /api/v1/certificates/{cert_id}/renew

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Renew a certificate with a new expiry date.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RenewCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `new_expiry_date` | str | Yes |  | New expiry date in ISO 8601 format |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 309. `POST` `/api/v1/certificates/{cert_id}/revoke`

**Summary:** POST /api/v1/certificates/{cert_id}/revoke

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Revoke a certificate with a stated reason.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Reason for revocation |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 310. `GET` `/api/v1/certificates/{cert_id}/renewal-history`

**Summary:** GET /api/v1/certificates/{cert_id}/renewal-history

**Tags:** Certificate Lifecycle

**Auth:** API Key required

**Description:**

Return all renewal records for a certificate.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 311. `POST` `/api/v1/data-lake-security/stores`

**Summary:** Register data store

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Register a data store with classification and security configuration.

**Request Body:** `DataStoreCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  |  |
| `store_type` | str | No | s3 |  |
| `classification` | str | No | internal |  |
| `encryption_at_rest` | bool | No | True |  |
| `access_logging` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 312. `GET` `/api/v1/data-lake-security/stores`

**Summary:** List data stores

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

List data stores with optional classification filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `classification` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 313. `POST` `/api/v1/data-lake-security/stores/{store_id}/assess`

**Summary:** Run security assessment

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Run a security assessment on a data store. Returns findings and score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `store_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 314. `POST` `/api/v1/data-lake-security/stores/{store_id}/access`

**Summary:** Record access pattern

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Record an access event for a data store.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `store_id` | path | str | Yes | — |

**Request Body:** `AccessPatternCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `user_or_role` | str | No |  |  |
| `access_type` | str | No | read |  |
| `bytes_accessed` | int | No | 0 |  |
| `is_anomalous` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 315. `GET` `/api/v1/data-lake-security/stores/{store_id}/access`

**Summary:** Get access patterns

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Return recent access patterns for a data store.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `store_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 316. `GET` `/api/v1/data-lake-security/stores/{store_id}/exfil-risk`

**Summary:** Detect data exfiltration risk

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Compute data exfiltration risk score and indicators.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `store_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 317. `GET` `/api/v1/data-lake-security/stats`

**Summary:** Data lake security stats

**Tags:** Data Lake Security

**Auth:** API Key required

**Description:**

Return aggregate data lake security statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 318. `POST` `/api/v1/mdm/devices`

**Summary:** POST /api/v1/mdm/devices

**Tags:** mdm

**Auth:** API Key required

**Description:**

Enroll a new device into MDM.

**Request Body:** `EnrollDeviceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `name` | str | Yes |  | Device display name |
| `platform` | str | Yes |  | Device platform: ios/android/windows/macos |
| `serial_number` | str | No |  | Device serial number |
| `os_version` | str | No |  | Operating system version |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 319. `GET` `/api/v1/mdm/devices`

**Summary:** GET /api/v1/mdm/devices

**Tags:** mdm

**Auth:** API Key required

**Description:**

List enrolled devices with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `platform` | query | Optional | No | Filter by platform |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 320. `GET` `/api/v1/mdm/devices/{device_id}`

**Summary:** GET /api/v1/mdm/devices/{device_id}

**Tags:** mdm

**Auth:** API Key required

**Description:**

Get a single device by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 321. `PUT` `/api/v1/mdm/devices/{device_id}/compliance`

**Summary:** PUT /api/v1/mdm/devices/{device_id}/compliance

**Tags:** mdm

**Auth:** API Key required

**Description:**

Update compliance score and issues for a device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |

**Request Body:** `UpdateComplianceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `compliance_score` | int | Yes |  | Compliance score 0-100 |
| `issues` | List | No | PydanticUndefined | List of compliance issues |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 322. `POST` `/api/v1/mdm/devices/{device_id}/wipe`

**Summary:** POST /api/v1/mdm/devices/{device_id}/wipe

**Tags:** mdm

**Auth:** API Key required

**Description:**

Initiate a remote wipe for a device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |

**Request Body:** `WipeDeviceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `reason` | str | Yes |  | Reason for remote wipe |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 323. `GET` `/api/v1/mdm/summary`

**Summary:** GET /api/v1/mdm/summary

**Tags:** mdm

**Auth:** API Key required

**Description:**

Get compliance summary: totals by platform and status, average score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 324. `POST` `/api/v1/access-control/policies`

**Summary:** POST /api/v1/access-control/policies

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Create a new access control policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateAccessPolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Policy name |
| `resource_type` | str | Yes |  | file \| api \| database \| network \| application \| service |
| `action` | str | Yes |  | read \| write \| execute \| delete \| admin |
| `effect` | str | No | allow | allow \| deny |
| `conditions` | Optional | No | None | Optional policy conditions |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 325. `GET` `/api/v1/access-control/policies`

**Summary:** GET /api/v1/access-control/policies

**Tags:** Access Control

**Auth:** API Key required

**Description:**

List access policies, optionally filtered by resource_type or effect.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `resource_type` | query | Optional | No | None |
| `effect` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 326. `GET` `/api/v1/access-control/policies/{policy_id}`

**Summary:** GET /api/v1/access-control/policies/{policy_id}

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Get a specific access policy by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 327. `POST` `/api/v1/access-control/grants`

**Summary:** POST /api/v1/access-control/grants

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Grant access to a subject for a resource.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `GrantAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `subject_id` | str | Yes |  | User or group receiving access |
| `resource_id` | str | Yes |  | Resource being accessed |
| `policy_id` | str | Yes |  | Policy governing this grant |
| `granted_by` | str | Yes |  | User granting access |
| `expires_at` | Optional | No | None | ISO expiry timestamp (optional) |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 328. `GET` `/api/v1/access-control/grants`

**Summary:** GET /api/v1/access-control/grants

**Tags:** Access Control

**Auth:** API Key required

**Description:**

List grants, optionally filtered by subject or resource.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `subject_id` | query | Optional | No | None |
| `resource_id` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 329. `PUT` `/api/v1/access-control/grants/{grant_id}/revoke`

**Summary:** PUT /api/v1/access-control/grants/{grant_id}/revoke

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Revoke an active access grant.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `grant_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `revoked_by` | str | Yes |  | User revoking access |
| `reason` | str | No |  | Reason for revocation |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 330. `GET` `/api/v1/access-control/check`

**Summary:** GET /api/v1/access-control/check

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Check active grants for a subject+resource pair.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `subject_id` | query | str | Yes | Subject to check |
| `resource_id` | query | str | Yes | Resource to check |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 331. `GET` `/api/v1/access-control/stats`

**Summary:** GET /api/v1/access-control/stats

**Tags:** Access Control

**Auth:** API Key required

**Description:**

Return access control overview stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 332. `POST` `/api/v1/wireless-security/access-points`

**Summary:** POST /api/v1/wireless-security/access-points

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

Register a new wireless access point.

**Request Body:** `RegisterAPRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  | Access point name |
| `band` | str | Yes |  | Frequency band: 2.4ghz, 5ghz, 6ghz, dual_band |
| `security_protocol` | str | No | wpa2 | Security protocol: open, wep, wpa, wpa2, wpa3 |
| `ssid` | Optional | No | None |  |
| `bssid` | Optional | No | None |  |
| `location` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 333. `GET` `/api/v1/wireless-security/access-points`

**Summary:** GET /api/v1/wireless-security/access-points

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

List wireless access points.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `band` | query | Optional | No | None |
| `security_protocol` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 334. `GET` `/api/v1/wireless-security/access-points/{ap_id}`

**Summary:** GET /api/v1/wireless-security/access-points/{ap_id}

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

Get a single access point by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `ap_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 335. `POST` `/api/v1/wireless-security/threats`

**Summary:** POST /api/v1/wireless-security/threats

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

Record a wireless threat event.

**Request Body:** `RecordThreatRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `threat_type` | str | Yes |  | Type: rogue_ap, evil_twin, deauth_attack, krack, pmkid, wardriving, eavesdropping |
| `severity` | str | Yes |  | Severity: low, medium, high, critical |
| `ap_id` | Optional | No | None |  |
| `bssid` | Optional | No | None |  |
| `description` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 336. `GET` `/api/v1/wireless-security/threats`

**Summary:** GET /api/v1/wireless-security/threats

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

List wireless threats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `threat_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 337. `PUT` `/api/v1/wireless-security/threats/{threat_id}/resolve`

**Summary:** PUT /api/v1/wireless-security/threats/{threat_id}/resolve

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

Resolve a wireless threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |

**Request Body:** `ResolveThreatRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `resolution` | str | Yes |  | Resolution description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 338. `GET` `/api/v1/wireless-security/stats`

**Summary:** GET /api/v1/wireless-security/stats

**Tags:** Wireless Security

**Auth:** API Key required

**Description:**

Get wireless security stats for org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 339. `POST` `/api/v1/nac/endpoints`

**Summary:** POST /api/v1/nac/endpoints

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Register a new network endpoint.

**Request Body:** `RegisterEndpointRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  | Endpoint name |
| `mac_address` | str | Yes |  | MAC address (required) |
| `ip_address` | Optional | No | None |  |
| `device_type` | str | No | workstation | workstation/laptop/server/mobile/iot/printer/other |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 340. `GET` `/api/v1/nac/endpoints`

**Summary:** GET /api/v1/nac/endpoints

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

List network endpoints.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_type` | query | Optional | No | None |
| `nac_status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 341. `GET` `/api/v1/nac/endpoints/{endpoint_id}`

**Summary:** GET /api/v1/nac/endpoints/{endpoint_id}

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Get a single endpoint by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `endpoint_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 342. `POST` `/api/v1/nac/endpoints/{endpoint_id}/assess-posture`

**Summary:** POST /api/v1/nac/endpoints/{endpoint_id}/assess-posture

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Assess endpoint posture from 5 boolean checks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `endpoint_id` | path | str | Yes | — |

**Request Body:** `AssessPostureRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `antivirus` | bool | No | False |  |
| `firewall` | bool | No | False |  |
| `os_patched` | bool | No | False |  |
| `disk_encrypted` | bool | No | False |  |
| `compliant_software` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 343. `PUT` `/api/v1/nac/endpoints/{endpoint_id}/nac-status`

**Summary:** PUT /api/v1/nac/endpoints/{endpoint_id}/nac-status

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Manually update NAC status for an endpoint.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `endpoint_id` | path | str | Yes | — |

**Request Body:** `UpdateNacStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `nac_status` | str | Yes |  | allowed/restricted/quarantined/blocked |
| `reason` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 344. `POST` `/api/v1/nac/policies`

**Summary:** POST /api/v1/nac/policies

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Create a NAC policy.

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  | Policy name |
| `required_posture_score` | int | No | 80 |  |
| `action` | str | No | allow | allow/restrict/quarantine/block |
| `applies_to` | str | No | all | all/workstation/laptop/server/mobile/iot |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 345. `GET` `/api/v1/nac/policies`

**Summary:** GET /api/v1/nac/policies

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

List all NAC policies for org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 346. `GET` `/api/v1/nac/stats`

**Summary:** GET /api/v1/nac/stats

**Tags:** Network Access Control

**Auth:** API Key required

**Description:**

Get NAC stats for org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 347. `POST` `/api/v1/mfa/enrollments`

**Summary:** POST /api/v1/mfa/enrollments

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Create a new MFA enrollment (status=pending).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `EnrollmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `mfa_type` | str | Yes |  |  |
| `backup_codes_count` | int | No | 0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 348. `GET` `/api/v1/mfa/enrollments`

**Summary:** GET /api/v1/mfa/enrollments

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

List MFA enrollments with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `user_id` | query | Optional | No | None |
| `mfa_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 349. `GET` `/api/v1/mfa/enrollments/{enrollment_id}`

**Summary:** GET /api/v1/mfa/enrollments/{enrollment_id}

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Get a single enrollment by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `enrollment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 350. `PUT` `/api/v1/mfa/enrollments/{enrollment_id}/activate`

**Summary:** PUT /api/v1/mfa/enrollments/{enrollment_id}/activate

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Activate a pending MFA enrollment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `enrollment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 351. `PUT` `/api/v1/mfa/enrollments/{enrollment_id}/disable`

**Summary:** PUT /api/v1/mfa/enrollments/{enrollment_id}/disable

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Disable an active MFA enrollment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `enrollment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 352. `POST` `/api/v1/mfa/events`

**Summary:** POST /api/v1/mfa/events

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Record an MFA authentication event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `MFAEventCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `event_type` | str | Yes |  |  |
| `mfa_type` | str | No |  |  |
| `success` | bool | Yes |  |  |
| `ip_address` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 353. `GET` `/api/v1/mfa/events`

**Summary:** GET /api/v1/mfa/events

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

List MFA events with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `user_id` | query | Optional | No | None |
| `event_type` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 354. `POST` `/api/v1/mfa/policies`

**Summary:** POST /api/v1/mfa/policies

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Create an MFA enforcement policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  |  |
| `required_mfa_types` | List | No | [] |  |
| `enforcement` | str | No | optional |  |
| `grace_period_days` | int | No | 7 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 355. `GET` `/api/v1/mfa/policies`

**Summary:** GET /api/v1/mfa/policies

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

List all MFA policies for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 356. `GET` `/api/v1/mfa/stats`

**Summary:** GET /api/v1/mfa/stats

**Tags:** MFA Management

**Auth:** API Key required

**Description:**

Return aggregated MFA statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 357. `POST` `/api/v1/shadow-ai/discover`

**Summary:** POST /api/v1/shadow-ai/discover

**Tags:** Shadow AI

**Auth:** API Key required

**Description:**

Discover shadow AI signals; optionally flag unregistered hits in CMDB.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `DiscoverRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `sources` | Optional | No | None |  |
| `flag_unregistered` | bool | No | False |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 358. `POST` `/api/v1/shadow-ai/register`

**Summary:** POST /api/v1/shadow-ai/register

**Tags:** Shadow AI

**Auth:** API Key required

**Description:**

Register an AI service into the approved registry.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `service_name` | str | Yes |  |  |
| `provider` | str | No |  |  |
| `data_classification` | str | No | internal |  |
| `approved_by` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 359. `GET` `/api/v1/shadow-ai/registry`

**Summary:** GET /api/v1/shadow-ai/registry

**Tags:** Shadow AI

**Auth:** API Key required

**Description:**

List approved AI services for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 360. `POST` `/api/v1/shadow-ai/attack-paths`

**Summary:** POST /api/v1/shadow-ai/attack-paths

**Tags:** Shadow AI

**Auth:** API Key required

**Description:**

Return potential prompt-injection / data-exfiltration paths for a service.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AttackPathsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `service_name` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 361. `GET` `/api/v1/shadow-ai/stats`

**Summary:** GET /api/v1/shadow-ai/stats

**Tags:** Shadow AI

**Auth:** API Key required

**Description:**

Summary stats combining discovery + registry.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 362. `POST` `/api/v1/digital-identity/profiles`

**Summary:** POST /api/v1/digital-identity/profiles

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Create a new identity profile.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ProfileCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `identity_level` | str | No | ial1 |  |
| `verification_method` | str | No | self_asserted |  |
| `assurance_level` | str | No | aal1 |  |
| `attributes` | Dict | No | {} |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 363. `GET` `/api/v1/digital-identity/profiles`

**Summary:** GET /api/v1/digital-identity/profiles

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

List identity profiles with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `verification_status` | query | Optional | No | None |
| `identity_level` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 364. `GET` `/api/v1/digital-identity/profiles/{user_id}`

**Summary:** GET /api/v1/digital-identity/profiles/{user_id}

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Get identity profile by user_id.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 365. `PUT` `/api/v1/digital-identity/profiles/{user_id}/verify`

**Summary:** PUT /api/v1/digital-identity/profiles/{user_id}/verify

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Verify an identity profile.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `VerifyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `verification_method` | str | No | document |  |
| `identity_level` | str | No | ial2 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 366. `PUT` `/api/v1/digital-identity/profiles/{user_id}/suspend`

**Summary:** PUT /api/v1/digital-identity/profiles/{user_id}/suspend

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Suspend an identity profile.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SuspendRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 367. `POST` `/api/v1/digital-identity/events`

**Summary:** POST /api/v1/digital-identity/events

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Record a verification event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `EventCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `event_type` | str | Yes |  |  |
| `outcome` | str | No | pending |  |
| `evidence_type` | str | No |  |  |
| `notes` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 368. `GET` `/api/v1/digital-identity/events/{user_id}`

**Summary:** GET /api/v1/digital-identity/events/{user_id}

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Get verification event history for a user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `limit` | query | int | No | 50 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 369. `POST` `/api/v1/digital-identity/attributes/{user_id}`

**Summary:** POST /api/v1/digital-identity/attributes/{user_id}

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Add an identity attribute for a user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AttributeCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `attribute_name` | str | Yes |  |  |
| `attribute_value` | str | Yes |  |  |
| `verified` | bool | No | False |  |
| `source` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 370. `GET` `/api/v1/digital-identity/attributes/{user_id}`

**Summary:** GET /api/v1/digital-identity/attributes/{user_id}

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

List identity attributes for a user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 371. `GET` `/api/v1/digital-identity/stats`

**Summary:** GET /api/v1/digital-identity/stats

**Tags:** Digital Identity

**Auth:** API Key required

**Description:**

Return aggregated identity statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 372. `POST` `/api/v1/itdr/threats`

**Summary:** POST /api/v1/itdr/threats

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Record a new identity threat detection.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ThreatCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `threat_type` | str | Yes |  |  |
| `user_id` | str | Yes |  |  |
| `source_ip` | str | No |  |  |
| `severity` | str | No | medium |  |
| `confidence` | float | No | 50.0 |  |
| `indicators` | List | No | [] |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 373. `GET` `/api/v1/itdr/threats`

**Summary:** GET /api/v1/itdr/threats

**Tags:** ITDR

**Auth:** API Key required

**Description:**

List identity threats with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `threat_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 374. `GET` `/api/v1/itdr/threats/{threat_id}`

**Summary:** GET /api/v1/itdr/threats/{threat_id}

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Get a single identity threat by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 375. `PUT` `/api/v1/itdr/threats/{threat_id}/status`

**Summary:** PUT /api/v1/itdr/threats/{threat_id}/status

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Update the status of an identity threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ThreatStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `new_status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 376. `POST` `/api/v1/itdr/behaviors`

**Summary:** POST /api/v1/itdr/behaviors

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Record an identity behavior event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BehaviorCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `behavior_type` | str | Yes |  |  |
| `risk_score` | int | No | 50 |  |
| `details` | Dict | No | {} |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 377. `GET` `/api/v1/itdr/behaviors`

**Summary:** GET /api/v1/itdr/behaviors

**Tags:** ITDR

**Auth:** API Key required

**Description:**

List identity behaviors with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `user_id` | query | Optional | No | None |
| `behavior_type` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 378. `POST` `/api/v1/itdr/response-actions`

**Summary:** POST /api/v1/itdr/response-actions

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Create a response action for a threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ResponseActionCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `threat_id` | str | Yes |  |  |
| `action_type` | str | Yes |  |  |
| `notes` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 379. `PUT` `/api/v1/itdr/response-actions/{action_id}/execute`

**Summary:** PUT /api/v1/itdr/response-actions/{action_id}/execute

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Execute a response action.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `action_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 380. `GET` `/api/v1/itdr/response-actions`

**Summary:** GET /api/v1/itdr/response-actions

**Tags:** ITDR

**Auth:** API Key required

**Description:**

List response actions with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `threat_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 381. `GET` `/api/v1/itdr/stats`

**Summary:** GET /api/v1/itdr/stats

**Tags:** ITDR

**Auth:** API Key required

**Description:**

Return aggregated ITDR statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 382. `POST` `/api/v1/pki/certificates`

**Summary:** POST /api/v1/pki/certificates

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Issue a new PKI certificate.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `IssueCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `common_name` | str | Yes |  | Common name (CN) for the certificate |
| `expires_at` | str | Yes |  | ISO expiry timestamp |
| `serial_number` | Optional | No |  | Serial number |
| `issuer` | Optional | No |  | Issuing CA |
| `subject_alt_names` | Optional | No | None | SANs |
| `key_algorithm` | Optional | No | RSA | RSA \| ECDSA \| DSA |
| `key_size` | Optional | No | 2048 | Key size in bits |
| `cert_type` | Optional | No | server | root_ca \| intermediate_ca \| server \| client \| code_signing \| email |
| `status` | Optional | No | active | initial status |
| `issued_at` | Optional | No | None | ISO issued timestamp |
| `auto_renew` | Optional | No | False | Auto-renew flag |
| `actor` | Optional | No | system | Issuing actor |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 383. `GET` `/api/v1/pki/certificates/expiring`

**Summary:** GET /api/v1/pki/certificates/expiring

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

List active certificates expiring within days_ahead days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `days_ahead` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 384. `GET` `/api/v1/pki/certificates`

**Summary:** GET /api/v1/pki/certificates

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

List certificates, optionally filtered by cert_type or status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `cert_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 385. `GET` `/api/v1/pki/certificates/{cert_id}`

**Summary:** GET /api/v1/pki/certificates/{cert_id}

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Get a specific certificate by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 386. `PUT` `/api/v1/pki/certificates/{cert_id}/revoke`

**Summary:** PUT /api/v1/pki/certificates/{cert_id}/revoke

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Revoke a certificate.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `cert_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeCertificateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | No |  | Revocation reason |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 387. `POST` `/api/v1/pki/cas`

**Summary:** POST /api/v1/pki/cas

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Register a certificate authority.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterCARequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | CA name |
| `ca_type` | str | Yes |  | root \| intermediate \| external |
| `subject` | Optional | No |  | CA subject DN |
| `key_algorithm` | Optional | No | RSA | Key algorithm |
| `status` | Optional | No | active | active \| inactive \| compromised |
| `cert_count` | Optional | No | 0 | Certificates issued |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 388. `GET` `/api/v1/pki/cas`

**Summary:** GET /api/v1/pki/cas

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

List certificate authorities.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 389. `GET` `/api/v1/pki/audit-log`

**Summary:** GET /api/v1/pki/audit-log

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Retrieve PKI audit log entries.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `entity_id` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 390. `GET` `/api/v1/pki/stats`

**Summary:** GET /api/v1/pki/stats

**Tags:** PKI Management

**Auth:** API Key required

**Description:**

Return aggregated PKI statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 391. `POST` `/api/v1/cloud-analytics/events`

**Summary:** Record a cloud security event

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Ingest a cloud security event from any supported source.

**Request Body:** `RecordEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `event_source` | str | No | cloudtrail | Cloud event source |
| `event_type` | str | No | api_call | Event type |
| `severity` | str | No | low | Severity: critical/high/medium/low |
| `account_id` | str | No |  | Cloud account ID |
| `region` | str | No |  | Cloud region |
| `resource_type` | str | No |  | Resource type |
| `resource_id` | str | No |  | Resource ID |
| `actor` | str | No |  | Actor (user/role/service) |
| `risk_score` | float | No | 0.0 | Risk score 0-100 |
| `details` | str | No |  | Event details / raw payload |
| `event_at` | Optional | No | None | ISO-8601 event timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 392. `GET` `/api/v1/cloud-analytics/events`

**Summary:** List cloud security events

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

List cloud security events with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `event_source` | query | Optional | No | Filter by event source |
| `severity` | query | Optional | No | Filter by severity |
| `event_type` | query | Optional | No | Filter by event type |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 393. `POST` `/api/v1/cloud-analytics/anomalies`

**Summary:** Record a cloud security anomaly

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Record a detected cloud security anomaly.

**Request Body:** `RecordAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `anomaly_type` | str | No | unusual_api | Anomaly type |
| `severity` | str | No | medium | Severity: critical/high/medium/low |
| `account_id` | str | No |  | Cloud account ID |
| `confidence_score` | float | No | 0.0 | Confidence 0-100 |
| `affected_resources` | List | No | PydanticUndefined | Affected resource IDs |
| `status` | str | No | open | Anomaly status |
| `detected_at` | Optional | No | None | ISO-8601 detection timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 394. `GET` `/api/v1/cloud-analytics/anomalies`

**Summary:** List cloud security anomalies

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

List anomalies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `anomaly_type` | query | Optional | No | Filter by anomaly type |
| `severity` | query | Optional | No | Filter by severity |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 395. `PUT` `/api/v1/cloud-analytics/anomalies/{anomaly_id}/status`

**Summary:** Update anomaly status

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Update the status of a cloud security anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |

**Request Body:** `UpdateAnomalyStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `status` | str | Yes |  | open/investigating/confirmed/false_positive |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 396. `POST` `/api/v1/cloud-analytics/rules`

**Summary:** Create a detection rule

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Create a cloud security detection/compliance/baseline/anomaly rule.

**Request Body:** `CreateRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `rule_name` | str | Yes |  | Rule name |
| `rule_type` | str | No | detection | detection/compliance/baseline/anomaly |
| `condition` | str | No |  | Rule condition expression |
| `severity` | str | No | medium | Severity: critical/high/medium/low |
| `event_sources` | List | No | PydanticUndefined | Applicable event sources |
| `enabled` | bool | No | True | Whether the rule is active |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 397. `GET` `/api/v1/cloud-analytics/rules`

**Summary:** List detection rules

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

List detection rules with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `rule_type` | query | Optional | No | Filter by rule type |
| `enabled` | query | Optional | No | Filter by enabled state |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 398. `PUT` `/api/v1/cloud-analytics/rules/{rule_id}/trigger`

**Summary:** Trigger a detection rule

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Increment match_count for a rule (simulate a rule match).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Request Body:** `TriggerRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 399. `GET` `/api/v1/cloud-analytics/stats`

**Summary:** Get cloud analytics statistics

**Tags:** Cloud Security Analytics

**Auth:** API Key required

**Description:**

Return aggregate cloud security analytics statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 400. `POST` `/api/v1/identity-risk/identities`

**Summary:** POST /api/v1/identity-risk/identities

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Register a new identity.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `IdentityCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | str | No |  |  |
| `email` | str | No |  |  |
| `identity_type` | str | No | human |  |
| `department` | str | No |  |  |
| `risk_score` | float | No | 0.0 |  |
| `mfa_enabled` | bool | No | False |  |
| `last_activity` | Optional | No | None |  |
| `status` | str | No | active |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 401. `GET` `/api/v1/identity-risk/identities`

**Summary:** GET /api/v1/identity-risk/identities

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

List identities with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_type` | query | Optional | No | None |
| `risk_level` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 402. `GET` `/api/v1/identity-risk/identities/{identity_id}`

**Summary:** GET /api/v1/identity-risk/identities/{identity_id}

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Get a single identity by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `identity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 403. `PUT` `/api/v1/identity-risk/identities/{identity_id}/risk-score`

**Summary:** PUT /api/v1/identity-risk/identities/{identity_id}/risk-score

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Update identity risk score (auto-computes risk_level).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `identity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RiskScoreUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `risk_score` | float | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 404. `POST` `/api/v1/identity-risk/risk-factors`

**Summary:** POST /api/v1/identity-risk/risk-factors

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Record a risk factor for an identity.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RiskFactorCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `factor_type` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `score_impact` | float | No | 0.0 |  |
| `description` | str | No |  |  |
| `detected_at` | Optional | No | None |  |
| `status` | str | No | active |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 405. `GET` `/api/v1/identity-risk/risk-factors`

**Summary:** GET /api/v1/identity-risk/risk-factors

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

List risk factors with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 406. `PUT` `/api/v1/identity-risk/risk-factors/{factor_id}/mitigate`

**Summary:** PUT /api/v1/identity-risk/risk-factors/{factor_id}/mitigate

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Mark a risk factor as mitigated.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `factor_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 407. `POST` `/api/v1/identity-risk/access-reviews`

**Summary:** POST /api/v1/identity-risk/access-reviews

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Record an access review decision.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AccessReviewCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `reviewer` | str | Yes |  |  |
| `decision` | str | No | deferred |  |
| `resource` | str | No |  |  |
| `access_level` | str | No |  |  |
| `review_reason` | str | No |  |  |
| `reviewed_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 408. `GET` `/api/v1/identity-risk/access-reviews`

**Summary:** GET /api/v1/identity-risk/access-reviews

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

List access reviews with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_id` | query | Optional | No | None |
| `decision` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 409. `GET` `/api/v1/identity-risk/stats`

**Summary:** GET /api/v1/identity-risk/stats

**Tags:** Identity Risk

**Auth:** API Key required

**Description:**

Return aggregated identity risk statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 410. `POST` `/api/v1/pag/accounts`

**Summary:** POST /api/v1/pag/accounts

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

Register a new privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AccountCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | str | Yes |  |  |
| `account_type` | str | No | service |  |
| `system` | str | No |  |  |
| `owner` | str | No |  |  |
| `justification` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 411. `GET` `/api/v1/pag/accounts`

**Summary:** GET /api/v1/pag/accounts

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

List privileged accounts with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `account_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 412. `GET` `/api/v1/pag/accounts/{account_id}`

**Summary:** GET /api/v1/pag/accounts/{account_id}

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

Get a single privileged account by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 413. `POST` `/api/v1/pag/accounts/{account_id}/sessions`

**Summary:** POST /api/v1/pag/accounts/{account_id}/sessions

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

Record an access session for a privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SessionCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `accessed_by` | str | No |  |  |
| `system` | str | No |  |  |
| `duration_minutes` | int | No | 0 |  |
| `commands_executed` | int | No | 0 |  |
| `justification` | str | No |  |  |
| `approved_by` | str | No |  |  |
| `session_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 414. `GET` `/api/v1/pag/sessions`

**Summary:** GET /api/v1/pag/sessions

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

List access sessions with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `account_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 415. `POST` `/api/v1/pag/accounts/{account_id}/anomalies`

**Summary:** POST /api/v1/pag/accounts/{account_id}/anomalies

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

Flag a behavioral anomaly on a privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `anomaly_type` | str | No | off_hours |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 416. `GET` `/api/v1/pag/anomalies`

**Summary:** GET /api/v1/pag/anomalies

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

List anomalies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `account_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 417. `GET` `/api/v1/pag/stats`

**Summary:** GET /api/v1/pag/stats

**Tags:** Privileged Access Governance

**Auth:** API Key required

**Description:**

Return aggregated privileged access governance statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 418. `POST` `/api/v1/cloud-posture/accounts`

**Summary:** POST /api/v1/cloud-posture/accounts

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

Register a new cloud account for posture tracking.

**Request Body:** `RegisterAccountRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `account_id` | str | Yes |  | Cloud provider account/subscription ID |
| `account_name` | str | No |  | Human-readable account name |
| `provider` | str | No | aws | Cloud provider: aws, azure, gcp, alibaba, oracle, ibm |
| `region` | str | No |  | Primary region |
| `resource_count` | int | No | 0 | Number of resources in account |
| `status` | str | No | active | Account status |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 419. `GET` `/api/v1/cloud-posture/accounts`

**Summary:** GET /api/v1/cloud-posture/accounts

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

List cloud accounts for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 420. `GET` `/api/v1/cloud-posture/accounts/{account_id}`

**Summary:** GET /api/v1/cloud-posture/accounts/{account_id}

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

Get a single cloud account by internal id.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 421. `POST` `/api/v1/cloud-posture/findings`

**Summary:** POST /api/v1/cloud-posture/findings

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

Record a cloud posture finding.

**Request Body:** `RecordFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `cloud_account_id` | str | Yes |  | Internal cloud account id or account_id |
| `resource_id` | str | No |  | Affected resource identifier |
| `resource_type` | str | No | compute | Resource type: iam, storage, compute, network, database, serverless, container |
| `provider` | str | No | aws | Cloud provider |
| `severity` | str | No | medium | Severity: critical, high, medium, low, info |
| `title` | str | No |  | Short finding title |
| `description` | str | No |  | Detailed finding description |
| `remediation` | str | No |  | Remediation steps |
| `notes` | str | No |  | Additional notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 422. `GET` `/api/v1/cloud-posture/findings`

**Summary:** GET /api/v1/cloud-posture/findings

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

List cloud posture findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `resource_type` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 423. `PATCH` `/api/v1/cloud-posture/findings/{finding_id}/status`

**Summary:** PATCH /api/v1/cloud-posture/findings/{finding_id}/status

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

Update the status of a cloud posture finding.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `UpdateFindingStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `status` | str | Yes |  | New status: open, suppressed, resolved, false_positive |
| `notes` | str | No |  | Status update notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 424. `GET` `/api/v1/cloud-posture/stats`

**Summary:** GET /api/v1/cloud-posture/stats

**Tags:** Cloud Posture

**Auth:** API Key required

**Description:**

Return aggregate cloud posture statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 425. `POST` `/api/v1/session-recording/sessions`

**Summary:** POST /api/v1/session-recording/sessions

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

Start a new privileged session recording.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `StartSessionBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user` | str | Yes |  | User initiating the session |
| `session_type` | str | No | ssh | ssh \| rdp \| database \| api \| console \| winrm \| telnet |
| `target_host` | str | Yes |  | Target host name or FQDN |
| `target_ip` | str | No |  | Target IP address |
| `initiated_by` | str | No |  | System or PAM that initiated the session |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 426. `GET` `/api/v1/session-recording/sessions`

**Summary:** GET /api/v1/session-recording/sessions

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

List sessions, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `user` | query | Optional | No | None |
| `session_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 427. `GET` `/api/v1/session-recording/sessions/{session_id}`

**Summary:** GET /api/v1/session-recording/sessions/{session_id}

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

Fetch a single session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 428. `POST` `/api/v1/session-recording/sessions/{session_id}/end`

**Summary:** POST /api/v1/session-recording/sessions/{session_id}/end

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

End a privileged session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `EndSessionBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `duration_seconds` | int | No | 0 | Total session duration in seconds |
| `recording_url` | str | No |  | URL to session recording artifact |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 429. `POST` `/api/v1/session-recording/sessions/{session_id}/alerts`

**Summary:** POST /api/v1/session-recording/sessions/{session_id}/alerts

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

Record an alert for a session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RecordAlertBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `alert_type` | str | Yes |  | suspicious_command \| data_exfiltration \| privilege_escalation \| policy_violation \| anomaly |
| `severity` | str | No | medium | critical \| high \| medium \| low \| info |
| `description` | str | No |  | Alert description |
| `command_context` | str | No |  | Command or context that triggered the alert |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 430. `GET` `/api/v1/session-recording/alerts`

**Summary:** GET /api/v1/session-recording/alerts

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

List alerts, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `session_id` | query | Optional | No | None |
| `alert_type` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `list`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 431. `GET` `/api/v1/session-recording/stats`

**Summary:** GET /api/v1/session-recording/stats

**Tags:** Privileged Session Recording

**Auth:** API Key required

**Description:**

Return aggregate recording stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 432. `POST` `/api/v1/cloud-inventory/resources`

**Summary:** POST /api/v1/cloud-inventory/resources

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Request Body:** `ResourceCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  | Cloud provider resource identifier |
| `resource_name` | str | No |  | Human-readable resource name |
| `provider` | str | No | aws | aws/azure/gcp/alibaba/oracle/ibm/digitalocean |
| `resource_type` | str | No | compute | compute/storage/database/network/iam/container/serverless/cdn/dns/load_balancer |
| `region` | str | No |  | Cloud region |
| `account_id` | str | No |  | Cloud account/subscription ID |
| `tags` | Dict | No | PydanticUndefined | Resource tags |
| `resource_state` | str | No | running | running/stopped/terminated/unknown/pending |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 433. `GET` `/api/v1/cloud-inventory/resources`

**Summary:** GET /api/v1/cloud-inventory/resources

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `provider` | query | Optional | No | Filter by provider |
| `resource_type` | query | Optional | No | Filter by resource_type |
| `compliance_status` | query | Optional | No | Filter by compliance_status |
| `resource_state` | query | Optional | No | Filter by resource_state |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 434. `GET` `/api/v1/cloud-inventory/resources/{resource_id}`

**Summary:** GET /api/v1/cloud-inventory/resources/{resource_id}

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 435. `PATCH` `/api/v1/cloud-inventory/resources/{resource_id}/state`

**Summary:** PATCH /api/v1/cloud-inventory/resources/{resource_id}/state

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Request Body:** `ResourceStateUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `state` | str | Yes |  | running/stopped/terminated/unknown/pending |
| `compliance_status` | Optional | No | None | compliant/non_compliant/unknown/exempt |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 436. `POST` `/api/v1/cloud-inventory/resources/{resource_id}/findings`

**Summary:** POST /api/v1/cloud-inventory/resources/{resource_id}/findings

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organization ID |

**Request Body:** `FindingCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `severity` | str | No | medium | critical/high/medium/low |
| `title` | str | No |  | Finding title |
| `compliance_check` | str | No |  | Compliance control reference |
| `remediation` | str | No |  | Remediation guidance |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 437. `GET` `/api/v1/cloud-inventory/findings`

**Summary:** GET /api/v1/cloud-inventory/findings

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |
| `cloud_resource_id` | query | Optional | No | Filter by resource internal ID |
| `severity` | query | Optional | No | Filter by severity |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 438. `GET` `/api/v1/cloud-inventory/stats`

**Summary:** GET /api/v1/cloud-inventory/stats

**Tags:** cloud-inventory

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 439. `POST` `/api/v1/microsegmentation/segments`

**Summary:** POST /api/v1/microsegmentation/segments

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

Create a microsegment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `SegmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `segment_type` | str | Yes |  |  |
| `cidr_range` | str | No |  |  |
| `description` | str | No |  |  |
| `enforcement_mode` | str | No | monitoring |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 440. `GET` `/api/v1/microsegmentation/segments`

**Summary:** GET /api/v1/microsegmentation/segments

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

List microsegments with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `segment_type` | query | Optional | No | None |
| `enforcement_mode` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 441. `GET` `/api/v1/microsegmentation/segments/{segment_id}`

**Summary:** GET /api/v1/microsegmentation/segments/{segment_id}

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

Get a single microsegment by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `segment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 442. `POST` `/api/v1/microsegmentation/policies`

**Summary:** POST /api/v1/microsegmentation/policies

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

Create a microsegmentation policy between two segments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `src_segment_id` | str | Yes |  |  |
| `dst_segment_id` | str | Yes |  |  |
| `policy_action` | str | No | allow |  |
| `protocol` | str | No | tcp |  |
| `port_range` | str | No |  |  |
| `description` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 443. `GET` `/api/v1/microsegmentation/policies`

**Summary:** GET /api/v1/microsegmentation/policies

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

List policies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `src_segment_id` | query | Optional | No | None |
| `dst_segment_id` | query | Optional | No | None |
| `policy_action` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 444. `POST` `/api/v1/microsegmentation/violations`

**Summary:** POST /api/v1/microsegmentation/violations

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

Record a microsegmentation policy violation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ViolationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `segment_id` | str | Yes |  |  |
| `src_ip` | str | No |  |  |
| `dst_ip` | str | No |  |  |
| `protocol` | str | No | tcp |  |
| `port` | int | No | 0 |  |
| `violation_type` | str | No | blocked_traffic |  |
| `severity` | str | No | medium |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 445. `GET` `/api/v1/microsegmentation/violations`

**Summary:** GET /api/v1/microsegmentation/violations

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

List violations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `segment_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 446. `GET` `/api/v1/microsegmentation/stats`

**Summary:** GET /api/v1/microsegmentation/stats

**Tags:** Microsegmentation Policy

**Auth:** API Key required

**Description:**

Return aggregated microsegmentation statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 447. `POST` `/api/v1/sspm/apps`

**Summary:** POST /api/v1/sspm/apps

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

Register a new SaaS application.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AppCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app_name` | str | Yes |  |  |
| `app_category` | str | Yes |  |  |
| `vendor` | str | No |  |  |
| `user_count` | int | No | 0 |  |
| `data_sensitivity` | str | No |  |  |
| `oauth_scopes` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 448. `GET` `/api/v1/sspm/apps`

**Summary:** GET /api/v1/sspm/apps

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

List SaaS apps with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `app_category` | query | Optional | No | None |
| `risk_level` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 449. `GET` `/api/v1/sspm/apps/{app_id}`

**Summary:** GET /api/v1/sspm/apps/{app_id}

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

Get a single SaaS app by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 450. `POST` `/api/v1/sspm/apps/{app_id}/assess`

**Summary:** POST /api/v1/sspm/apps/{app_id}/assess

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

Conduct a security assessment for a SaaS app.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AssessmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `score` | float | No | 0.0 |  |
| `findings_count` | int | No | 0 |  |
| `assessor` | str | No |  |  |
| `assessment_date` | Optional | No | None |  |
| `notes` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 451. `GET` `/api/v1/sspm/assessments`

**Summary:** GET /api/v1/sspm/assessments

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

List assessments with optional app filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `app_id` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 452. `POST` `/api/v1/sspm/apps/{app_id}/findings`

**Summary:** POST /api/v1/sspm/apps/{app_id}/findings

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

Record a security finding for a SaaS app.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `FindingCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `finding_type` | str | No |  |  |
| `severity` | str | No | medium |  |
| `title` | str | No |  |  |
| `description` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 453. `GET` `/api/v1/sspm/findings`

**Summary:** GET /api/v1/sspm/findings

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

List findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `app_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 454. `GET` `/api/v1/sspm/stats`

**Summary:** GET /api/v1/sspm/stats

**Tags:** SaaS Security Posture

**Auth:** API Key required

**Description:**

Return aggregated SSPM statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 455. `POST` `/api/v1/cloud-accounts/accounts`

**Summary:** POST /api/v1/cloud-accounts/accounts

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Register a new cloud account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AccountRegister`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  |  |
| `account_name` | str | Yes |  |  |
| `provider` | str | Yes |  |  |
| `region` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 456. `GET` `/api/v1/cloud-accounts/accounts`

**Summary:** GET /api/v1/cloud-accounts/accounts

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

List cloud accounts with optional provider/status filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 457. `GET` `/api/v1/cloud-accounts/accounts/{account_id}`

**Summary:** GET /api/v1/cloud-accounts/accounts/{account_id}

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Get a cloud account with its recent events.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 458. `POST` `/api/v1/cloud-accounts/accounts/{account_id}/scan`

**Summary:** POST /api/v1/cloud-accounts/accounts/{account_id}/scan

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Update scan results for a cloud account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ScanUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `findings_count` | int | Yes |  |  |
| `risk_score` | float | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 459. `POST` `/api/v1/cloud-accounts/accounts/{account_id}/events`

**Summary:** POST /api/v1/cloud-accounts/accounts/{account_id}/events

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Record a security event for a cloud account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `EventCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `event_type` | str | Yes |  |  |
| `severity` | str | Yes |  |  |
| `resource` | str | No |  |  |
| `description` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 460. `POST` `/api/v1/cloud-accounts/accounts/{account_id}/events/{event_id}/resolve`

**Summary:** POST /api/v1/cloud-accounts/accounts/{account_id}/events/{event_id}/resolve

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Resolve a security event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `event_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 461. `GET` `/api/v1/cloud-accounts/events/unresolved`

**Summary:** GET /api/v1/cloud-accounts/events/unresolved

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Get unresolved events, optionally filtered by severity.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 462. `POST` `/api/v1/cloud-accounts/policies`

**Summary:** POST /api/v1/cloud-accounts/policies

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Create an account security policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  |  |
| `policy_type` | str | Yes |  |  |
| `scope` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 463. `POST` `/api/v1/cloud-accounts/policies/{policy_id}/evaluate`

**Summary:** POST /api/v1/cloud-accounts/policies/{policy_id}/evaluate

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Evaluate a policy and update its violation count.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `PolicyEvaluate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `violation_count` | int | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 464. `GET` `/api/v1/cloud-accounts/risk-summary`

**Summary:** GET /api/v1/cloud-accounts/risk-summary

**Tags:** Cloud Account Monitoring

**Auth:** API Key required

**Description:**

Return per-provider risk summary.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 465. `POST` `/api/v1/cloud-findings/findings`

**Summary:** Ingest a cloud security finding (dedup on open findings)

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `IngestFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `provider` | str | Yes |  | aws/azure/gcp/alibaba/oci/ibm |
| `account_id` | str | Yes |  | Cloud account/subscription ID |
| `region` | str | No |  | Cloud region |
| `resource_type` | str | No |  | Resource type (e.g. s3, vm) |
| `resource_id` | str | Yes |  | Resource identifier |
| `finding_title` | str | Yes |  | Short finding title |
| `finding_type` | str | No | misconfiguration | misconfiguration/vulnerability/compliance/threat/exposure |
| `severity` | str | Yes |  | critical/high/medium/low/informational |
| `cvss_score` | float | No | 0.0 | CVSS score 0-10 |
| `remediation` | str | No |  | Remediation guidance |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 466. `POST` `/api/v1/cloud-findings/findings/bulk`

**Summary:** Bulk ingest cloud findings

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `BulkIngestRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `findings` | List | Yes |  | List of finding dicts |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 467. `PUT` `/api/v1/cloud-findings/findings/{finding_id}/resolve`

**Summary:** Resolve a finding

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `ResolveRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 468. `POST` `/api/v1/cloud-findings/findings/{finding_id}/suppress`

**Summary:** Suppress a finding

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `SuppressRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `suppressed_by` | str | Yes |  | Who suppressed |
| `reason` | str | Yes |  | Suppression reason |
| `expires_at` | str | No |  | ISO-8601 expiry (optional) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 469. `POST` `/api/v1/cloud-findings/findings/{finding_id}/remediation`

**Summary:** Assign remediation for a finding

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `AssignRemediationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `assignee` | str | Yes |  | Assigned engineer/team |
| `due_date` | str | Yes |  | ISO-8601 due date |
| `notes` | str | No |  | Additional notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 470. `PUT` `/api/v1/cloud-findings/remediation/{remediation_id}`

**Summary:** Update remediation status

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `remediation_id` | path | str | Yes | — |

**Request Body:** `UpdateRemediationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `status` | str | Yes |  | assigned/in_progress/completed/cancelled |
| `notes` | str | No |  | Updated notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 471. `GET` `/api/v1/cloud-findings/findings`

**Summary:** List findings with optional filters

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 472. `GET` `/api/v1/cloud-findings/summary`

**Summary:** Get finding summary stats

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 473. `GET` `/api/v1/cloud-findings/top-resources`

**Summary:** Top resources by finding count

**Tags:** Cloud Security Findings

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `limit` | query | int | No | 10 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 474. `POST` `/api/v1/ciem-ad/least-privilege/{identity_id}`

**Summary:** CIEM least-privilege recommendation for a specific identity

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Return current perms, unused perms over the window, and right-sized policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `identity_id` | path | str | Yes | — |

**Request Body:** `LeastPrivilegeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organization identifier |
| `current_permissions` | Optional | No | None | Permissions currently granted to the identity |
| `used_permissions` | Optional | No | None | Permissions actually used (explicit) |
| `usage_log` | Optional | No | None | Usage log rows [{action, timestamp}] — actions in the last window_days are used |
| `window_days` | int | No | 90 | Look-back window in days |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 475. `POST` `/api/v1/ciem-ad/ad-risks`

**Summary:** Evaluate all AD/Entra risk predicates against a set of AD objects

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Runs kerberoastable, DCSync, adminCount mismatch, unconstrained delegation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ADRisksRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ad_objects` | List | Yes |  | List of AD/Entra object dicts (sAMAccountName, SPN, memberOf, uac, adminCount, ...) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 476. `GET` `/api/v1/ciem-ad/ad-risks`

**Summary:** Empty default evaluation (stats-only)

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Return empty-evaluation shape — useful as a smoke endpoint.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 477. `GET` `/api/v1/ciem-ad/standing-privilege`

**Summary:** Detect standing privilege + produce JIT recommendations

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Combined output of detect_standing_privilege + just_in_time_recommendations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `stale_days` | query | int | No | 30 |
| `lookback_days` | query | int | No | 30 |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 478. `POST` `/api/v1/ciem-ad/itdr/detect`

**Summary:** Run ITDR AD-specific detection rules (ESC1, ESC4, Golden/Skeleton ticket)

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Evaluate ADCS template + Kerberos/LSASS auth events for AD-specific attacks.

**Request Body:** `ITDRDetectRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organization identifier |
| `templates` | Optional | No | None | ADCS certificate templates (for ESC1/ESC4) |
| `auth_events` | Optional | No | None | Kerberos/LSASS auth events (for Golden/Skeleton ticket) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 479. `POST` `/api/v1/ciem-ad/attack-path`

**Summary:** Build AD attack path from start_identity to target

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Chains kerberoastable -> cracked -> admin_count -> domain_admin by default.

**Request Body:** `AttackPathRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organization identifier |
| `start_identity` | str | Yes |  | Starting principal |
| `target` | str | No | domain_admin | Target principal/role |
| `graph` | Optional | No | None | Optional adjacency map — uses canonical chain if omitted |
| `max_hops` | int | No | 8 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 480. `GET` `/api/v1/ciem-ad/stats`

**Summary:** Aggregated CIEM+AD stats across the 5 merged engines

**Tags:** CIEM+AD Attack Paths

**Auth:** API Key required

**Description:**

Cross-engine summary. Never raises — missing DBs yield zero counters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 481. `POST` `/api/v1/privileged-identity/accounts`

**Summary:** POST /api/v1/privileged-identity/accounts

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Register a privileged account (deduped on org+username+system).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterAccountBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | str | Yes |  | Account username |
| `account_type` | str | No | admin | service_account \| admin \| root \| domain_admin \| database_admin \| application_account \| shared |
| `system_name` | str | No |  | Target system name |
| `department` | str | No |  | Owning department |
| `owner` | str | No |  | Account owner |
| `mfa_enabled` | bool | No | False | MFA status |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 482. `PUT` `/api/v1/privileged-identity/accounts/{account_id}/risk`

**Summary:** PUT /api/v1/privileged-identity/accounts/{account_id}/risk

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Override the risk level of a privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdateRiskBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `risk_level` | str | Yes |  | critical \| high \| medium \| low |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 483. `POST` `/api/v1/privileged-identity/sessions`

**Summary:** POST /api/v1/privileged-identity/sessions

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Open a new privileged session.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `OpenSessionBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  | Privileged account ID |
| `session_type` | str | No | ssh | ssh \| rdp \| database \| api \| console \| jump_host |
| `target_system` | str | No |  | Target system hostname/IP |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 484. `PUT` `/api/v1/privileged-identity/sessions/{session_id}/close`

**Summary:** PUT /api/v1/privileged-identity/sessions/{session_id}/close

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Close a privileged session and record metrics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `session_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `CloseSessionBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `commands_executed` | int | No | 0 | Number of commands run |
| `anomaly_score` | float | No | 0.0 | Anomaly score 0.0-10.0 (clamped) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 485. `POST` `/api/v1/privileged-identity/accounts/{account_id}/certify`

**Summary:** POST /api/v1/privileged-identity/accounts/{account_id}/certify

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Certify a privileged account (approved / revoked / suspended).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `CertifyAccountBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `certified_by` | str | Yes |  | Certifier user ID |
| `decision` | str | Yes |  | approved \| revoked \| suspended |
| `justification` | str | No |  | Certification justification |
| `next_certification` | str | No |  | Next certification date ISO |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 486. `PUT` `/api/v1/privileged-identity/accounts/{account_id}/rotate`

**Summary:** PUT /api/v1/privileged-identity/accounts/{account_id}/rotate

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Record a password rotation for a privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 487. `GET` `/api/v1/privileged-identity/summary`

**Summary:** GET /api/v1/privileged-identity/summary

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Return aggregate summary for privileged accounts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 488. `GET` `/api/v1/privileged-identity/high-risk`

**Summary:** GET /api/v1/privileged-identity/high-risk

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Return critical and high risk privileged accounts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 489. `GET` `/api/v1/privileged-identity/sessions/active`

**Summary:** GET /api/v1/privileged-identity/sessions/active

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Return active privileged sessions with account details.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 490. `GET` `/api/v1/privileged-identity/accounts/{account_id}/sessions`

**Summary:** GET /api/v1/privileged-identity/accounts/{account_id}/sessions

**Tags:** Privileged Identity Management

**Auth:** API Key required

**Description:**

Return session history for a privileged account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `limit` | query | int | No | 20 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 491. `GET` `/api/v1/identity-lifecycle/`

**Summary:** GET /api/v1/identity-lifecycle/

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Get identity lifecycle entitlement summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 492. `POST` `/api/v1/identity-lifecycle/accounts`

**Summary:** POST /api/v1/identity-lifecycle/accounts

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Provision a new identity account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ProvisionAccountBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | str | Yes |  | Unique username for the account |
| `display_name` | str | No |  | Human-readable display name |
| `email` | str | No |  | Email address |
| `account_type` | str | No | employee | employee \| contractor \| service \| system \| bot \| vendor \| temp |
| `department` | str | No |  | Department or team |
| `manager` | str | No |  | Manager username or ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 493. `GET` `/api/v1/identity-lifecycle/accounts`

**Summary:** GET /api/v1/identity-lifecycle/accounts

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

List identity accounts, optionally filtered by status and department.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |
| `department` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 494. `GET` `/api/v1/identity-lifecycle/accounts/{account_id}`

**Summary:** GET /api/v1/identity-lifecycle/accounts/{account_id}

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Fetch a single account with events and active entitlements.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 495. `POST` `/api/v1/identity-lifecycle/accounts/{account_id}/deprovision`

**Summary:** POST /api/v1/identity-lifecycle/accounts/{account_id}/deprovision

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Deprovision an account and revoke all entitlements.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DeprovisionBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `performed_by` | str | No |  | User performing the action |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 496. `POST` `/api/v1/identity-lifecycle/accounts/{account_id}/suspend`

**Summary:** POST /api/v1/identity-lifecycle/accounts/{account_id}/suspend

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Suspend an identity account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SuspendBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `performed_by` | str | No |  | User performing the action |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 497. `POST` `/api/v1/identity-lifecycle/accounts/{account_id}/reactivate`

**Summary:** POST /api/v1/identity-lifecycle/accounts/{account_id}/reactivate

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Reactivate a suspended or deprovisioned account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ReactivateBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `performed_by` | str | No |  | User performing the action |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 498. `POST` `/api/v1/identity-lifecycle/accounts/{account_id}/access`

**Summary:** POST /api/v1/identity-lifecycle/accounts/{account_id}/access

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Grant a system access entitlement to an account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `account_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `GrantAccessBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `system_name` | str | Yes |  | Target system name |
| `role` | str | Yes |  | Role to grant |
| `access_level` | str | No | read | read \| write \| admin \| owner |
| `expires_at` | str | No |  | ISO datetime for expiry (empty = never) |
| `granted_by` | str | No |  | Approver username or ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 499. `POST` `/api/v1/identity-lifecycle/entitlements/{entitlement_id}/revoke`

**Summary:** POST /api/v1/identity-lifecycle/entitlements/{entitlement_id}/revoke

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Revoke a specific access entitlement.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entitlement_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeEntitlementBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `performed_by` | str | No |  | User performing revocation |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 500. `GET` `/api/v1/identity-lifecycle/orphans`

**Summary:** GET /api/v1/identity-lifecycle/orphans

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Return active accounts inactive for >= days_inactive days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `days_inactive` | query | int | No | Inactivity threshold in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 501. `GET` `/api/v1/identity-lifecycle/summary`

**Summary:** GET /api/v1/identity-lifecycle/summary

**Tags:** Identity Lifecycle

**Auth:** API Key required

**Description:**

Return aggregate identity and entitlement summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 502. `GET` `/api/v1/access-anomaly/`

**Summary:** GET /api/v1/access-anomaly/

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

Get access anomaly summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 503. `POST` `/api/v1/access-anomaly/events`

**Summary:** POST /api/v1/access-anomaly/events

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `EventCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `username` | str | Yes |  |  |
| `source_ip` | str | No |  |  |
| `country` | str | No |  |  |
| `city` | str | No |  |  |
| `access_time` | Optional | No | None |  |
| `resource` | str | No |  |  |
| `action` | str | No |  |  |
| `success` | int | No | 1 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 504. `POST` `/api/v1/access-anomaly/events/{event_id}/detect-anomalies`

**Summary:** POST /api/v1/access-anomaly/events/{event_id}/detect-anomalies

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `event_id` | path | str | Yes | — |

**Request Body:** `DetectAnomaliesRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `username` | str | Yes |  |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 505. `POST` `/api/v1/access-anomaly/baseline`

**Summary:** POST /api/v1/access-anomaly/baseline

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `BaselineUpsert`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `username` | str | Yes |  |  |
| `typical_countries` | List | No | [] |  |
| `typical_hours` | List | No | [] |  |
| `typical_resources` | List | No | [] |  |
| `avg_daily_events` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 506. `POST` `/api/v1/access-anomaly/impossible-travel/{username}`

**Summary:** POST /api/v1/access-anomaly/impossible-travel/{username}

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `username` | path | str | Yes | — |

**Request Body:** `ImpossibleTravelRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `hours_window` | float | No | 4.0 |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 507. `POST` `/api/v1/access-anomaly/anomalies/{anomaly_id}/resolve`

**Summary:** POST /api/v1/access-anomaly/anomalies/{anomaly_id}/resolve

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |

**Request Body:** `ResolveRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 508. `GET` `/api/v1/access-anomaly/anomalies`

**Summary:** GET /api/v1/access-anomaly/anomalies

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |
| `anomaly_type` | query | Optional | No | None |
| `username` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 509. `GET` `/api/v1/access-anomaly/users/{username}/profile`

**Summary:** GET /api/v1/access-anomaly/users/{username}/profile

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `username` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 510. `GET` `/api/v1/access-anomaly/high-risk-users`

**Summary:** GET /api/v1/access-anomaly/high-risk-users

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `min_anomaly_count` | query | int | No | 3 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 511. `GET` `/api/v1/access-anomaly/summary`

**Summary:** GET /api/v1/access-anomaly/summary

**Tags:** Access Anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 512. `GET` `/api/v1/cost-optimization/`

**Summary:** GET /api/v1/cost-optimization/

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Get cloud cost optimization portfolio summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 513. `POST` `/api/v1/cost-optimization/tools`

**Summary:** POST /api/v1/cost-optimization/tools

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Register a new security tool for cost tracking.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ToolCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tool_name` | str | Yes |  |  |
| `tool_category` | str | No | detection |  |
| `vendor` | str | No |  |  |
| `cloud_provider` | str | No | multi-cloud |  |
| `monthly_cost` | float | No | 0.0 |  |
| `licenses` | int | No | 0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 514. `GET` `/api/v1/cost-optimization/tools`

**Summary:** GET /api/v1/cost-optimization/tools

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

List all security tools for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 515. `GET` `/api/v1/cost-optimization/tools/{tool_id}/roi`

**Summary:** GET /api/v1/cost-optimization/tools/{tool_id}/roi

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Return tool ROI details with assessments and optimizations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `tool_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 516. `PATCH` `/api/v1/cost-optimization/tools/{tool_id}/utilization`

**Summary:** PATCH /api/v1/cost-optimization/tools/{tool_id}/utilization

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Update tool utilization percentage and risk coverage.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `tool_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UtilizationUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `utilization_pct` | float | Yes |  |  |
| `risk_coverage` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 517. `POST` `/api/v1/cost-optimization/tools/{tool_id}/optimizations`

**Summary:** POST /api/v1/cost-optimization/tools/{tool_id}/optimizations

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Identify a cost optimization opportunity for a tool.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `tool_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `OptimizationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `optimization_type` | str | Yes |  |  |
| `description` | str | No |  |  |
| `estimated_savings` | float | No | 0.0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 518. `POST` `/api/v1/cost-optimization/optimizations/{optimization_id}/implement`

**Summary:** POST /api/v1/cost-optimization/optimizations/{optimization_id}/implement

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Mark an optimization as implemented with actual savings.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `optimization_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ImplementOptimization`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `actual_savings` | float | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 519. `POST` `/api/v1/cost-optimization/tools/{tool_id}/roi-assessment`

**Summary:** POST /api/v1/cost-optimization/tools/{tool_id}/roi-assessment

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Add a ROI assessment for a security tool.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `tool_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ROIAssessmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `assessment_period` | str | Yes |  |  |
| `incidents_prevented` | int | No | 0 |  |
| `avg_incident_cost` | float | No | 0.0 |  |
| `risk_reduction_pct` | float | No | 0.0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 520. `GET` `/api/v1/cost-optimization/underutilized`

**Summary:** GET /api/v1/cost-optimization/underutilized

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Return active tools with low utilization.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `max_utilization` | query | float | No | 30.0 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 521. `GET` `/api/v1/cost-optimization/portfolio`

**Summary:** GET /api/v1/cost-optimization/portfolio

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Return aggregate portfolio cost summary.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 522. `GET` `/api/v1/cost-optimization/cost-per-risk`

**Summary:** GET /api/v1/cost-optimization/cost-per-risk

**Tags:** Cloud Cost Optimization

**Auth:** API Key required

**Description:**

Return cost per risk reduction percentage, ordered ASC.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 523. `POST` `/api/v1/cloud-connectors/accounts`

**Summary:** Register cloud account credentials

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Register credentials for a cloud provider account.  Validates the credentials structurally before
storing. Secrets are stored in memory (and optionally in a JSON file if the engine was initialised
with a persist_path).

**Request Body:** `RegisterCredentialsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  | Cloud provider: aws \| azure \| gcp |
| `account_id` | str | Yes |  | AWS account ID / Azure subscription / GCP project |
| `label` | str | No | default | Human-readable label |
| `aws_access_key_id` | Optional | No | None | AWS access key ID |
| `aws_secret_access_key` | Optional | No | None | AWS secret access key |
| `aws_role_arn` | Optional | No | None | AWS IAM role ARN for assume-role |
| `aws_region` | str | No | us-east-1 | AWS region |
| `aws_session_token` | Optional | No | None | AWS temporary session token |
| `azure_tenant_id` | Optional | No | None | Azure AD tenant ID |
| `azure_client_id` | Optional | No | None | Azure service principal client ID |
| `azure_client_secret` | Optional | No | None | Azure service principal secret |
| `azure_subscription_id` | Optional | No | None | Azure subscription ID |
| `gcp_service_account_json` | Optional | No | None | GCP service account JSON (raw string) |
| `gcp_project_id` | Optional | No | None | GCP project ID |

**Responses:**

**200 OK** — `RegisterCredentialsResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ok` | bool | Yes |  |  |
| `message` | str | Yes |  |  |
| `provider` | str | Yes |  |  |
| `account_id` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 524. `DELETE` `/api/v1/cloud-connectors/accounts/{provider}/{account_id}`

**Summary:** Remove registered cloud account

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Remove stored credentials for a cloud account.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | path | str | Yes | — |
| `account_id` | path | str | Yes | — |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 525. `GET` `/api/v1/cloud-connectors/accounts`

**Summary:** List registered cloud accounts

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

List all registered cloud accounts with secrets masked.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | Optional | No | Filter by provider: aws \| azure \| gcp |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 526. `GET` `/api/v1/cloud-connectors/accounts/health`

**Summary:** Connector health for all or filtered accounts

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Return health metrics (last sync, errors, quota) for cloud connectors.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | Optional | No | Filter by provider |
| `account_id` | query | Optional | No | Filter by account ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 527. `POST` `/api/v1/cloud-connectors/accounts/{provider}/{account_id}/validate`

**Summary:** Validate cloud account credentials

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Test live connectivity for the stored credentials.  Makes a real API call (STS GetCallerIdentity for
AWS, token fetch for Azure, etc.). Returns ok=False when credentials are invalid or expired.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | path | str | Yes | — |
| `account_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `ValidateResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ok` | bool | Yes |  |  |
| `message` | str | Yes |  |  |
| `provider` | str | Yes |  |  |
| `account_id` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 528. `GET` `/api/v1/cloud-connectors/resources`

**Summary:** List cloud resources (normalized)

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Return cloud resources normalized to the unified CloudResource schema.  Falls back to stub data when
cloud credentials are not configured or API calls fail (mirrors the AWS Security Hub router
pattern).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | str | Yes | Cloud provider: aws \| azure \| gcp |
| `account_id` | query | str | Yes | Account / subscription / project ID |
| `resource_type` | query | Optional | No | Filter: compute\|storage\|network\|database\|iam\|container\|serverless |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 529. `GET` `/api/v1/cloud-connectors/findings`

**Summary:** List cloud security findings (normalized)

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Pull and normalize security findings from: - AWS Security Hub (ASFF format) - Azure Defender for
Cloud - GCP Security Command Center

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | str | Yes | Cloud provider: aws \| azure \| gcp |
| `account_id` | query | str | Yes | Account / subscription / project ID |
| `severity` | query | Optional | No | Filter: critical\|high\|medium\|low\|info |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 530. `GET` `/api/v1/cloud-connectors/posture`

**Summary:** Get cloud security posture report

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Return a security posture summary: score, control pass/fail, findings breakdown by severity, and
compliance framework coverage.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | str | Yes | Cloud provider: aws \| azure \| gcp |
| `account_id` | query | str | Yes | Account / subscription / project ID |

**Responses:**

**200 OK** — `PostureResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  |  |
| `account_id` | str | Yes |  |  |
| `region` | Optional | No | None |  |
| `score` | float | Yes |  |  |
| `total_controls` | int | Yes |  |  |
| `passed_controls` | int | Yes |  |  |
| `failed_controls` | int | Yes |  |  |
| `critical_findings` | int | Yes |  |  |
| `high_findings` | int | Yes |  |  |
| `medium_findings` | int | Yes |  |  |
| `low_findings` | int | Yes |  |  |
| `frameworks` | List | No | PydanticUndefined |  |
| `generated_at` | str | Yes |  |  |
| `details` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 531. `POST` `/api/v1/cloud-connectors/sync`

**Summary:** Trigger full sync for one cloud account

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Trigger a synchronous resource + finding sync for a single cloud account.  Returns a SyncResult with
counts and timing. Use /sync/organization to sync all accounts for a provider in one call.

**Request Body:** `SyncRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  | Cloud provider: aws \| azure \| gcp |
| `account_id` | str | Yes |  | Account to sync |

**Responses:**

**200 OK** — `SyncResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `sync_id` | str | Yes |  |  |
| `provider` | str | Yes |  |  |
| `account_id` | str | Yes |  |  |
| `started_at` | str | Yes |  |  |
| `completed_at` | Optional | No | None |  |
| `status` | str | Yes |  |  |
| `resources_found` | int | No | 0 |  |
| `findings_found` | int | No | 0 |  |
| `error` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 532. `POST` `/api/v1/cloud-connectors/sync/organization`

**Summary:** Sync all accounts for a cloud provider

**Tags:** cloud-connectors

**Auth:** API Key required

**Description:**

Trigger sync for every registered account under one cloud provider.  Useful for organization-level
scanning. Runs sequentially; each account obeys its provider's rate limiter.

**Request Body:** `SyncOrganizationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  | Cloud provider: aws \| azure \| gcp |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 533. `POST` `/api/v1/cloud-graph/build`

**Summary:** Build cloud resource graph

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Ingest raw resource list, auto-infer relationships, and persist the graph.

**Request Body:** `BuildGraphRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resources` | List | Yes |  | List of raw cloud resource dicts |
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `CloudGraph`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `nodes` | List | No | PydanticUndefined |  |
| `edges` | List | No | PydanticUndefined |  |
| `stats` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 534. `GET` `/api/v1/cloud-graph/graph`

**Summary:** Get cloud graph

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the full cloud resource graph, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `node_type` | query | Optional | No | Filter by NodeType |
| `public_only` | query | bool | No | Return only public nodes |

**Responses:**

**200 OK** — `CloudGraph`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `nodes` | List | No | PydanticUndefined |  |
| `edges` | List | No | PydanticUndefined |  |
| `stats` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 535. `POST` `/api/v1/cloud-graph/nodes`

**Summary:** Add a graph node

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add a single cloud resource node to the graph.

**Request Body:** `AddNodeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | str | Yes |  | NodeType value |
| `name` | str | Yes |  | Resource name |
| `provider` | str | No | AWS | Cloud provider |
| `region` | str | No | us-east-1 | Cloud region |
| `config` | Dict | No | PydanticUndefined | Resource config dict |
| `risk_score` | float | No | 0.0 | Risk score 0-1 |
| `vulnerabilities` | List | No | PydanticUndefined | Known CVEs/issues |
| `public` | bool | No | False | Internet-reachable? |
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `GraphNode`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `type` | NodeType | Yes |  |  |
| `name` | str | Yes |  |  |
| `provider` | str | No | AWS |  |
| `region` | str | No | us-east-1 |  |
| `config` | Dict | No | PydanticUndefined |  |
| `risk_score` | float | No | 0.0 |  |
| `vulnerabilities` | List | No | PydanticUndefined |  |
| `public` | bool | No | False |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 536. `POST` `/api/v1/cloud-graph/edges`

**Summary:** Add a graph edge

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add a relationship edge between two nodes.

**Request Body:** `AddEdgeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `source_id` | str | Yes |  | Source node ID |
| `target_id` | str | Yes |  | Target node ID |
| `type` | str | Yes |  | EdgeType value |
| `metadata` | Dict | No | PydanticUndefined | Edge metadata |
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `GraphEdge`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `source_id` | str | Yes |  |  |
| `target_id` | str | Yes |  |  |
| `type` | EdgeType | Yes |  |  |
| `metadata` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 537. `GET` `/api/v1/cloud-graph/exposed`

**Summary:** Internet-exposed resources

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all internet-reachable (public=True) cloud resources.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 538. `GET` `/api/v1/cloud-graph/attack-paths`

**Summary:** Attack paths from internet to sensitive data

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Find traversal paths from public-facing nodes to sensitive resources.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 539. `GET` `/api/v1/cloud-graph/blast-radius/{node_id}`

**Summary:** Blast radius for a node

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the subgraph of resources affected if the given node is compromised.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `node_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `CloudGraph`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `nodes` | List | No | PydanticUndefined |  |
| `edges` | List | No | PydanticUndefined |  |
| `stats` | Dict | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 540. `GET` `/api/v1/cloud-graph/overprivileged`

**Summary:** Overprivileged IAM entities

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return IAM roles and users with excessive permissions.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 541. `GET` `/api/v1/cloud-graph/segmentation`

**Summary:** Network segmentation analysis

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Analyse VPC and subnet isolation — flags mixed public/private VPCs.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 542. `GET` `/api/v1/cloud-graph/risk-paths`

**Summary:** Ranked attack paths by risk score

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return attack paths sorted by cumulative risk score (highest first).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 543. `GET` `/api/v1/cloud-graph/stats`

**Summary:** Graph statistics

**Tags:** cloud-graph

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return node/edge counts and per-type breakdown for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 544. `GET` `/api/v1/scan/gcp-scc/status`

**Summary:** Check GCP Security Command Center configuration

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Return whether GCP credentials are configured.  When unconfigured all endpoints return mock data so
the pipeline can be exercised without real GCP credentials.

**Responses:**

**200 OK** — `GCPStatusResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `configured` | bool | Yes |  |  |
| `project_id` | str | Yes |  |  |
| `organization_id` | str | Yes |  |  |
| `message` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 545. `GET` `/api/v1/scan/gcp-scc/findings`

**Summary:** Pull raw findings from GCP Security Command Center

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Pull raw GCP SCC findings.  Supports optional filtering by severity and state. Returns mock data
when GCP credentials are not configured.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `severity` | query | Optional | No | Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| `state` | query | Optional | No | Filter by state: ACTIVE, INACTIVE |
| `source_id` | query | str | No | SCC source ID to list findings from. Defaults to '-' (all sources). |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 546. `GET` `/api/v1/scan/gcp-scc/sources`

**Summary:** Get GCP SCC sources

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Retrieve GCP Security Command Center sources (Security Health Analytics, Event Threat Detection,
Container Threat Detection, etc.).  Returns mock data when GCP credentials are not configured.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 547. `GET` `/api/v1/scan/gcp-scc/assets`

**Summary:** Get GCP SCC assets

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Retrieve assets tracked by GCP Security Command Center.  Returns mock data when GCP credentials are
not configured.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 548. `POST` `/api/v1/scan/gcp-scc/import`

**Summary:** Import GCP SCC findings into ALDECI

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Pull findings from GCP Security Command Center, normalize to UnifiedFinding format, store in
history, and ingest into the Brain Pipeline.  Returns mock data when GCP credentials are not
configured.

**Request Body:** `ImportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `ImportResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `import_id` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `started_at` | str | Yes |  |  |
| `completed_at` | str | Yes |  |  |
| `status` | str | Yes |  |  |
| `is_mock` | bool | Yes |  |  |
| `findings_count` | int | Yes |  |  |
| `severity_breakdown` | Dict | Yes |  |  |
| `findings` | List | Yes |  |  |
| `error` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 549. `GET` `/api/v1/scan/gcp-scc/history`

**Summary:** List GCP SCC import history

**Tags:** gcp-scc

**Auth:** API Key required

**Description:**

Return the import history for the given organisation, most recent first.  Findings are omitted from
the summary; re-run an import to get full results.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 550. `GET` `/api/v1/k8s/posture`

**Summary:** Overall cluster security posture

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the most recently computed cluster security posture.  Returns 404 if no scan has been run
yet. Trigger a scan via POST /scan first.

**Responses:**

**200 OK** — `PostureResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster_name` | str | Yes |  |  |
| `overall_score` | float | Yes |  |  |
| `grade` | str | Yes |  |  |
| `total_checks` | int | Yes |  |  |
| `passed_checks` | int | Yes |  |  |
| `failed_checks` | int | Yes |  |  |
| `warned_checks` | int | Yes |  |  |
| `critical_findings` | int | Yes |  |  |
| `high_findings` | int | Yes |  |  |
| `medium_findings` | int | Yes |  |  |
| `low_findings` | int | Yes |  |  |
| `scanned_at` | str | Yes |  |  |
| `scan_duration_ms` | int | Yes |  |  |
| `namespace_scores` | List | Yes |  |  |
| `workload_scores` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 551. `GET` `/api/v1/k8s/findings`

**Summary:** Security findings across clusters

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return security findings from the most recent cluster scan with optional filtering.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `severity` | query | Optional | No | Filter by severity: critical\|high\|medium\|low\|info |
| `category` | query | Optional | No | Filter by category: pod_security\|rbac\|network_policy\|image_security\|secrets_management\|admission_control\|cluster_config |
| `namespace` | query | Optional | No | Filter by namespace |
| `limit` | query | int | No | Max findings to return |
| `offset` | query | int | No | Pagination offset |

**Responses:**

**200 OK** — `FindingsResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `total` | int | Yes |  |  |
| `findings` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 552. `POST` `/api/v1/k8s/scan`

**Summary:** Trigger cluster security scan

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Trigger a full KSPM scan of the specified cluster.  Accepts kubeconfig path for remote clusters,
in_cluster flag for pod-based scanning, or raw resource dicts for offline/testing analysis.

**Request Body:** `ScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster_name` | str | No | default | Logical cluster name |
| `kubeconfig_path` | Optional | No | None | Path to kubeconfig file |
| `in_cluster` | bool | No | False | Use in-cluster service account credentials |
| `context` | Optional | No | None | kubeconfig context to use |
| `namespaces` | List | No | PydanticUndefined | Namespaces to scan (empty = all) |
| `trusted_registries` | List | No | PydanticUndefined | Trusted image registries (overrides engine defaults if non-empty) |
| `resources` | List | No | PydanticUndefined | Raw Kubernetes resource dicts (for offline/testing mode) |
| `rbac_resources` | List | No | PydanticUndefined | Raw RBAC resource dicts (Role, ClusterRole, RoleBinding, ClusterRoleBinding) |
| `network_policies` | List | No | PydanticUndefined | Raw NetworkPolicy resource dicts |

**Responses:**

**200 OK** — `PostureResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster_name` | str | Yes |  |  |
| `overall_score` | float | Yes |  |  |
| `grade` | str | Yes |  |  |
| `total_checks` | int | Yes |  |  |
| `passed_checks` | int | Yes |  |  |
| `failed_checks` | int | Yes |  |  |
| `warned_checks` | int | Yes |  |  |
| `critical_findings` | int | Yes |  |  |
| `high_findings` | int | Yes |  |  |
| `medium_findings` | int | Yes |  |  |
| `low_findings` | int | Yes |  |  |
| `scanned_at` | str | Yes |  |  |
| `scan_duration_ms` | int | Yes |  |  |
| `namespace_scores` | List | Yes |  |  |
| `workload_scores` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 553. `GET` `/api/v1/k8s/rbac`

**Summary:** RBAC analysis results

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return RBAC analysis from the most recent scan.  Includes cluster-admin bindings, wildcard
permissions, overprivileged service accounts, escalation paths, and unused roles.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 554. `GET` `/api/v1/k8s/network-policies`

**Summary:** Network policy audit results

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return network policy audit results from the most recent scan.  Shows default-deny status, coverage
percentage, permissive rules, and namespace isolation gaps.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 555. `GET` `/api/v1/k8s/images`

**Summary:** Image security findings

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return image security findings from the most recent scan.  Includes latest-tag usage, untrusted
registries, pull policy violations, and image signing status.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 556. `GET` `/api/v1/k8s/admission-rules`

**Summary:** Active admission control rules

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all active admission control rules configured in the engine.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 557. `POST` `/api/v1/k8s/admission-rules`

**Summary:** Add or replace an admission control rule

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add a new admission control rule or replace an existing one by name.

**Request Body:** `AdmissionRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Unique rule name |
| `description` | str | No |  | Human-readable description |
| `action` | str | No | deny | Action on violation: deny \| warn \| audit |
| `enabled` | bool | No | True |  |
| `conditions` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 558. `GET` `/api/v1/k8s/secrets`

**Summary:** Secrets management audit results

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return secrets management audit from the most recent scan.  Shows secrets exposed as env vars,
secrets in ConfigMaps, etcd encryption status, and External Secrets Operator presence.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 559. `GET` `/api/v1/k8s/check-results`

**Summary:** Detailed check results from latest scan

**Tags:** Kubernetes Security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return per-check results from the most recent scan, optionally filtered by category.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `category` | query | Optional | No | Filter by check category |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 560. `POST` `/api/v1/prowler/scan`

**Summary:** Trigger a Prowler scan against a cloud provider

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

Trigger a Prowler CLI scan. Requires Prowler to be installed on the host.

**Request Body:** `TriggerScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `provider` | str | No | aws | Cloud provider: aws/azure/gcp |
| `account_id` | str | No |  | Cloud account/subscription ID |
| `regions` | str | No |  | Comma-separated regions to scan |
| `checks` | Optional | No | None | Specific checks to run |
| `timeout` | int | No | 3600 | Scan timeout in seconds |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 561. `POST` `/api/v1/prowler/ingest`

**Summary:** Ingest raw Prowler JSON output

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

Ingest findings from raw Prowler JSON output without running the CLI.

**Request Body:** `IngestJsonRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `provider` | str | No | aws | Cloud provider: aws/azure/gcp |
| `account_id` | str | No |  | Cloud account ID |
| `raw_json` | str | Yes |  | Raw Prowler JSON output |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 562. `GET` `/api/v1/prowler/scans`

**Summary:** List Prowler scan history

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `limit` | query | int | No | 50 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 563. `GET` `/api/v1/prowler/scans/{scan_id}`

**Summary:** Get a specific Prowler scan

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `scan_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 564. `GET` `/api/v1/prowler/findings`

**Summary:** List Prowler findings with filters

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `scan_id` | query | Optional | No | None |
| `provider` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `service` | query | Optional | No | None |
| `limit` | query | int | No | 100 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 565. `GET` `/api/v1/prowler/findings/{finding_id}`

**Summary:** Get a specific Prowler finding

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 566. `PUT` `/api/v1/prowler/findings/{finding_id}/resolve`

**Summary:** Resolve a Prowler finding

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `ResolveRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 567. `PUT` `/api/v1/prowler/findings/{finding_id}/suppress`

**Summary:** Suppress a Prowler finding

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `SuppressRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 568. `GET` `/api/v1/prowler/compliance`

**Summary:** Get CIS compliance results

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `scan_id` | query | Optional | No | None |
| `framework` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 569. `GET` `/api/v1/prowler/compliance/summary`

**Summary:** Get aggregated compliance summary per framework

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `scan_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 570. `GET` `/api/v1/prowler/summary`

**Summary:** Get overall Prowler scan summary

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 571. `GET` `/api/v1/prowler/status`

**Summary:** Check Prowler CLI installation status

**Tags:** Prowler CSPM

**Auth:** API Key required

**Description:**

Check if Prowler CLI is installed and available.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 572. `POST` `/api/v1/iot-security/devices`

**Summary:** POST /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Register a new IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `DeviceCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_name` | str | No |  |  |
| `device_category` | str | No | other |  |
| `protocol` | str | No | mqtt |  |
| `ip_address` | str | No |  |  |
| `mac_address` | str | No |  |  |
| `firmware_version` | str | No |  |  |
| `last_seen` | Optional | No | None |  |
| `risk_score` | float | No | 50.0 |  |
| `status` | str | No | online |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 573. `GET` `/api/v1/iot-security/devices`

**Summary:** GET /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT devices, optionally filtered by device_category and/or status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_category` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 574. `GET` `/api/v1/iot-security/devices/{device_id}`

**Summary:** GET /api/v1/iot-security/devices/{device_id}

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Get a single IoT device by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 575. `PUT` `/api/v1/iot-security/devices/{device_id}/status`

**Summary:** PUT /api/v1/iot-security/devices/{device_id}/status

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Update the status of an IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DeviceStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 576. `POST` `/api/v1/iot-security/anomalies`

**Summary:** POST /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Record an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_id` | str | No |  |  |
| `anomaly_type` | str | No | unusual_traffic |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 577. `GET` `/api/v1/iot-security/anomalies`

**Summary:** GET /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT anomalies, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 578. `PUT` `/api/v1/iot-security/anomalies/{anomaly_id}/resolve`

**Summary:** PUT /api/v1/iot-security/anomalies/{anomaly_id}/resolve

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Resolve an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyResolve`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolution_status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 579. `POST` `/api/v1/iot-security/policies`

**Summary:** POST /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Create an IoT security policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | No |  |  |
| `policy_type` | str | No | monitoring |  |
| `applies_to_category` | str | No | all |  |
| `enforcement` | str | No | recommended |  |
| `enabled` | bool | No | True |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 580. `GET` `/api/v1/iot-security/policies`

**Summary:** GET /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT security policies, optionally filtered by enabled flag.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 581. `GET` `/api/v1/iot-security/stats`

**Summary:** GET /api/v1/iot-security/stats

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Return aggregated IoT security statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 582. `POST` `/api/v1/ddos-protection/resources`

**Summary:** Register a protected resource

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RegisterResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `name` | str | Yes |  | Friendly name for the resource |
| `ip_or_fqdn` | str | Yes |  | IP address or fully-qualified domain name |
| `resource_type` | str | Yes |  | web \| api \| dns \| network |
| `protection_tier` | str | No | basic | basic \| standard \| premium |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 583. `GET` `/api/v1/ddos-protection/resources`

**Summary:** List protected resources

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 584. `POST` `/api/v1/ddos-protection/attacks`

**Summary:** Record a DDoS attack event

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RecordAttackRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `resource_id` | str | Yes |  | Protected resource UUID |
| `attack_type` | str | Yes |  | volumetric \| protocol \| application \| slowloris \| amplification |
| `source_ips` | List | No | PydanticUndefined | List of attacking source IPs |
| `peak_gbps` | float | No | 0.0 | Peak attack volume in Gbps |
| `duration_seconds` | int | No | 0 | Attack duration in seconds |
| `status` | str | No | detected | detected \| mitigating \| mitigated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 585. `GET` `/api/v1/ddos-protection/attacks`

**Summary:** List attack events

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |
| `resource_id` | query | Optional | No | Filter by resource UUID |
| `status` | query | Optional | No | Filter by status |
| `limit` | query | int | No | Maximum records to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 586. `PATCH` `/api/v1/ddos-protection/attacks/{attack_id}/status`

**Summary:** Update attack event status

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `attack_id` | path | str | Yes | — |

**Request Body:** `UpdateAttackStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `status` | str | Yes |  | detected \| mitigating \| mitigated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 587. `POST` `/api/v1/ddos-protection/rules`

**Summary:** Create a mitigation rule

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateMitigationRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `name` | str | Yes |  | Rule name |
| `rule_type` | str | Yes |  | rate_limit \| geo_block \| ip_block \| challenge |
| `threshold` | Any | Yes |  | Rule threshold value |
| `action` | str | Yes |  | Action to take when rule triggers |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 588. `GET` `/api/v1/ddos-protection/rules`

**Summary:** List mitigation rules

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 589. `GET` `/api/v1/ddos-protection/stats`

**Summary:** Get DDoS stats for an org

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 590. `POST` `/api/v1/ot-security/assets`

**Summary:** POST /api/v1/ot-security/assets

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Register a new OT asset (PLC, HMI, SCADA, RTU, sensor, or historian).

**Request Body:** `RegisterAssetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `name` | str | Yes |  | Asset name |
| `asset_type` | str | Yes |  | Asset type: plc/hmi/scada/rtu/sensor/historian |
| `criticality` | str | No | medium | Criticality: low/medium/high/critical |
| `vendor` | str | No |  | Vendor/manufacturer |
| `firmware_version` | str | No |  | Firmware version |
| `ip_address` | str | No |  | IP address |
| `zone` | str | No |  | Network zone or purdue level |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 591. `GET` `/api/v1/ot-security/assets`

**Summary:** GET /api/v1/ot-security/assets

**Tags:** ot-security

**Auth:** API Key required

**Description:**

List OT assets with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `asset_type` | query | Optional | No | Filter by asset type |
| `criticality` | query | Optional | No | Filter by criticality |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 592. `GET` `/api/v1/ot-security/assets/{asset_id}`

**Summary:** GET /api/v1/ot-security/assets/{asset_id}

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Get a single OT asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 593. `POST` `/api/v1/ot-security/anomalies`

**Summary:** POST /api/v1/ot-security/anomalies

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Record a new anomaly against an OT asset.

**Request Body:** `RecordAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `asset_id` | str | Yes |  | Target asset ID |
| `anomaly_type` | str | Yes |  | Type of anomaly |
| `severity` | str | Yes |  | Severity: low/medium/high/critical |
| `description` | str | No |  | Anomaly description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 594. `GET` `/api/v1/ot-security/anomalies`

**Summary:** GET /api/v1/ot-security/anomalies

**Tags:** ot-security

**Auth:** API Key required

**Description:**

List OT anomalies with optional status and severity filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `status` | query | Optional | No | Filter by status |
| `severity` | query | Optional | No | Filter by severity |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 595. `PUT` `/api/v1/ot-security/anomalies/{anomaly_id}/resolve`

**Summary:** PUT /api/v1/ot-security/anomalies/{anomaly_id}/resolve

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Resolve an open anomaly with a resolution note.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |

**Request Body:** `ResolveAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `resolution` | str | Yes |  | Resolution notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 596. `GET` `/api/v1/ot-security/stats`

**Summary:** GET /api/v1/ot-security/stats

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Get OT environment statistics: asset counts by type/criticality, open anomalies.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 597. `POST` `/api/v1/ot-sec/assets`

**Summary:** POST /api/v1/ot-sec/assets

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Register a new OT asset.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AssetCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `asset_name` | str | No |  |  |
| `asset_type` | str | Yes |  |  |
| `vendor` | str | No |  |  |
| `model` | str | No |  |  |
| `firmware_version` | str | No |  |  |
| `zone` | str | Yes |  |  |
| `protocol` | str | No | other |  |
| `risk_score` | float | No | 50.0 |  |
| `status` | str | No | operational |  |
| `last_patched` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 598. `GET` `/api/v1/ot-sec/assets`

**Summary:** GET /api/v1/ot-sec/assets

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List OT assets with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_type` | query | Optional | No | None |
| `zone` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 599. `GET` `/api/v1/ot-sec/assets/{asset_id}`

**Summary:** GET /api/v1/ot-sec/assets/{asset_id}

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Get a single OT asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 600. `PUT` `/api/v1/ot-sec/assets/{asset_id}/status`

**Summary:** PUT /api/v1/ot-sec/assets/{asset_id}/status

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Update asset operational status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AssetStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 601. `POST` `/api/v1/ot-sec/incidents`

**Summary:** POST /api/v1/ot-sec/incidents

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Record an OT security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `IncidentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `asset_id` | str | No |  |  |
| `incident_type` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `impact_level` | str | No | none |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 602. `GET` `/api/v1/ot-sec/incidents`

**Summary:** GET /api/v1/ot-sec/incidents

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List incidents with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 603. `PUT` `/api/v1/ot-sec/incidents/{incident_id}/status`

**Summary:** PUT /api/v1/ot-sec/incidents/{incident_id}/status

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Update incident status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `IncidentStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 604. `POST` `/api/v1/ot-sec/zones`

**Summary:** POST /api/v1/ot-sec/zones

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Create an OT network zone.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ZoneCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `zone_name` | str | No |  |  |
| `zone_type` | str | Yes |  |  |
| `asset_count` | int | No | 0 |  |
| `security_level` | str | No | sl1 |  |
| `purdue_level` | int | No | 0 |  |
| `conduit_count` | int | No | 0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 605. `GET` `/api/v1/ot-sec/zones`

**Summary:** GET /api/v1/ot-sec/zones

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List zones with optional zone_type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `zone_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 606. `GET` `/api/v1/ot-sec/stats`

**Summary:** GET /api/v1/ot-sec/stats

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Return aggregated OT security statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 607. `GET` `/api/v1/network-forensics/`

**Summary:** GET /api/v1/network-forensics/

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List network forensics captures for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 608. `POST` `/api/v1/network-forensics/captures`

**Summary:** POST /api/v1/network-forensics/captures

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CaptureCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `interface` | str | Yes |  |  |
| `filter_bpf` | str | No |  |  |
| `duration_sec` | int | No | 60 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 609. `GET` `/api/v1/network-forensics/captures`

**Summary:** GET /api/v1/network-forensics/captures

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 610. `GET` `/api/v1/network-forensics/captures/{capture_id}`

**Summary:** GET /api/v1/network-forensics/captures/{capture_id}

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 611. `POST` `/api/v1/network-forensics/captures/{capture_id}/artifacts`

**Summary:** POST /api/v1/network-forensics/captures/{capture_id}/artifacts

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ArtifactCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `artifact_type` | str | No | pcap |  |
| `size_bytes` | int | No | 0 |  |
| `findings_count` | int | No | 0 |  |
| `analysis_json` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 612. `POST` `/api/v1/network-forensics/captures/{capture_id}/analyze`

**Summary:** POST /api/v1/network-forensics/captures/{capture_id}/analyze

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnalyzeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `suspicious_ips` | List | No | [] |  |
| `protocols_seen` | List | No | [] |  |
| `anomalies` | List | No | [] |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 613. `GET` `/api/v1/network-forensics/artifacts`

**Summary:** GET /api/v1/network-forensics/artifacts

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `capture_id` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 614. `GET` `/api/v1/network-forensics/stats`

**Summary:** GET /api/v1/network-forensics/stats

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 615. `POST` `/api/v1/digital-twin/twins`

**Summary:** POST /api/v1/digital-twin/twins

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Create a new digital twin.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `TwinCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `twin_type` | str | No | network |  |
| `description` | str | No |  |  |
| `asset_count` | int | No | 0 |  |
| `fidelity_level` | str | No | medium |  |
| `sync_status` | str | No | stale |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 616. `GET` `/api/v1/digital-twin/twins`

**Summary:** GET /api/v1/digital-twin/twins

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List digital twins with optional type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 617. `GET` `/api/v1/digital-twin/twins/{twin_id}`

**Summary:** GET /api/v1/digital-twin/twins/{twin_id}

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Get a single digital twin by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `twin_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 618. `POST` `/api/v1/digital-twin/twins/{twin_id}/simulations`

**Summary:** POST /api/v1/digital-twin/twins/{twin_id}/simulations

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Run a simulation on a digital twin.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `twin_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SimulationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `simulation_type` | str | No | attack_path |  |
| `parameters_json` | dict | No | {} |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 619. `GET` `/api/v1/digital-twin/simulations`

**Summary:** GET /api/v1/digital-twin/simulations

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List simulations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_id` | query | Optional | No | None |
| `simulation_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 620. `POST` `/api/v1/digital-twin/simulations/{simulation_id}/findings`

**Summary:** POST /api/v1/digital-twin/simulations/{simulation_id}/findings

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Add a finding to a simulation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `simulation_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `FindingCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `title` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |
| `twin_id` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 621. `GET` `/api/v1/digital-twin/findings`

**Summary:** GET /api/v1/digital-twin/findings

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 622. `GET` `/api/v1/digital-twin/stats`

**Summary:** GET /api/v1/digital-twin/stats

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Return aggregated digital twin statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 623. `GET` `/api/v1/network-threats/`

**Summary:** GET /api/v1/network-threats/

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Get network threat statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 624. `POST` `/api/v1/network-threats/threats`

**Summary:** POST /api/v1/network-threats/threats

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Record or update a network threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ThreatCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `threat_name` | str | Yes |  |  |
| `threat_type` | str | Yes |  |  |
| `source_ip` | str | Yes |  |  |
| `dest_ip` | str | Yes |  |  |
| `dest_port` | int | No | 0 |  |
| `protocol` | str | No | tcp |  |
| `severity` | str | No | medium |  |
| `confidence` | float | No | 0.5 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 625. `POST` `/api/v1/network-threats/threats/{threat_id}/resolve`

**Summary:** POST /api/v1/network-threats/threats/{threat_id}/resolve

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Resolve an active threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 626. `GET` `/api/v1/network-threats/threats/active`

**Summary:** GET /api/v1/network-threats/threats/active

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return active network threats with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `threat_type` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 627. `POST` `/api/v1/network-threats/rules`

**Summary:** POST /api/v1/network-threats/rules

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Create a new threat detection rule.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RuleCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | Yes |  |  |
| `rule_type` | str | Yes |  |  |
| `pattern` | str | Yes |  |  |
| `action` | str | No | alert |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 628. `POST` `/api/v1/network-threats/rules/{rule_id}/trigger`

**Summary:** POST /api/v1/network-threats/rules/{rule_id}/trigger

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Increment match_count for a rule.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 629. `GET` `/api/v1/network-threats/rules`

**Summary:** GET /api/v1/network-threats/rules

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

List threat detection rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 630. `PUT` `/api/v1/network-threats/baselines`

**Summary:** PUT /api/v1/network-threats/baselines

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Upsert a network baseline metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BaselineUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  |  |
| `baseline_value` | float | Yes |  |  |
| `current_value` | float | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 631. `GET` `/api/v1/network-threats/baselines/anomalous`

**Summary:** GET /api/v1/network-threats/baselines/anomalous

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return baselines flagged as anomalous.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 632. `GET` `/api/v1/network-threats/stats`

**Summary:** GET /api/v1/network-threats/stats

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return aggregated network threat statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 633. `POST` `/api/v1/cloud-ir/incidents`

**Summary:** Create a cloud incident

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `incident_name` | str | Yes |  | Descriptive incident name |
| `cloud_provider` | str | No | aws | Cloud provider |
| `incident_type` | str | Yes |  | Type of cloud incident |
| `severity` | str | No | medium | Severity: critical/high/medium/low |
| `affected_services` | Optional | No | None | List of affected services |
| `affected_regions` | Optional | No | None | List of affected regions |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 634. `GET` `/api/v1/cloud-ir/incidents`

**Summary:** List incidents for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |
| `status` | query | Optional | No | None |
| `cloud_provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 635. `GET` `/api/v1/cloud-ir/incidents/{incident_id}`

**Summary:** Get a single incident with actions and playbooks

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 636. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/contain`

**Summary:** Mark incident as contained

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `ContainIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `blast_radius` | str | No | unknown | Blast radius description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 637. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/actions`

**Summary:** Add a containment action to an incident

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `AddActionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `action_type` | str | Yes |  | Containment action type |
| `resource_id` | str | No |  | Affected resource identifier |
| `description` | str | No |  | Action description |
| `automated` | bool | No | False | Whether action was automated |
| `executed_by` | str | No |  | Who executed the action |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 638. `POST` `/api/v1/cloud-ir/actions/{action_id}/complete`

**Summary:** Mark a containment action as completed

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `action_id` | path | str | Yes | — |

**Request Body:** `CompleteActionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `result` | str | No |  | Action result/outcome |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 639. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/resolve`

**Summary:** Mark incident as resolved

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `ResolveIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `root_cause` | str | No |  | Root cause analysis |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 640. `POST` `/api/v1/cloud-ir/playbooks`

**Summary:** Create an IR playbook

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreatePlaybookRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `playbook_name` | str | Yes |  | Playbook name |
| `cloud_provider` | str | Yes |  | Target cloud provider |
| `incident_type` | str | Yes |  | Target incident type |
| `steps` | Optional | No | None | Ordered playbook steps |
| `estimated_mins` | int | No | 30 | Estimated execution time in minutes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 641. `GET` `/api/v1/cloud-ir/playbooks`

**Summary:** List IR playbooks for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 642. `POST` `/api/v1/cloud-ir/playbooks/{playbook_id}/execute`

**Summary:** Execute a playbook (increments execution_count)

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `playbook_id` | path | str | Yes | — |

**Request Body:** `ExecutePlaybookRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 643. `GET` `/api/v1/cloud-ir/metrics`

**Summary:** Get IR metrics for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 644. `POST` `/api/v1/network-anomaly/samples`

**Summary:** Record a traffic sample

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `TrafficSampleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | TCP/UDP/ICMP/HTTP/HTTPS/DNS/SMTP/FTP/SSH/other |
| `direction` | str | No | inbound | inbound/outbound/lateral |
| `bytes_per_min` | float | No | 0.0 | Bytes per minute |
| `packets_per_min` | float | No | 0.0 | Packets per minute |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 645. `POST` `/api/v1/network-anomaly/baselines/update`

**Summary:** Update baseline from recent samples

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `BaselineUpdateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | Protocol |
| `direction` | str | No | inbound | Traffic direction |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 646. `POST` `/api/v1/network-anomaly/detect`

**Summary:** Detect anomalies against current baseline

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `DetectAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | Protocol |
| `direction` | str | No | inbound | Traffic direction |
| `bytes_per_min` | float | No | 0.0 | Observed bytes per minute |
| `packets_per_min` | float | No | 0.0 | Observed packets per minute |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 647. `PUT` `/api/v1/network-anomaly/anomalies/{anomaly_id}/resolve`

**Summary:** Resolve a network anomaly

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 648. `GET` `/api/v1/network-anomaly/summary`

**Summary:** Get anomaly summary for org

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 649. `GET` `/api/v1/network-anomaly/baselines`

**Summary:** Get baseline health for org

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 650. `GET` `/api/v1/network-anomaly/traffic-trend`

**Summary:** Get traffic trend for segment/protocol

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `segment` | query | str | Yes | Network segment |
| `protocol` | query | str | No | Protocol |
| `hours` | query | int | No | Hours of history to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 651. `POST` `/api/v1/cloud-compliance/assessments`

**Summary:** POST /api/v1/cloud-compliance/assessments

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Create a new cloud compliance assessment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Request Body:** `AssessmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cloud_provider` | str | No | aws | aws/azure/gcp/multi |
| `framework` | str | Yes |  | cis_aws_v1.5 / nist_800_53 / soc2 / etc. |
| `scope` | Dict | No | PydanticUndefined |  |
| `total_controls` | int | No | 0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 652. `GET` `/api/v1/cloud-compliance/assessments`

**Summary:** GET /api/v1/cloud-compliance/assessments

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List assessments, optionally filtered by framework or cloud provider.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 653. `GET` `/api/v1/cloud-compliance/assessments/{assessment_id}`

**Summary:** GET /api/v1/cloud-compliance/assessments/{assessment_id}

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return assessment details with control summary.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 654. `POST` `/api/v1/cloud-compliance/assessments/{assessment_id}/controls`

**Summary:** POST /api/v1/cloud-compliance/assessments/{assessment_id}/controls

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Record a control result against an assessment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ControlResultCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_id` | str | Yes |  |  |
| `control_name` | str | No |  |  |
| `section` | str | No |  |  |
| `severity` | str | No | medium | critical/high/medium/low/info |
| `status` | str | No | manual_check | passed/failed/not_applicable/manual_check |
| `evidence` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `region` | str | No |  |  |
| `remediation` | str | No |  |  |
| `auto_remediated` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 655. `POST` `/api/v1/cloud-compliance/assessments/{assessment_id}/complete`

**Summary:** POST /api/v1/cloud-compliance/assessments/{assessment_id}/complete

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Mark an assessment as completed and compute final score + drift.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 656. `GET` `/api/v1/cloud-compliance/controls`

**Summary:** GET /api/v1/cloud-compliance/controls

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List control results with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `assessment_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 657. `POST` `/api/v1/cloud-compliance/remediation-plans`

**Summary:** POST /api/v1/cloud-compliance/remediation-plans

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Create a remediation plan for a control failure.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RemediationPlanCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `assessment_id` | str | Yes |  |  |
| `control_id` | str | Yes |  |  |
| `priority` | str | No | p3 | p1/p2/p3/p4 |
| `assigned_team` | str | No |  |  |
| `estimated_effort` | str | No | medium | low/medium/high |
| `target_date` | str | No |  |  |
| `notes` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 658. `PATCH` `/api/v1/cloud-compliance/remediation-plans/{plan_id}/status`

**Summary:** PATCH /api/v1/cloud-compliance/remediation-plans/{plan_id}/status

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Update the status of a remediation plan.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `plan_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RemediationStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  | planned/in_progress/completed/deferred |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 659. `GET` `/api/v1/cloud-compliance/remediation-plans`

**Summary:** GET /api/v1/cloud-compliance/remediation-plans

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List remediation plans with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `assessment_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 660. `GET` `/api/v1/cloud-compliance/drift`

**Summary:** GET /api/v1/cloud-compliance/drift

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return compliance drift history over time.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `limit` | query | int | No | 10 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 661. `GET` `/api/v1/cloud-compliance/stats`

**Summary:** GET /api/v1/cloud-compliance/stats

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return aggregated cloud compliance statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 662. `POST` `/api/v1/physical-security/locations`

**Summary:** POST /api/v1/physical-security/locations

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Register a new physical location.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterLocationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Location name |
| `location_type` | str | Yes |  | office \| datacenter \| warehouse \| facility \| remote |
| `address` | Optional | No | None | Physical address |
| `security_level` | str | No | medium | low \| medium \| high \| critical |
| `capacity` | Optional | No | None | Max occupancy |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 663. `GET` `/api/v1/physical-security/locations`

**Summary:** GET /api/v1/physical-security/locations

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

List physical locations, optionally filtered by type or security level.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `location_type` | query | Optional | No | None |
| `security_level` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 664. `GET` `/api/v1/physical-security/locations/{location_id}`

**Summary:** GET /api/v1/physical-security/locations/{location_id}

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Get a specific location by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `location_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 665. `POST` `/api/v1/physical-security/events`

**Summary:** POST /api/v1/physical-security/events

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Record a physical access event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RecordAccessEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `location_id` | str | Yes |  | Target location ID |
| `person_id` | str | Yes |  | Person or badge ID |
| `access_type` | str | Yes |  | entry \| exit \| attempt \| denied |
| `method` | str | Yes |  | badge \| biometric \| pin \| key \| tailgate |
| `timestamp` | Optional | No | None | ISO timestamp (defaults to now) |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 666. `GET` `/api/v1/physical-security/events`

**Summary:** GET /api/v1/physical-security/events

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

List access events, optionally filtered by location or access type.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `location_id` | query | Optional | No | None |
| `access_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 667. `POST` `/api/v1/physical-security/incidents`

**Summary:** POST /api/v1/physical-security/incidents

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Record a new physical security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RecordIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `location_id` | str | Yes |  | Location where incident occurred |
| `incident_type` | str | Yes |  | tailgating \| unauthorized_access \| theft \| vandalism \| fire \| flood \| other |
| `severity` | str | Yes |  | low \| medium \| high \| critical |
| `description` | Optional | No | None | Incident details |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 668. `PUT` `/api/v1/physical-security/incidents/{incident_id}/resolve`

**Summary:** PUT /api/v1/physical-security/incidents/{incident_id}/resolve

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Resolve an open physical security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ResolveIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolution` | str | Yes |  | Description of resolution taken |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 669. `GET` `/api/v1/physical-security/stats`

**Summary:** GET /api/v1/physical-security/stats

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Return physical security overview stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 670. `POST` `/api/v1/identity-governance/reviews`

**Summary:** Create an access review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `ReviewIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `review_type` | str | No | quarterly |  |
| `reviewer_id` | str | No |  |  |
| `start_date` | str | No |  |  |
| `due_date` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 671. `GET` `/api/v1/identity-governance/reviews`

**Summary:** List access reviews

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 672. `GET` `/api/v1/identity-governance/reviews/{review_id}`

**Summary:** Get a review with item summary

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 673. `POST` `/api/v1/identity-governance/reviews/{review_id}/items`

**Summary:** Add an item to a review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Request Body:** `ReviewItemIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `identity_name` | str | No |  |  |
| `identity_type` | str | No | user |  |
| `entitlement` | str | No |  |  |
| `entitlement_level` | str | No | read |  |
| `last_used` | Optional | No | None |  |
| `risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 674. `POST` `/api/v1/identity-governance/items/{item_id}/decision`

**Summary:** Submit a reviewer decision

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `item_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Request Body:** `DecisionIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `decision` | str | Yes |  |  |
| `reviewer_id` | str | Yes |  |  |
| `notes` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 675. `POST` `/api/v1/identity-governance/reviews/{review_id}/complete`

**Summary:** Complete an access review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 676. `POST` `/api/v1/identity-governance/entitlements`

**Summary:** Add an entitlement

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `EntitlementIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `identity_name` | str | No |  |  |
| `identity_type` | str | No | user |  |
| `entitlement` | str | No |  |  |
| `system` | str | No |  |  |
| `granted_date` | str | No |  |  |
| `last_used` | Optional | No | None |  |
| `is_orphaned` | bool | No | False |  |
| `is_excessive` | bool | No | False |  |
| `risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 677. `GET` `/api/v1/identity-governance/entitlements`

**Summary:** List entitlements

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `identity_id` | query | Optional | No | None |
| `is_orphaned` | query | Optional | No | None |
| `is_excessive` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 678. `POST` `/api/v1/identity-governance/entitlements/flag-orphaned`

**Summary:** Flag all entitlements for an identity as orphaned

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `identity_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 679. `POST` `/api/v1/identity-governance/policies`

**Summary:** Create an access policy

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `PolicyIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  |  |
| `policy_type` | str | No | least_privilege |  |
| `conditions` | Dict | No | {} |  |
| `auto_remediate` | bool | No | False |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 680. `GET` `/api/v1/identity-governance/policies`

**Summary:** List access policies

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 681. `GET` `/api/v1/identity-governance/stats`

**Summary:** Get identity governance statistics

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 682. `POST` `/api/v1/quantum-crypto/assets`

**Summary:** POST /api/v1/quantum-crypto/assets

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Register a cryptographic asset for quantum vulnerability tracking.

**Request Body:** `RegisterAssetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `asset_name` | str | Yes |  | Name of the cryptographic asset |
| `asset_type` | str | Yes |  | Type: tls_certificate, vpn, signing_key, encryption_key, code_signing, database_encryption, api_key, ssh_key |
| `current_algorithm` | str | Yes |  | Current algorithm: rsa, ecdsa, dh, aes, 3des, sha1, sha256, sha384, sha512 |
| `key_size` | int | No | 0 | Key size in bits |
| `risk_level` | str | No | low | Risk level: critical, high, medium, low |
| `migration_status` | str | No | not_started | Migration status: not_started, planned, in_progress, completed, exempt |
| `discovered_at` | Optional | No | None | ISO 8601 discovery timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 683. `GET` `/api/v1/quantum-crypto/assets`

**Summary:** GET /api/v1/quantum-crypto/assets

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List cryptographic assets, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_type` | query | Optional | No | None |
| `quantum_vulnerable` | query | Optional | No | None |
| `migration_status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 684. `GET` `/api/v1/quantum-crypto/assets/{asset_id}`

**Summary:** GET /api/v1/quantum-crypto/assets/{asset_id}

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Get a single cryptographic asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 685. `PUT` `/api/v1/quantum-crypto/assets/{asset_id}/migration-status`

**Summary:** PUT /api/v1/quantum-crypto/assets/{asset_id}/migration-status

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Update the migration status of a cryptographic asset.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |

**Request Body:** `UpdateMigrationStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `migration_status` | str | Yes |  | New status: not_started, planned, in_progress, completed, exempt |
| `migrated_at` | Optional | No | None | ISO 8601 migration timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 686. `POST` `/api/v1/quantum-crypto/assessments`

**Summary:** POST /api/v1/quantum-crypto/assessments

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Create a quantum readiness assessment.

**Request Body:** `CreateAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `assessment_name` | str | Yes |  | Assessment name |
| `scope` | str | No |  | Assessment scope description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 687. `PUT` `/api/v1/quantum-crypto/assessments/{assessment_id}/complete`

**Summary:** PUT /api/v1/quantum-crypto/assessments/{assessment_id}/complete

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Complete an assessment and compute the quantum readiness score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |

**Request Body:** `CompleteAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `total_assets` | int | Yes |  |  |
| `vulnerable_assets` | int | Yes |  |  |
| `migrated_assets` | int | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 688. `GET` `/api/v1/quantum-crypto/assessments`

**Summary:** GET /api/v1/quantum-crypto/assessments

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List quantum readiness assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 689. `POST` `/api/v1/quantum-crypto/migrations`

**Summary:** POST /api/v1/quantum-crypto/migrations

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Create a PQC migration plan for an asset.

**Request Body:** `CreateMigrationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `asset_id` | str | Yes |  | Asset to migrate |
| `from_algorithm` | str | No |  | Source algorithm |
| `to_algorithm` | str | No |  | Target PQC algorithm |
| `priority` | str | No | medium | Priority: immediate, high, medium, low, scheduled |
| `planned_date` | Optional | No | None | ISO 8601 planned date |
| `migrated_by` | str | No |  | Operator or system performing migration |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 690. `GET` `/api/v1/quantum-crypto/migrations`

**Summary:** GET /api/v1/quantum-crypto/migrations

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List PQC migration plans, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `priority` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 691. `GET` `/api/v1/quantum-crypto/stats`

**Summary:** GET /api/v1/quantum-crypto/stats

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Return aggregate quantum crypto statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 692. `POST` `/api/v1/access-reviews/reviews`

**Summary:** POST /api/v1/access-reviews/reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Create a new access review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ReviewCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `review_name` | str | Yes |  |  |
| `review_type` | str | No | quarterly |  |
| `reviewer_id` | str | No |  |  |
| `due_date` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 693. `GET` `/api/v1/access-reviews/reviews`

**Summary:** GET /api/v1/access-reviews/reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

List access reviews, optionally filtered by status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 694. `GET` `/api/v1/access-reviews/reviews/{review_id}`

**Summary:** GET /api/v1/access-reviews/reviews/{review_id}

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get a review with all its items.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 695. `POST` `/api/v1/access-reviews/reviews/{review_id}/items`

**Summary:** POST /api/v1/access-reviews/reviews/{review_id}/items

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Add an item to an access review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ReviewItemCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `resource_id` | str | Yes |  |  |
| `resource_type` | str | No |  |  |
| `access_level` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 696. `POST` `/api/v1/access-reviews/reviews/{review_id}/items/{item_id}/decide`

**Summary:** POST /api/v1/access-reviews/reviews/{review_id}/items/{item_id}/decide

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Record a certify/revoke/modify/defer decision on a review item.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `item_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DecisionCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `decision` | str | Yes |  |  |
| `decision_reason` | str | No |  |  |
| `decided_by` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 697. `GET` `/api/v1/access-reviews/overdue`

**Summary:** GET /api/v1/access-reviews/overdue

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get access reviews past their due date that are not completed.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 698. `POST` `/api/v1/access-reviews/campaigns`

**Summary:** POST /api/v1/access-reviews/campaigns

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Create a review campaign.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CampaignCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `campaign_name` | str | Yes |  |  |
| `frequency` | str | No | quarterly |  |
| `scope` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 699. `GET` `/api/v1/access-reviews/campaigns/stats`

**Summary:** GET /api/v1/access-reviews/campaigns/stats

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get aggregated campaign stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 700. `GET` `/api/v1/access-reviews/summary`

**Summary:** GET /api/v1/access-reviews/summary

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get total/pending/completed/overdue review counts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 701. `GET` `/api/v1/access-reviews`

**Summary:** GET /api/v1/access-reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Root endpoint — returns reviews list for dashboard health-checks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 702. `GET` `/api/v1/access-governance/`

**Summary:** GET /api/v1/access-governance/

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Get access governance summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 703. `POST` `/api/v1/access-governance/entitlements`

**Summary:** POST /api/v1/access-governance/entitlements

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Grant an entitlement to a user for a resource.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `GrantEntitlementRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User to grant access to |
| `resource_id` | str | Yes |  | Resource identifier |
| `resource_type` | str | Yes |  | application \| database \| server \| network \| cloud-service \| api \| data-store \| vault |
| `access_level` | str | Yes |  | read \| write \| admin \| execute \| delete \| full-control |
| `granted_by` | str | No |  | Approver username |
| `expires_at` | Optional | No | None | ISO 8601 expiry timestamp (optional) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 704. `POST` `/api/v1/access-governance/entitlements/{entitlement_id}/revoke`

**Summary:** POST /api/v1/access-governance/entitlements/{entitlement_id}/revoke

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Revoke an entitlement by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entitlement_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 705. `POST` `/api/v1/access-governance/sod/detect`

**Summary:** POST /api/v1/access-governance/sod/detect

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Detect SoD violations for a user against provided rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `DetectSodRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User ID to check |
| `sod_rules` | List | Yes |  | List of SoD rules to evaluate |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 706. `POST` `/api/v1/access-governance/violations/{violation_id}/acknowledge`

**Summary:** POST /api/v1/access-governance/violations/{violation_id}/acknowledge

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Acknowledge a SoD violation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `violation_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AcknowledgeViolationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `acknowledged_by` | str | Yes |  | Who acknowledged the violation |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 707. `POST` `/api/v1/access-governance/roles`

**Summary:** POST /api/v1/access-governance/roles

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Create a new role definition.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `CreateRoleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role_name` | str | Yes |  | Unique role name |
| `role_type` | str | Yes |  | business \| technical \| privileged \| service-account \| emergency |
| `permissions` | List | No | PydanticUndefined | List of permission strings |
| `owner` | str | No |  | Role owner |
| `risk_level` | str | No | medium | critical \| high \| medium \| low |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 708. `POST` `/api/v1/access-governance/roles/{role_id}/assign`

**Summary:** POST /api/v1/access-governance/roles/{role_id}/assign

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Assign a role to a user (increments user_count, grants permissions).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `role_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AssignRoleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User ID to assign role to |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 709. `GET` `/api/v1/access-governance/users/{user_id}/entitlements`

**Summary:** GET /api/v1/access-governance/users/{user_id}/entitlements

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return all entitlements for a user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |
| `status` | query | Optional | No | Filter: active \| revoked \| expired |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 710. `GET` `/api/v1/access-governance/expiring`

**Summary:** GET /api/v1/access-governance/expiring

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return active entitlements expiring within days_ahead days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `days_ahead` | query | int | No | Look-ahead window in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 711. `GET` `/api/v1/access-governance/summary`

**Summary:** GET /api/v1/access-governance/summary

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return access governance summary statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 712. `POST` `/api/v1/access-requests/requests`

**Summary:** POST /api/v1/access-requests/requests

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Create a new access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateAccessRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `requester` | str | Yes |  | User making the request |
| `resource_id` | str | No |  | Target resource identifier |
| `resource_name` | str | No |  | Human-readable resource name |
| `resource_type` | str | No | application | database \| application \| server \| network \| cloud_resource \| file_share \| api |
| `access_type` | str | No | read | read \| write \| admin \| execute \| delete \| full_control |
| `justification` | str | No |  | Business justification |
| `priority` | str | No | normal | urgent \| high \| normal \| low |
| `duration_days` | int | No | 30 | Access duration in days |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 713. `GET` `/api/v1/access-requests/requests`

**Summary:** GET /api/v1/access-requests/requests

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

List access requests, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `access_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `resource_type` | query | Optional | No | None |

**Responses:**

**200 OK** — `dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 714. `GET` `/api/v1/access-requests/requests/{request_id}`

**Summary:** GET /api/v1/access-requests/requests/{request_id}

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Fetch a single access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 715. `POST` `/api/v1/access-requests/requests/{request_id}/approve`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/approve

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Approve an access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ApproveRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  | Approver user ID |
| `notes` | str | No |  | Optional approval notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 716. `POST` `/api/v1/access-requests/requests/{request_id}/reject`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/reject

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Reject an access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RejectRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  | Approver user ID |
| `reason` | str | Yes |  | Rejection reason |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 717. `POST` `/api/v1/access-requests/requests/{request_id}/revoke`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/revoke

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Revoke access for an approved request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeAccessBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Revocation reason |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 718. `GET` `/api/v1/access-requests/stats`

**Summary:** GET /api/v1/access-requests/stats

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Return aggregate stats for access requests.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 719. `POST` `/api/v1/cloud-governance/policies`

**Summary:** POST /api/v1/cloud-governance/policies

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Create a new cloud governance policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `policy_type` | str | Yes |  | access/cost/security/compliance/resource/tagging |
| `cloud_provider` | str | No | multi_cloud | aws/azure/gcp/multi_cloud/on_premise |
| `enforcement` | str | No | advisory | advisory/warning/blocking |
| `description` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 720. `GET` `/api/v1/cloud-governance/policies`

**Summary:** GET /api/v1/cloud-governance/policies

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

List governance policies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `policy_type` | query | Optional | No | Filter by policy_type |
| `cloud_provider` | query | Optional | No | Filter by cloud_provider |
| `enforcement` | query | Optional | No | Filter by enforcement |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 721. `GET` `/api/v1/cloud-governance/policies/{policy_id}`

**Summary:** GET /api/v1/cloud-governance/policies/{policy_id}

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Return a single governance policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 722. `POST` `/api/v1/cloud-governance/violations`

**Summary:** POST /api/v1/cloud-governance/violations

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Record a new policy violation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ViolationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_id` | str | Yes |  |  |
| `resource_id` | str | Yes |  |  |
| `resource_type` | str | Yes |  |  |
| `violation_details` | str | No |  |  |
| `severity` | str | No | medium | low/medium/high/critical |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 723. `GET` `/api/v1/cloud-governance/violations`

**Summary:** GET /api/v1/cloud-governance/violations

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

List violations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `policy_id` | query | Optional | No | Filter by policy_id |
| `severity` | query | Optional | No | Filter by severity |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 724. `PUT` `/api/v1/cloud-governance/violations/{violation_id}/remediate`

**Summary:** PUT /api/v1/cloud-governance/violations/{violation_id}/remediate

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Mark a violation as remediated.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `violation_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RemediateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `remediated_by` | str | Yes |  |  |
| `action_taken` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 725. `GET` `/api/v1/cloud-governance/stats`

**Summary:** GET /api/v1/cloud-governance/stats

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Return aggregated cloud governance statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 726. `GET` `/api/v1/security-baselines/`

**Summary:** GET /api/v1/security-baselines/

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

List security baselines for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 727. `POST` `/api/v1/security-baselines/baselines`

**Summary:** POST /api/v1/security-baselines/baselines

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Create a new security baseline in draft status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `CreateBaselineRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `baseline_name` | str | Yes |  | Descriptive name for the baseline |
| `target_type` | str | Yes |  | server \| workstation \| network_device \| cloud_instance \| container \| database \| application |
| `framework` | str | Yes |  | CIS \| NIST \| STIG \| ISO27001 \| PCI-DSS \| custom |
| `version` | str | No | 1.0 | Baseline version string |
| `created_by` | str | Yes |  | Username of creator |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 728. `POST` `/api/v1/security-baselines/baselines/{baseline_id}/controls`

**Summary:** POST /api/v1/security-baselines/baselines/{baseline_id}/controls

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Add a control to a baseline.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AddControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_id` | str | Yes |  | Control identifier (e.g. CIS-1.1) |
| `control_name` | str | Yes |  | Human-readable control name |
| `category` | str | No |  | Control category |
| `description` | str | No |  | Detailed control description |
| `expected_value` | str | Yes |  | Expected configuration value |
| `severity` | str | No | medium | critical \| high \| medium \| low |
| `automated_check` | bool | No | False | Whether check can be automated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 729. `PUT` `/api/v1/security-baselines/baselines/{baseline_id}/publish`

**Summary:** PUT /api/v1/security-baselines/baselines/{baseline_id}/publish

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Publish a baseline (status=active, published_at=now).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 730. `POST` `/api/v1/security-baselines/baselines/{baseline_id}/assess`

**Summary:** POST /api/v1/security-baselines/baselines/{baseline_id}/assess

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Run a baseline assessment against a target system.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `RunAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target_name` | str | Yes |  | Target system/host name |
| `assessed_by` | str | Yes |  | Assessor username or tool name |
| `results` | List | Yes |  | Per-control assessment results |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 731. `GET` `/api/v1/security-baselines/baselines/{baseline_id}`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Return baseline detail with controls and last 5 assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 732. `GET` `/api/v1/security-baselines/baselines/{baseline_id}/drift`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}/drift

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Compare last 2 assessments to detect control drift.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 733. `GET` `/api/v1/security-baselines/baselines/{baseline_id}/trend`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}/trend

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Return compliance trend across all assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 734. `GET` `/api/v1/security-baselines/baselines`

**Summary:** GET /api/v1/security-baselines/baselines

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

List baselines for an org, optionally filtered by status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `status` | query | Optional | No | draft \| active \| deprecated |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 735. `POST` `/api/v1/security-benchmarks/benchmarks`

**Summary:** POST /api/v1/security-benchmarks/benchmarks

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Create an industry benchmark definition.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BenchmarkCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `benchmark_name` | str | Yes |  |  |
| `benchmark_source` | str | Yes |  |  |
| `sector` | str | Yes |  |  |
| `metric_name` | str | Yes |  |  |
| `metric_category` | str | Yes |  |  |
| `p25` | float | Yes |  |  |
| `p50` | float | Yes |  |  |
| `p75` | float | Yes |  |  |
| `p90` | float | Yes |  |  |
| `unit` | str | No |  |  |
| `higher_is_better` | bool | No | True |  |
| `published_date` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 736. `GET` `/api/v1/security-benchmarks/benchmarks`

**Summary:** GET /api/v1/security-benchmarks/benchmarks

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

List benchmarks with optional sector and category filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `sector` | query | Optional | No | None |
| `metric_category` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 737. `POST` `/api/v1/security-benchmarks/import-dbir`

**Summary:** POST /api/v1/security-benchmarks/import-dbir

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Import Verizon DBIR / VERIS Community Database breach incidents.  Pulls https://github.com/vz-
risk/VCDB and upserts every validated incident into the local dbir.db. The benchmark engine can then
derive industry breach-rate distributions from this incident corpus.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 738. `POST` `/api/v1/security-benchmarks/metrics`

**Summary:** POST /api/v1/security-benchmarks/metrics

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Record an org security metric measurement.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `OrgMetricCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  |  |
| `metric_category` | str | Yes |  |  |
| `value` | float | Yes |  |  |
| `unit` | str | No |  |  |
| `source` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 739. `GET` `/api/v1/security-benchmarks/metrics/{metric_name}/trend`

**Summary:** GET /api/v1/security-benchmarks/metrics/{metric_name}/trend

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Return metric trend for an org over the past N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `days` | query | int | No | 90 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 740. `POST` `/api/v1/security-benchmarks/compare`

**Summary:** POST /api/v1/security-benchmarks/compare

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Compare an org metric to a benchmark and compute percentile rank.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CompareRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `benchmark_id` | str | Yes |  |  |
| `org_metric_id` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 741. `GET` `/api/v1/security-benchmarks/summary`

**Summary:** GET /api/v1/security-benchmarks/summary

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Return benchmark comparison summary with performance counts and overall percentile.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 742. `GET` `/api/v1/security-benchmarks/`

**Summary:** GET /api/v1/security-benchmarks/

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Root endpoint — returns benchmarks list for dashboard health-checks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 743. `POST` `/api/v1/posture-benchmarking/benchmarks`

**Summary:** POST /api/v1/posture-benchmarking/benchmarks

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Create a new security posture benchmark.

**Request Body:** `CreateBenchmarkRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `benchmark_name` | str | Yes |  | Name of the benchmark |
| `framework` | str | Yes |  | Framework: cis, nist, iso27001, soc2, pci_dss, hipaa, custom |
| `version` | str | No |  | Framework version |
| `category` | str | Yes |  | Category: network, endpoint, cloud, identity, application, data, operations, compliance |
| `total_controls` | int | No | 0 | Total number of controls |
| `score` | float | No | 0.0 | Initial score |
| `industry_avg_score` | float | No | 0.0 |  |
| `percentile` | int | No | 50 |  |
| `status` | str | No | draft | Status: active, archived, draft |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 744. `GET` `/api/v1/posture-benchmarking/benchmarks`

**Summary:** GET /api/v1/posture-benchmarking/benchmarks

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List benchmarks for the org, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 745. `POST` `/api/v1/posture-benchmarking/import-cis`

**Summary:** POST /api/v1/posture-benchmarking/import-cis

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Import CIS Benchmark XCCDF controls into local catalog.  Source resolution order:   1.
``req.file_path`` (admin-uploaded XCCDF doc — used when CIS source is gated)   2. ``req.url``
(caller-supplied HTTP source)   3. Default public SCAP-Repository mirror (CIS Controls v8)

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `Optional`

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 746. `GET` `/api/v1/posture-benchmarking/cis-controls`

**Summary:** GET /api/v1/posture-benchmarking/cis-controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List imported CIS Benchmark controls with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | query | Optional | No | None |
| `profile` | query | Optional | No | e.g. L1, L2 |
| `severity` | query | Optional | No | informational\|low\|medium\|high |
| `page` | query | int | No | 1 |
| `page_size` | query | int | No | 100 |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 747. `GET` `/api/v1/posture-benchmarking/benchmarks/{benchmark_id}`

**Summary:** GET /api/v1/posture-benchmarking/benchmarks/{benchmark_id}

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Get a single benchmark by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 748. `PUT` `/api/v1/posture-benchmarking/benchmarks/{benchmark_id}/complete`

**Summary:** PUT /api/v1/posture-benchmarking/benchmarks/{benchmark_id}/complete

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Complete a benchmark assessment — sets status=active, recomputes score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 749. `POST` `/api/v1/posture-benchmarking/controls`

**Summary:** POST /api/v1/posture-benchmarking/controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Record a control assessment result.

**Request Body:** `RecordControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `benchmark_id` | str | Yes |  | Parent benchmark ID |
| `control_id` | str | No |  | Control identifier (e.g. CIS 1.1) |
| `title` | str | No |  | Control title |
| `description` | str | No |  | Control description |
| `result` | str | Yes |  | Result: pass, fail, partial, not_applicable |
| `severity` | str | Yes |  | Severity: critical, high, medium, low |
| `remediation` | str | No |  | Remediation guidance |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 750. `GET` `/api/v1/posture-benchmarking/controls`

**Summary:** GET /api/v1/posture-benchmarking/controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List controls, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `benchmark_id` | query | Optional | No | None |
| `result` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 751. `POST` `/api/v1/posture-benchmarking/comparisons`

**Summary:** POST /api/v1/posture-benchmarking/comparisons

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Add a peer-group comparison for a benchmark.

**Request Body:** `AddComparisonRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `benchmark_id` | str | Yes |  | Benchmark to compare |
| `peer_group` | str | Yes |  | Peer group: enterprise, smb, startup, government, healthcare, finance, retail |
| `peer_avg_score` | float | No | 0.0 |  |
| `our_score` | float | No | 0.0 |  |
| `percentile_rank` | int | No | 50 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 752. `GET` `/api/v1/posture-benchmarking/comparisons`

**Summary:** GET /api/v1/posture-benchmarking/comparisons

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List peer-group comparisons, optionally filtered by benchmark.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `benchmark_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 753. `GET` `/api/v1/posture-benchmarking/stats`

**Summary:** GET /api/v1/posture-benchmarking/stats

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Return aggregate benchmarking statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 754. `GET` `/api/v1/posture-history/`

**Summary:** GET /api/v1/posture-history/

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get security posture history domain summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 755. `POST` `/api/v1/posture-history/snapshots`

**Summary:** POST /api/v1/posture-history/snapshots

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Record a posture snapshot for a domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `SnapshotCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `score` | float | Yes |  |  |
| `findings_count` | int | No | 0 |  |
| `critical_count` | int | No | 0 |  |
| `high_count` | int | No | 0 |  |
| `source` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 756. `GET` `/api/v1/posture-history/snapshots`

**Summary:** GET /api/v1/posture-history/snapshots

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get posture snapshots filtered by date range and optional domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `days` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 757. `POST` `/api/v1/posture-history/trends/compute`

**Summary:** POST /api/v1/posture-history/trends/compute

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Compute and store a posture trend for a domain/period.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `TrendCompute`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `period` | str | No | monthly |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 758. `GET` `/api/v1/posture-history/trends`

**Summary:** GET /api/v1/posture-history/trends

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get computed posture trends, optionally filtered by domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 759. `PUT` `/api/v1/posture-history/baselines`

**Summary:** PUT /api/v1/posture-history/baselines

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Create or update a posture baseline for a domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BaselineSet`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `baseline_score` | float | Yes |  |  |
| `target_score` | float | Yes |  |  |
| `set_by` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 760. `GET` `/api/v1/posture-history/baselines/{domain}`

**Summary:** GET /api/v1/posture-history/baselines/{domain}

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get the baseline for a specific domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `domain` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 761. `GET` `/api/v1/posture-history/delta`

**Summary:** GET /api/v1/posture-history/delta

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get score delta (oldest to newest) for a domain over N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | str | Yes |  |
| `days` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 762. `GET` `/api/v1/posture-history/summary`

**Summary:** GET /api/v1/posture-history/summary

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get per-domain latest score, trend, and baseline gap.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 763. `POST` `/api/v1/posture-maturity/assessments`

**Summary:** Record a capability maturity assessment

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RecordAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `domain` | str | Yes |  | Security domain |
| `capability` | str | Yes |  | Capability being assessed |
| `maturity_level` | int | Yes |  | Current maturity level (1–max_level) |
| `max_level` | int | No | 5 | Maximum maturity level (default 5) |
| `evidence` | str | No |  | Supporting evidence |
| `assessor` | str | No |  | Who performed the assessment |
| `next_review` | str | No |  | ISO-8601 date/time for next review |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 764. `PUT` `/api/v1/posture-maturity/assessments/{assessment_id}`

**Summary:** Update maturity level for an assessment

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |

**Request Body:** `UpdateLevelRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `maturity_level` | int | Yes |  | New maturity level |
| `evidence` | str | No |  | Updated evidence |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 765. `POST` `/api/v1/posture-maturity/roadmap`

**Summary:** Create a roadmap item

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateRoadmapItemRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `domain` | str | Yes |  | Security domain |
| `capability` | str | Yes |  | Capability to improve |
| `current_level` | int | Yes |  | Current maturity level |
| `target_level` | int | Yes |  | Target maturity level |
| `priority` | str | No | medium | critical/high/medium/low |
| `effort` | str | No | medium | low/medium/high/very-high |
| `timeline` | str | No |  | Planned timeline (e.g. Q3 2026) |
| `owner` | str | No |  | Responsible owner |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 766. `PUT` `/api/v1/posture-maturity/roadmap/{item_id}/advance`

**Summary:** Advance roadmap item status

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `item_id` | path | str | Yes | — |

**Request Body:** `AdvanceRoadmapRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 767. `POST` `/api/v1/posture-maturity/snapshots`

**Summary:** Take a maturity snapshot

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `TakeSnapshotRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 768. `GET` `/api/v1/posture-maturity/overview`

**Summary:** Get maturity overview (snapshot + assessments + roadmap)

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 769. `GET` `/api/v1/posture-maturity/domains`

**Summary:** Get per-domain maturity breakdown

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 770. `GET` `/api/v1/posture-maturity/roadmap`

**Summary:** List roadmap items

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 771. `GET` `/api/v1/posture-maturity/overdue`

**Summary:** Get assessments with overdue reviews

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 772. `GET` `/api/v1/security-posture-pdf/download`

**Summary:** Download comprehensive security posture PDF report

**Tags:** security-posture-pdf, security-posture-pdf

**Auth:** API Key required

**Description:**

Generate and stream a comprehensive security posture PDF report.  Aggregates data from: - Security
posture score engine (risk score, grade, trend, components) - Vulnerability intelligence engine (top
10 critical CVEs) - Alerting engine (open alerts, MTTR, severity breakdown) - Cloud compliance
engine (7 framework statuses) - Asset inventory (total assets, by type/criticality/environment) -
Executive reporting engine (KPIs)  Returns a professional PDF ready for executive review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 773. `POST` `/api/v1/posture-reports/reports`

**Summary:** Create a new posture report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateReportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `report_name` | str | Yes |  | Report name |
| `report_type` | str | No | monthly | executive/board/audit/compliance/operational/monthly/quarterly/annual |
| `audience` | str | No | ciso | ciso/board/executives/auditors/regulators/team |
| `period_start` | str | Yes |  | Period start ISO date |
| `period_end` | str | Yes |  | Period end ISO date |
| `generated_by` | str | No |  | Author or system that generated the report |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 774. `POST` `/api/v1/posture-reports/reports/{report_id}/sections`

**Summary:** Add a section to a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |

**Request Body:** `AddSectionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `section_name` | str | Yes |  | Section name |
| `section_type` | str | No | summary | summary/risk/compliance/incidents/vulnerabilities/recommendations/kpis |
| `content` | str | No |  | Section content / narrative |
| `score` | float | No | 0.0 | Section score 0-100 |
| `sort_order` | int | No | 0 | Display order |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 775. `POST` `/api/v1/posture-reports/reports/{report_id}/metrics`

**Summary:** Add a metric to a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |

**Request Body:** `AddMetricRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `metric_name` | str | Yes |  | Metric name |
| `metric_value` | float | Yes |  | Current metric value |
| `metric_unit` | str | No |  | Unit label (e.g. %, ms, count) |
| `previous_value` | float | No | 0.0 | Previous period value for trend computation |
| `benchmark_value` | float | No | 0.0 | Industry benchmark value |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 776. `PUT` `/api/v1/posture-reports/reports/{report_id}/publish`

**Summary:** Publish a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 777. `GET` `/api/v1/posture-reports/reports/{report_id}`

**Summary:** Get report detail with sections and metrics

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 778. `GET` `/api/v1/posture-reports/reports`

**Summary:** List posture reports

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `report_type` | query | Optional | No | Filter by report type |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 779. `GET` `/api/v1/posture-reports/reports/latest/{report_type}`

**Summary:** Get latest report of a given type

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_type` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 780. `GET` `/api/v1/posture-reports/trends`

**Summary:** Get metric trend summary across published reports

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 781. `POST` `/api/v1/posture-scoring/controls`

**Summary:** POST /api/v1/posture-scoring/controls

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Register a new security control.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Control name |
| `domain` | str | No | governance | identity \| network \| endpoint \| cloud \| application \| data \| governance |
| `description` | str | No |  |  |
| `weight` | float | No | 1.0 | Relative importance weight |
| `control_status` | str | No | not_implemented | implemented \| partial \| not_implemented \| compensating |
| `evidence_url` | str | No |  |  |
| `last_assessed` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 782. `GET` `/api/v1/posture-scoring/controls`

**Summary:** GET /api/v1/posture-scoring/controls

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

List controls with optional domain/status filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `control_status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 783. `GET` `/api/v1/posture-scoring/controls/{control_id}`

**Summary:** GET /api/v1/posture-scoring/controls/{control_id}

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Retrieve a single control by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `control_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 784. `PATCH` `/api/v1/posture-scoring/controls/{control_id}/status`

**Summary:** PATCH /api/v1/posture-scoring/controls/{control_id}/status

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Update a control's status and optional evidence URL.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `control_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdateControlStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_status` | str | Yes |  | implemented \| partial \| not_implemented \| compensating |
| `evidence_url` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 785. `POST` `/api/v1/posture-scoring/score`

**Summary:** POST /api/v1/posture-scoring/score

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Compute weighted posture score and persist a snapshot.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CalculateScoreRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | Optional | No | None | Limit score to a specific domain; omit for all-domain score |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 786. `GET` `/api/v1/posture-scoring/history`

**Summary:** GET /api/v1/posture-scoring/history

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Retrieve posture score history snapshots.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `limit` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 787. `GET` `/api/v1/posture-scoring/stats`

**Summary:** GET /api/v1/posture-scoring/stats

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Return overall posture score, per-domain scores, and control gap counts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 788. `GET` `/api/v1/posture-scoring/context/{entity_id}`

**Summary:** GET /api/v1/posture-scoring/context/{entity_id}

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Return TrustGraph cross-domain context for a posture entity (related assets, findings, incidents).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 789. `GET` `/api/v1/posture-trends/`

**Summary:** GET /api/v1/posture-trends/

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Get security posture velocity summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 790. `POST` `/api/v1/posture-trends/datapoints`

**Summary:** POST /api/v1/posture-trends/datapoints

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Record a new security posture data point.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `RecordDatapointRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  | Name of the security metric |
| `metric_category` | str | Yes |  | vulnerability \| compliance \| identity \| network \| endpoint \| cloud \| data \| awareness |
| `value` | float | Yes |  | Metric value |
| `unit` | str | No | score | score \| percentage \| count \| days \| hours |
| `source` | str | No |  | Source system or tool |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 791. `POST` `/api/v1/posture-trends/analyze/{metric_name}`

**Summary:** POST /api/v1/posture-trends/analyze/{metric_name}

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Run trend analysis for a metric over the given period.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AnalyzeTrendRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `period_days` | int | No | 30 | Number of days to analyze |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 792. `GET` `/api/v1/posture-trends/trends`

**Summary:** GET /api/v1/posture-trends/trends

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

List latest trend analyses per metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `trend_label` | query | Optional | No | Filter by: improving \| declining \| stable |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 793. `GET` `/api/v1/posture-trends/trends/{metric_name}`

**Summary:** GET /api/v1/posture-trends/trends/{metric_name}

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Get the latest trend analysis for a specific metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 794. `POST` `/api/v1/posture-trends/targets`

**Summary:** POST /api/v1/posture-trends/targets

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Set or update a posture target for a metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `SetTargetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  | Metric to target |
| `target_value` | float | Yes |  | Desired target value |
| `current_value` | float | Yes |  | Current metric value |
| `set_by` | str | No |  | Who set the target |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 795. `PUT` `/api/v1/posture-trends/targets/{metric_name}/progress`

**Summary:** PUT /api/v1/posture-trends/targets/{metric_name}/progress

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Update the current value and recompute gap/ETA for a target.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `UpdateProgressRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `current_value` | float | Yes |  | Updated current metric value |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 796. `GET` `/api/v1/posture-trends/targets`

**Summary:** GET /api/v1/posture-trends/targets

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

List all posture targets with on_track boolean.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 797. `GET` `/api/v1/posture-trends/stagnating`

**Summary:** GET /api/v1/posture-trends/stagnating

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Return metric names with no datapoints in the last threshold_days days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `threshold_days` | query | int | No | Days without datapoints to be considered stagnating |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 798. `GET` `/api/v1/posture-trends/velocity-summary`

**Summary:** GET /api/v1/posture-trends/velocity-summary

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Return avg velocity per category plus fastest improving/declining metrics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 799. `POST` `/api/v1/identity/canonical`

**Summary:** Register a canonical asset identity

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RegisterCanonicalRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `canonical_id` | str | Yes |  | Unique canonical asset identifier |
| `org_id` | Optional | No | None |  |
| `properties` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 800. `POST` `/api/v1/identity/alias`

**Summary:** Add an alias for a canonical asset

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `AddAliasRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `canonical_id` | str | Yes |  |  |
| `alias_name` | str | Yes |  |  |
| `source` | str | No | manual |  |
| `confidence` | float | No | 1.0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 801. `POST` `/api/v1/identity/resolve`

**Summary:** Resolve an asset name to its canonical identity

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `ResolveRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Asset name to resolve |
| `org_id` | Optional | No | None |  |
| `threshold` | float | No | 0.65 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 802. `POST` `/api/v1/identity/resolve/batch`

**Summary:** Resolve multiple asset names

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `ResolveBatchRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `names` | List | Yes |  |  |
| `org_id` | Optional | No | None |  |
| `threshold` | float | No | 0.65 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 803. `GET` `/api/v1/identity/similar`

**Summary:** Find similar canonical assets

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `name` | query | str | Yes |  |
| `org_id` | query | Optional | No | None |
| `threshold` | query | float | No | 0.5 |
| `top_k` | query | int | No | 10 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 804. `GET` `/api/v1/identity/canonical`

**Summary:** List canonical assets

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | Optional | No | None |
| `limit` | query | int | No | 100 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 805. `GET` `/api/v1/identity/stats`

**Summary:** Get resolution statistics

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 806. `GET` `/api/v1/identity/health`

**Summary:** GET /api/v1/identity/health

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Fuzzy identity resolver health check.

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 807. `GET` `/api/v1/identity/findings`

**Summary:** GET /api/v1/identity/findings

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List identity resolution findings — assets with conflicting or ambiguous identities.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `limit` | query | int | No | 100 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 808. `GET` `/api/v1/identity/status`

**Summary:** GET /api/v1/identity/status

**Tags:** fuzzy-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Fuzzy identity resolver status (alias for /health).

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 809. `GET` `/api/v1/quantum-crypto/health`

**Summary:** GET /api/v1/quantum-crypto/health

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Health check alias for quantum crypto engine (mirrors /status).

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 810. `GET` `/api/v1/quantum-crypto/status`

**Summary:** GET /api/v1/quantum-crypto/status

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get quantum crypto engine status.  Honestly reports whether real ML-DSA (dilithium-py / liboqs) is
available or whether the system is running with the HMAC-SHA512 placeholder backend.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 811. `POST` `/api/v1/quantum-crypto/sign`

**Summary:** POST /api/v1/quantum-crypto/sign

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a hybrid quantum+classical signature.

**Request Body:** `SignRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `content` | str | Yes |  | Content to sign (base64 or UTF-8) |
| `key_id` | Optional | No | None | Key ID (auto-selects default) |
| `content_type` | str | No | evidence | Content type label |

**Responses:**

**200 OK** — `SignResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `signature_id` | str | Yes |  |  |
| `rsa_algorithm` | str | Yes |  |  |
| `mldsa_algorithm` | str | Yes |  |  |
| `content_hash` | str | Yes |  |  |
| `rsa_signature` | str | Yes |  |  |
| `mldsa_signature` | str | Yes |  |  |
| `worm_retention_until` | str | Yes |  |  |
| `verified` | bool | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 812. `POST` `/api/v1/quantum-crypto/verify`

**Summary:** POST /api/v1/quantum-crypto/verify

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Verify a hybrid quantum+classical signature.

**Request Body:** `VerifyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `content` | str | Yes |  | Original content |
| `signature` | Dict | Yes |  | HybridSignature envelope |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 813. `GET` `/api/v1/quantum-crypto/keys`

**Summary:** GET /api/v1/quantum-crypto/keys

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get current key information.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 814. `POST` `/api/v1/quantum-crypto/keys/rotate`

**Summary:** POST /api/v1/quantum-crypto/keys/rotate

**Tags:** Quantum Crypto

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Rotate ML-DSA keys (generates new keypair).

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 815. `GET` `/api/v1/cspm/posture`

**Summary:** Overall cloud security posture score

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the aggregated cloud security posture for the org.  The overall_score is 0-100 where higher
is better (less risk).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `OrgPosture`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `overall_score` | float | Yes |  |  |
| `total_resources` | int | Yes |  |  |
| `total_findings` | int | Yes |  |  |
| `critical_findings` | int | Yes |  |  |
| `high_findings` | int | Yes |  |  |
| `medium_findings` | int | Yes |  |  |
| `low_findings` | int | Yes |  |  |
| `accounts` | List | No | PydanticUndefined |  |
| `compliance_scores` | Dict | No | PydanticUndefined |  |
| `scanned_at` | str | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 816. `GET` `/api/v1/cspm/findings`

**Summary:** List CSPM misconfigurations

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List all CSPM findings for an org with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `status` | query | Optional | No | Filter by status |
| `severity` | query | Optional | No | Filter by severity |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 817. `GET` `/api/v1/cspm/resources`

**Summary:** Cloud resource inventory

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the full cloud resource inventory for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 818. `POST` `/api/v1/cspm/resources`

**Summary:** Register a cloud resource

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register or update a cloud resource in the CSPM inventory.

**Request Body:** `RegisterResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | CloudProvider | Yes |  |  |
| `resource_type` | ResourceType | Yes |  |  |
| `name` | str | Yes |  |  |
| `region` | str | No | global |  |
| `account_id` | str | No | unknown |  |
| `org_id` | str | No | default |  |
| `tags` | Dict | No | PydanticUndefined |  |
| `owner` | Optional | No | None |  |
| `is_public` | bool | No | False |  |
| `is_encrypted` | bool | No | True |  |
| `metadata` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `CloudResource`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `provider` | CloudProvider | Yes |  |  |
| `resource_type` | ResourceType | Yes |  |  |
| `name` | str | Yes |  |  |
| `region` | str | No | global |  |
| `account_id` | str | No | unknown |  |
| `org_id` | str | No | default |  |
| `tags` | Dict | No | PydanticUndefined |  |
| `owner` | Optional | No | None |  |
| `created_at` | Optional | No | None |  |
| `last_modified` | Optional | No | None |  |
| `is_public` | bool | No | False |  |
| `is_encrypted` | bool | No | True |  |
| `metadata` | Dict | No | PydanticUndefined |  |
| `discovered_at` | str | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 819. `GET` `/api/v1/cspm/benchmarks`

**Summary:** CIS benchmark compliance status

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return CIS Benchmark compliance status grouped by cloud provider.  Shows total/passing/failing rule
counts and per-rule status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 820. `POST` `/api/v1/cspm/scan`

**Summary:** Trigger cloud posture scan

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Trigger a CSPM scan for all registered resources in an org.  Evaluates all applicable CIS Benchmark
rules and detects configuration drift against the saved baseline. Returns the full scan result
including the updated posture score.

**Request Body:** `TriggerScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `account_ids` | List | No | PydanticUndefined |  |
| `providers` | List | No | PydanticUndefined |  |
| `rule_ids` | Optional | No | None |  |

**Responses:**

**200 OK** — `ScanResult`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `scan_id` | str | No | PydanticUndefined |  |
| `org_id` | str | No | default |  |
| `resources_scanned` | int | No | 0 |  |
| `findings_count` | int | No | 0 |  |
| `drift_events_count` | int | No | 0 |  |
| `posture` | Optional | No | None |  |
| `started_at` | str | No | PydanticUndefined |  |
| `completed_at` | str | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 821. `GET` `/api/v1/cspm/drift`

**Summary:** Configuration drift detection results

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return configuration drift events detected against the saved baseline.  Drift events include: new
public resources, removed security controls, changed encryption settings, and modified security
metadata.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 822. `POST` `/api/v1/cspm/baseline`

**Summary:** Save current state as drift baseline

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Snapshot the current resource state as the baseline for drift detection.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 823. `GET` `/api/v1/cspm/remediation/{finding_id}`

**Summary:** Remediation steps for a finding

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a step-by-step remediation playbook for a specific finding.  Includes CLI commands and
Terraform blocks where available, plus estimated effort and downtime risk indicators.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `RemediationPlaybook`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `finding_id` | str | Yes |  |  |
| `rule_id` | str | Yes |  |  |
| `title` | str | Yes |  |  |
| `steps` | List | Yes |  |  |
| `cli_commands` | List | No | PydanticUndefined |  |
| `terraform_blocks` | List | No | PydanticUndefined |  |
| `estimated_effort` | str | No | 5 minutes |  |
| `risk_level` | str | No | low |  |
| `requires_downtime` | bool | No | False |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 824. `GET` `/api/v1/cspm/compliance-map`

**Summary:** Mapping of CIS checks to compliance frameworks

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the full mapping of CIS Benchmark checks to compliance frameworks.  Frameworks covered: SOC2,
PCI-DSS, HIPAA, FedRAMP, NIST 800-53, CIS.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 825. `GET` `/api/v1/cspm/findings/{finding_id}`

**Summary:** Get a single finding

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Retrieve a single CSPM finding by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `CSPMFinding`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `rule_id` | str | No |  |  |
| `rule_title` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `resource_type` | ResourceType | No | ResourceType.EC2_INSTANCE |  |
| `provider` | CloudProvider | No | CloudProvider.AWS |  |
| `account_id` | str | No | unknown |  |
| `region` | str | No | global |  |
| `severity` | Severity | No | Severity.MEDIUM |  |
| `status` | FindingStatus | No | FindingStatus.OPEN |  |
| `description` | str | No |  |  |
| `remediation_summary` | str | No |  |  |
| `remediation_cli` | Optional | No | None |  |
| `remediation_terraform` | Optional | No | None |  |
| `compliance_mapping` | Dict | No | PydanticUndefined |  |
| `org_id` | str | No | default |  |
| `detected_at` | str | No | PydanticUndefined |  |
| `resolved_at` | Optional | No | None |  |
| `suppression_reason` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 826. `POST` `/api/v1/cspm/findings/{finding_id}/suppress`

**Summary:** Suppress a finding

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a finding as suppressed with a documented reason (e.g. accepted risk).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Request Body:** `SuppressFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Reason for suppressing this finding |

**Responses:**

**200 OK** — `CSPMFinding`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `rule_id` | str | No |  |  |
| `rule_title` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `resource_type` | ResourceType | No | ResourceType.EC2_INSTANCE |  |
| `provider` | CloudProvider | No | CloudProvider.AWS |  |
| `account_id` | str | No | unknown |  |
| `region` | str | No | global |  |
| `severity` | Severity | No | Severity.MEDIUM |  |
| `status` | FindingStatus | No | FindingStatus.OPEN |  |
| `description` | str | No |  |  |
| `remediation_summary` | str | No |  |  |
| `remediation_cli` | Optional | No | None |  |
| `remediation_terraform` | Optional | No | None |  |
| `compliance_mapping` | Dict | No | PydanticUndefined |  |
| `org_id` | str | No | default |  |
| `detected_at` | str | No | PydanticUndefined |  |
| `resolved_at` | Optional | No | None |  |
| `suppression_reason` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 827. `POST` `/api/v1/cspm/findings/{finding_id}/resolve`

**Summary:** Resolve a finding

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a finding as resolved after applying remediation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `CSPMFinding`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `rule_id` | str | No |  |  |
| `rule_title` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `resource_type` | ResourceType | No | ResourceType.EC2_INSTANCE |  |
| `provider` | CloudProvider | No | CloudProvider.AWS |  |
| `account_id` | str | No | unknown |  |
| `region` | str | No | global |  |
| `severity` | Severity | No | Severity.MEDIUM |  |
| `status` | FindingStatus | No | FindingStatus.OPEN |  |
| `description` | str | No |  |  |
| `remediation_summary` | str | No |  |  |
| `remediation_cli` | Optional | No | None |  |
| `remediation_terraform` | Optional | No | None |  |
| `compliance_mapping` | Dict | No | PydanticUndefined |  |
| `org_id` | str | No | default |  |
| `detected_at` | str | No | PydanticUndefined |  |
| `resolved_at` | Optional | No | None |  |
| `suppression_reason` | Optional | No | None |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 828. `GET` `/api/v1/cspm/scans`

**Summary:** Recent scan history

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return recent CSPM scan results for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `limit` | query | int | No | Max results |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 829. `GET` `/api/v1/cspm/resources/{resource_id}`

**Summary:** Get a single cloud resource

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Retrieve a single cloud resource from the inventory by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `CloudResource`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `provider` | CloudProvider | Yes |  |  |
| `resource_type` | ResourceType | Yes |  |  |
| `name` | str | Yes |  |  |
| `region` | str | No | global |  |
| `account_id` | str | No | unknown |  |
| `org_id` | str | No | default |  |
| `tags` | Dict | No | PydanticUndefined |  |
| `owner` | Optional | No | None |  |
| `created_at` | Optional | No | None |  |
| `last_modified` | Optional | No | None |  |
| `is_public` | bool | No | False |  |
| `is_encrypted` | bool | No | True |  |
| `metadata` | Dict | No | PydanticUndefined |  |
| `discovered_at` | str | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 830. `DELETE` `/api/v1/cspm/resources/{resource_id}`

**Summary:** Remove a cloud resource

**Tags:** CSPM

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Remove a cloud resource from the CSPM inventory.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 831. `POST` `/api/v1/cspm-engine/sync`

**Summary:** POST /api/v1/cspm-engine/sync

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Bulk-import cloud resources for an org/provider. Returns count of upserted records.

**Request Body:** `SyncResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  |  |
| `org_id` | str | No | default |  |
| `resources` | List | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 832. `GET` `/api/v1/cspm-engine/resources`

**Summary:** GET /api/v1/cspm-engine/resources

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud resources with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `category` | query | Optional | No | None |
| `public_only` | query | bool | No | False |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 833. `GET` `/api/v1/cspm-engine/resources/{resource_id}`

**Summary:** GET /api/v1/cspm-engine/resources/{resource_id}

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a cloud resource by its internal UUID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 834. `POST` `/api/v1/cspm-engine/scan`

**Summary:** POST /api/v1/cspm-engine/scan

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Run all applicable security checks for an org. Returns check results.

**Request Body:** `ScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `provider` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 835. `GET` `/api/v1/cspm-engine/results`

**Summary:** GET /api/v1/cspm-engine/results

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Retrieve stored check results with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 836. `GET` `/api/v1/cspm-engine/summary`

**Summary:** GET /api/v1/cspm-engine/summary

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return compliance summary: pass/fail counts, compliance rate, and breakdown by category.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 837. `GET` `/api/v1/cspm-engine/public`

**Summary:** GET /api/v1/cspm-engine/public

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return internet-exposed cloud resources.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 838. `GET` `/api/v1/cspm-engine/unencrypted`

**Summary:** GET /api/v1/cspm-engine/unencrypted

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return cloud resources with encryption disabled.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 839. `GET` `/api/v1/cspm-engine/iam`

**Summary:** GET /api/v1/cspm-engine/iam

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return IAM resources with overly permissive policies or misconfigurations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 840. `GET` `/api/v1/cspm-engine/score`

**Summary:** GET /api/v1/cspm-engine/score

**Tags:** cspm-engine

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a 0-100 cloud security posture score for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 841. `POST` `/api/v1/cspm/scan/iac`

**Summary:** Scan IaC template for misconfigurations

**Tags:** CSPM Deep Scan

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Scan Infrastructure-as-Code template text for cloud misconfigurations.  Supports Terraform (HCL) and
CloudFormation (JSON). Template type is auto-detected when set to 'auto'.  Checks for: - S3 buckets
with public ACLs - Security groups open to 0.0.0.0/0 - Unencrypted EBS volumes - Publicly accessible
RDS instances - Missing CloudTrail configuration - IAM policies with wildcard permissions

**Request Body:** `IaCScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `template_text` | str | Yes |  | Raw IaC template content (Terraform HCL or CloudFormation JSON) |
| `template_type` | str | No | auto | Template type: 'terraform', 'cloudformation', or 'auto' (detected by content) |
| `filename` | str | No | template | Optional filename for context |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 842. `POST` `/api/v1/cspm/scan/localstack`

**Summary:** Scan LocalStack resources for misconfigurations

**Tags:** CSPM Deep Scan

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Scan LocalStack (fake AWS at localhost:4566) for cloud misconfigurations.  Uses boto3 with a custom
endpoint URL pointing to LocalStack. Checks S3 bucket policies, IAM users and EC2 security groups.
Returns findings in the same format as IaC scanning.

**Request Body:** `LocalStackScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoint_url` | str | No | http://localhost:4566 | LocalStack endpoint URL |
| `region` | str | No | us-east-1 | AWS region to scan |
| `services` | List | No | PydanticUndefined | AWS services to scan (s3, iam, ec2) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 843. `GET` `/api/v1/cspm/score`

**Summary:** Cloud security posture score (0-100)

**Tags:** CSPM Deep Scan

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a 0-100 cloud security posture score based on recent scan results.  Score grades: - A: 90-100
(Excellent) - B: 80-89  (Good) - C: 70-79  (Fair) - D: 60-69  (Poor) - F: 0-59   (Critical risk)

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 844. `GET` `/api/v1/cspm/rules`

**Summary:** List all built-in CSPM rules

**Tags:** CSPM Deep Scan

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all built-in CSPM rules with metadata.  Rules cover AWS (40), Azure (25), and GCP (20) = 85
total. Each rule includes: rule_id, title, severity, cis_benchmark, category, description,
recommendation, compliance_frameworks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | Optional | No | Filter by provider: aws, azure, gcp |
| `severity` | query | Optional | No | Filter by severity: critical, high, medium, low, info |
| `category` | query | Optional | No | Filter by category: iam, storage, network, etc. |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 845. `GET` `/api/v1/cspm/compliance-report`

**Summary:** Cloud compliance posture report

**Tags:** CSPM Deep Scan

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a compliance posture report across all cloud providers.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 846. `POST` `/api/v1/connectors/cspm/scan`

**Summary:** POST /api/v1/connectors/cspm/scan

**Tags:** CSPM Connectors

**Auth:** API Key required

**Description:**

Run the CSPM family for a single tenant.

**Request Body:** `CSPMScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `provider` | str | No | aws |  |
| `account_id` | str | No | 000000000000 |  |
| `localstack_endpoint` | str | No | http://localhost:4566 |  |
| `iac_dir` | Optional | No | None |  |
| `run_prowler` | bool | No | True |  |
| `run_checkov` | bool | No | True |  |
| `run_cloudsploit` | bool | No | True |  |
| `run_agentless` | bool | No | True |  |
| `run_trivy` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 847. `POST` `/api/v1/connectors/cspm/scan-bulk`

**Summary:** POST /api/v1/connectors/cspm/scan-bulk

**Tags:** CSPM Connectors

**Auth:** API Key required

**Description:**

Run the CSPM family for many tenants — used by per-tenant attribution flows.

**Request Body:** `CSPMBulkScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tenants` | List | Yes |  |  |
| `provider` | str | No | aws |  |
| `account_id` | str | No | 000000000000 |  |
| `localstack_endpoint` | str | No | http://localhost:4566 |  |
| `iac_dir` | Optional | No | None |  |
| `run_prowler` | bool | No | True |  |
| `run_checkov` | bool | No | True |  |
| `run_cloudsploit` | bool | No | True |  |
| `run_agentless` | bool | No | True |  |
| `run_trivy` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 848. `GET` `/api/v1/connectors/cspm/status`

**Summary:** GET /api/v1/connectors/cspm/status

**Tags:** CSPM Connectors

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 849. `GET` `/api/v1/connectors/cspm/health`

**Summary:** GET /api/v1/connectors/cspm/health

**Tags:** CSPM Connectors

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 850. `POST` `/api/v1/drift/check`

**Summary:** Check resource against baselines

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Compare a resource's actual config against all matching baseline rules.

**Request Body:** `CheckResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resource_id` | str | Yes |  | Unique identifier of the resource |
| `resource_type` | str | Yes |  | Resource type (e.g. s3_bucket, iam_user) |
| `actual_config` | Dict | Yes |  | Current resource configuration |
| `provider` | CloudProvider | Yes |  | Cloud provider |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 851. `POST` `/api/v1/drift/check/batch`

**Summary:** Batch check resources

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Check multiple resources against baselines in a single call.

**Request Body:** `CheckBatchRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resources` | List | Yes |  | Resources to check |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 852. `GET` `/api/v1/drift/active`

**Summary:** List active drifts

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all unresolved drift findings for the organisation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `severity` | query | Optional | No | Filter by severity |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 853. `GET` `/api/v1/drift/summary`

**Summary:** Drift summary

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregated drift statistics for the organisation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `DriftSummary`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `total_resources` | int | Yes |  |  |
| `compliant` | int | Yes |  |  |
| `drifted` | int | Yes |  |  |
| `compliance_rate` | float | Yes |  |  |
| `by_severity` | Dict | Yes |  |  |
| `by_provider` | Dict | Yes |  |  |
| `top_drifts` | List | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 854. `GET` `/api/v1/drift/trend`

**Summary:** Drift trend over time

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return daily drift counts over the last N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `days` | query | int | No | Number of days to look back |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 855. `GET` `/api/v1/drift/baselines`

**Summary:** List baseline rules

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List all configured baseline rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `provider` | query | Optional | No | Filter by provider |
| `resource_type` | query | Optional | No | Filter by resource type |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 856. `POST` `/api/v1/drift/baselines`

**Summary:** Add baseline rule

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add a custom baseline rule.

**Request Body:** `BaselineRule`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `name` | str | Yes |  |  |
| `description` | str | Yes |  |  |
| `provider` | CloudProvider | Yes |  |  |
| `resource_type` | str | Yes |  |  |
| `expected_config` | Dict | Yes |  |  |
| `severity` | DriftSeverity | Yes |  |  |
| `cis_benchmark` | Optional | No | None |  |
| `remediation` | str | Yes |  |  |

**Responses:**

**200 OK** — `BaselineRule`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `name` | str | Yes |  |  |
| `description` | str | Yes |  |  |
| `provider` | CloudProvider | Yes |  |  |
| `resource_type` | str | Yes |  |  |
| `expected_config` | Dict | Yes |  |  |
| `severity` | DriftSeverity | Yes |  |  |
| `cis_benchmark` | Optional | No | None |  |
| `remediation` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 857. `DELETE` `/api/v1/drift/baselines/{rule_id}`

**Summary:** Delete baseline rule

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Delete a baseline rule by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 858. `GET` `/api/v1/drift/defaults`

**Summary:** Built-in CIS baselines

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the built-in CIS baseline rules (not yet persisted).

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 859. `POST` `/api/v1/drift/defaults/load`

**Summary:** Load built-in CIS baselines

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Persist all built-in CIS baseline rules into the database.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 860. `GET` `/api/v1/drift/history`

**Summary:** Drift history

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return drift history for an organisation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `resource_id` | query | Optional | No | Filter by resource ID |
| `days` | query | int | No | Number of days to look back |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 861. `POST` `/api/v1/drift/resolve/{drift_id}`

**Summary:** Resolve a drift finding

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a drift finding as resolved.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `drift_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 862. `GET` `/api/v1/drift/remediation/{drift_id}`

**Summary:** Get remediation steps

**Tags:** drift

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return remediation steps for a specific drift finding.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `drift_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 863. `POST` `/api/v1/posture/calculate`

**Summary:** Calculate posture score

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Compute a fresh posture score for the given org and persist it.

**Request Body:** `CalculatePostureRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `period` | str | No | current | Label for this scoring period |

**Responses:**

**200 OK** — `PostureScore`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  | Organisation identifier |
| `overall_score` | float | Yes |  | Weighted aggregate score 0-100 |
| `grade` | str | Yes |  | Letter grade A-F |
| `components` | List | No | PydanticUndefined |  |
| `calculated_at` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |
| `period` | str | No | current | Score period label |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 864. `GET` `/api/v1/posture/current`

**Summary:** Get latest posture score

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the most recent posture score for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `PostureScore`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  | Organisation identifier |
| `overall_score` | float | Yes |  | Weighted aggregate score 0-100 |
| `grade` | str | Yes |  | Letter grade A-F |
| `components` | List | No | PydanticUndefined |  |
| `calculated_at` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |
| `period` | str | No | current | Score period label |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 865. `GET` `/api/v1/posture/history`

**Summary:** Posture score history

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all persisted posture scores within the last N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `days` | query | int | No | Look-back window in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 866. `GET` `/api/v1/posture/trend`

**Summary:** Posture score trend

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return date + score pairs for chart rendering.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `days` | query | int | No | Look-back window in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 867. `GET` `/api/v1/posture/components`

**Summary:** Component score breakdown

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the latest score with full component breakdown.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `PostureScore`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  | Organisation identifier |
| `overall_score` | float | Yes |  | Weighted aggregate score 0-100 |
| `grade` | str | Yes |  | Letter grade A-F |
| `components` | List | No | PydanticUndefined |  |
| `calculated_at` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |
| `period` | str | No | current | Score period label |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 868. `POST` `/api/v1/posture/compare`

**Summary:** Compare multiple orgs

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return latest posture scores for multiple orgs, sorted by score descending.

**Request Body:** `CompareOrgsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_ids` | List | Yes |  | List of org IDs to compare |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 869. `POST` `/api/v1/posture/tracker/calculate`

**Summary:** Calculate + record posture snapshot

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Calculate current posture from live data and persist a snapshot.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `PostureSnapshot`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `snapshot_id` | str | No | PydanticUndefined | Unique snapshot identifier |
| `timestamp` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |
| `org_id` | str | Yes |  | Organisation identifier |
| `overall_score` | float | Yes |  | Posture score 0-100 |
| `critical_findings` | int | No | 0 | Open critical severity findings |
| `high_findings` | int | No | 0 | Open high severity findings |
| `medium_findings` | int | No | 0 | Open medium severity findings |
| `low_findings` | int | No | 0 | Open low severity findings |
| `sla_compliance_rate` | float | No | 0.0 | Percentage of findings resolved within SLA |
| `trustgraph_coverage` | float | No | 0.0 | Percentage of assets indexed in TrustGraph |
| `remediation_rate` | float | No | 0.0 | Findings remediated in last 30 days (%) |
| `trend` | str | No | stable | Trend vs previous snapshot: 'improving', 'stable', or 'degrading' |
| `components` | Dict | No | PydanticUndefined | Raw component scores from PostureScorer (optional) |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 870. `GET` `/api/v1/posture/tracker/current`

**Summary:** Get current posture snapshot

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the most recent posture snapshot for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `PostureSnapshot`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `snapshot_id` | str | No | PydanticUndefined | Unique snapshot identifier |
| `timestamp` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |
| `org_id` | str | Yes |  | Organisation identifier |
| `overall_score` | float | Yes |  | Posture score 0-100 |
| `critical_findings` | int | No | 0 | Open critical severity findings |
| `high_findings` | int | No | 0 | Open high severity findings |
| `medium_findings` | int | No | 0 | Open medium severity findings |
| `low_findings` | int | No | 0 | Open low severity findings |
| `sla_compliance_rate` | float | No | 0.0 | Percentage of findings resolved within SLA |
| `trustgraph_coverage` | float | No | 0.0 | Percentage of assets indexed in TrustGraph |
| `remediation_rate` | float | No | 0.0 | Findings remediated in last 30 days (%) |
| `trend` | str | No | stable | Trend vs previous snapshot: 'improving', 'stable', or 'degrading' |
| `components` | Dict | No | PydanticUndefined | Raw component scores from PostureScorer (optional) |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 871. `GET` `/api/v1/posture/tracker/trend`

**Summary:** 30-day posture trend

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all posture snapshots within the last N days, oldest first.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `days` | query | int | No | Look-back window in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 872. `GET` `/api/v1/posture/tracker/compare`

**Summary:** Compare two posture snapshots

**Tags:** posture

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Diff two posture snapshots and return score/finding deltas with a trend label.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `snapshot_id_1` | query | str | Yes | First snapshot ID |
| `snapshot_id_2` | query | str | Yes | Second snapshot ID |

**Responses:**

**200 OK** — `PostureDiff`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `snapshot_id_1` | str | Yes |  |  |
| `snapshot_id_2` | str | Yes |  |  |
| `timestamp_1` | str | Yes |  |  |
| `timestamp_2` | str | Yes |  |  |
| `org_id` | str | Yes |  |  |
| `score_delta` | float | Yes |  | score2 - score1 (positive = improved) |
| `critical_delta` | int | Yes |  | critical_findings2 - critical_findings1 |
| `high_delta` | int | Yes |  | high_findings2 - high_findings1 |
| `sla_delta` | float | Yes |  | sla_compliance_rate2 - sla_compliance_rate1 |
| `coverage_delta` | float | Yes |  | trustgraph_coverage2 - trustgraph_coverage1 |
| `remediation_delta` | float | Yes |  | remediation_rate2 - remediation_rate1 |
| `trend` | str | Yes |  | 'improving', 'stable', or 'degrading' |
| `summary` | str | Yes |  | Human-readable summary of changes |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 873. `POST` `/api/v1/posture-benchmark/generate`

**Summary:** Generate benchmark report

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Compare org posture against industry-vertical benchmarks and persist the report.

**Request Body:** `GenerateBenchmarkRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `vertical` | IndustryVertical | Yes |  | Industry vertical for comparison |
| `org_metrics` | Optional | No | None | Metric name -> measured value (optional; previously stored values used if omitted) |

**Responses:**

**200 OK** — `BenchmarkReport`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  | Organisation identifier |
| `vertical` | IndustryVertical | Yes |  | Industry vertical used for comparison |
| `metrics` | List | No | PydanticUndefined |  |
| `overall_percentile` | float | Yes |  | Weighted average percentile rank across all metrics |
| `strengths` | List | No | PydanticUndefined | Metrics where org outperforms the industry average |
| `weaknesses` | List | No | PydanticUndefined | Metrics where org underperforms the industry average |
| `recommendations` | List | No | PydanticUndefined | Prioritised improvement recommendations |
| `generated_at` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 874. `GET` `/api/v1/posture-benchmark/industry-averages`

**Summary:** Get industry benchmark averages

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return benchmark statistics (avg, p90, direction) for every metric in the vertical.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `vertical` | query | IndustryVertical | Yes | Industry vertical |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 875. `GET` `/api/v1/posture-benchmark/percentile`

**Summary:** Get percentile rank for a metric

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return where the org stands percentile-wise for a specific metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `metric_name` | query | str | Yes | Metric name (e.g. 'mttr_days') |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 876. `GET` `/api/v1/posture-benchmark/improvement-priorities`

**Summary:** Get improvement priorities

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return metrics ranked by improvement opportunity (worst percentile first) with recommendations.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 877. `GET` `/api/v1/posture-benchmark/history`

**Summary:** Get benchmark history

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all historical benchmark reports for an org, ordered chronologically.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 878. `GET` `/api/v1/posture-benchmark/latest`

**Summary:** Get latest benchmark report

**Tags:** posture-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the most recent benchmark report for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `BenchmarkReport`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | str | No | PydanticUndefined |  |
| `org_id` | str | Yes |  | Organisation identifier |
| `vertical` | IndustryVertical | Yes |  | Industry vertical used for comparison |
| `metrics` | List | No | PydanticUndefined |  |
| `overall_percentile` | float | Yes |  | Weighted average percentile rank across all metrics |
| `strengths` | List | No | PydanticUndefined | Metrics where org outperforms the industry average |
| `weaknesses` | List | No | PydanticUndefined | Metrics where org underperforms the industry average |
| `recommendations` | List | No | PydanticUndefined | Prioritised improvement recommendations |
| `generated_at` | str | No | PydanticUndefined | ISO-8601 UTC timestamp |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 879. `GET` `/api/v1/rasp/status`

**Summary:** RASP engine status and live metrics

**Tags:** RASP

**Auth:** API Key required

**Description:**

Return a combined snapshot of the RASP engine status and runtime metrics.  Includes: - Current
operating mode - Engine uptime - Request and threat counters - Category / severity breakdown - Top
attacker IPs (up to 10) - Number of active detection rules - Number of currently blocked IPs

**Responses:**

**200 OK** — `RaspStatusResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | RaspMode | Yes |  |  |
| `engine_uptime_seconds` | float | Yes |  |  |
| `requests_inspected` | int | Yes |  |  |
| `threats_detected` | int | Yes |  |  |
| `threats_blocked` | int | Yes |  |  |
| `threats_allowed_monitor` | int | Yes |  |  |
| `threats_redirected` | int | Yes |  |  |
| `false_positive_rate` | float | Yes |  |  |
| `by_category` | Dict | Yes |  |  |
| `by_severity` | Dict | Yes |  |  |
| `top_attacker_ips` | Dict | Yes |  |  |
| `active_rules` | int | Yes |  |  |
| `blocked_ips` | int | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 880. `GET` `/api/v1/rasp/threats`

**Summary:** Recent detected threats

**Tags:** RASP

**Auth:** API Key required

**Description:**

Return recent threat events from the in-memory ring buffer (max 1000).  Results are ordered newest-
first. Filter by threat category with the ``category`` query parameter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `limit` | query | int | No | Max results |
| `category` | query | Optional | No | Filter by category: sqli \| xss \| cmdi \| path_traversal \| xxe \| ssrf \| lfi \| rfi |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 881. `GET` `/api/v1/rasp/rules`

**Summary:** Active detection rules

**Tags:** RASP

**Auth:** API Key required

**Description:**

Return all detection rules (enabled and disabled).  Each rule includes: rule_id, category, name,
description, pattern, severity, confidence, and enabled flag.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 882. `PUT` `/api/v1/rasp/rules/{rule_id}`

**Summary:** Enable or disable a detection rule

**Tags:** RASP

**Auth:** API Key required

**Description:**

Enable or disable a specific detection rule by its ID (e.g. ``SQLI-001``).  Returns ``found=false``
if the rule ID does not exist.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Request Body:** `RuleToggleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | Yes |  | True to enable the rule, False to disable |

**Responses:**

**200 OK** — `RuleToggleResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_id` | str | Yes |  |  |
| `enabled` | bool | Yes |  |  |
| `found` | bool | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 883. `GET` `/api/v1/rasp/attackers`

**Summary:** Top attacker IPs with threat statistics

**Tags:** RASP

**Auth:** API Key required

**Description:**

Return the top attacker IPs ranked by total threat events, with a per-category breakdown and current
block status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `limit` | query | int | No | Max results |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 884. `PUT` `/api/v1/rasp/mode`

**Summary:** Switch RASP operating mode

**Tags:** RASP

**Auth:** API Key required

**Description:**

Switch the RASP engine operating mode at runtime:  - **monitor** — log threats and allow requests
through (default, zero friction) - **block** — reject malicious requests with HTTP 403 -
**redirect** — forward malicious requests to a honeypot URL  When switching to ``redirect`` mode you
may optionally supply a ``honeypot_url``; if omitted the existing URL is kept.

**Request Body:** `SetModeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | RaspMode | Yes |  | New operating mode: monitor \| block \| redirect |
| `honeypot_url` | Optional | No | None | Honeypot redirect URL (required when mode=redirect) |

**Responses:**

**200 OK** — `SetModeResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | RaspMode | Yes |  |  |
| `message` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 885. `GET` `/api/v1/rasp/config`

**Summary:** Current RASP configuration

**Tags:** RASP

**Auth:** API Key required

**Description:**

Return the full current RASP engine configuration, including:  - Operating mode - Honeypot URL -
Rate limiting thresholds - Body inspection limits - Trusted IP list - Enabled threat categories

**Responses:**

**200 OK** — `RaspConfig`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | RaspMode | No | RaspMode.MONITOR |  |
| `honeypot_url` | str | No | http://honeypot.internal/trap |  |
| `rate_limit` | RateLimitConfig | No | PydanticUndefined |  |
| `max_body_inspect_bytes` | int | No | 65536 |  |
| `inspect_request_body` | bool | No | True |  |
| `inspect_headers` | bool | No | True |  |
| `inspect_query_params` | bool | No | True |  |
| `trusted_ips` | List | No | PydanticUndefined |  |
| `enabled_categories` | List | No | PydanticUndefined |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 886. `POST` `/api/v1/network/zones`

**Summary:** POST /api/v1/network/zones

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Define a new network zone.

**Request Body:** `DefineZoneRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Zone name |
| `type` | ZoneType | Yes |  | Zone type |
| `cidrs` | List | No | PydanticUndefined | CIDR blocks |
| `assets` | List | No | PydanticUndefined | Asset IDs |
| `trust_level` | int | No | 50 | Trust level 0-100 |
| `metadata` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 887. `GET` `/api/v1/network/zones`

**Summary:** GET /api/v1/network/zones

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List all network zones.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 888. `GET` `/api/v1/network/zones/{zone_id}`

**Summary:** GET /api/v1/network/zones/{zone_id}

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single zone by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `zone_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 889. `POST` `/api/v1/network/flows`

**Summary:** POST /api/v1/network/flows

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record an observed network flow between two zones.

**Request Body:** `AddFlowRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `source_zone` | str | Yes |  | Source zone ID |
| `dest_zone` | str | Yes |  | Destination zone ID |
| `ports` | List | No | PydanticUndefined | Destination ports |
| `protocol` | str | No | tcp | Network protocol |
| `direction` | Optional | No | None | Flow direction (auto-detected if omitted) |
| `metadata` | Dict | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 890. `GET` `/api/v1/network/flows`

**Summary:** GET /api/v1/network/flows

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List recorded network flows.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `allowed` | query | Optional | No | Filter by allowed status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 891. `GET` `/api/v1/network/analysis/segmentation`

**Summary:** GET /api/v1/network/analysis/segmentation

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Check all flows against zone segmentation policies.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 892. `POST` `/api/v1/network/analysis/detect-violations`

**Summary:** POST /api/v1/network/analysis/detect-violations

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Detect and persist unauthorized cross-zone traffic violations.

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 893. `GET` `/api/v1/network/analysis/zone-matrix`

**Summary:** GET /api/v1/network/analysis/zone-matrix

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get zone-to-zone communication matrix.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 894. `GET` `/api/v1/network/analysis/lateral-movement`

**Summary:** GET /api/v1/network/analysis/lateral-movement

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Assess lateral movement risk across the network.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 895. `GET` `/api/v1/network/analysis/segmentation-score`

**Summary:** GET /api/v1/network/analysis/segmentation-score

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get micro-segmentation score (0-100).

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 896. `GET` `/api/v1/network/stats`

**Summary:** GET /api/v1/network/stats

**Tags:** network-segmentation

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregate network statistics.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 897. `POST` `/api/v1/access-matrix/rules`

**Summary:** POST /api/v1/access-matrix/rules

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Grant access: create or replace an access rule.

**Request Body:** `GrantAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role` | str | Yes |  | ALDECI role name |
| `resource_type` | ResourceType | Yes |  |  |
| `access_level` | AccessLevel | Yes |  |  |
| `resource_id` | Optional | No | None | None = all resources of type |
| `conditions` | Dict | No | PydanticUndefined |  |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 898. `DELETE` `/api/v1/access-matrix/rules/{rule_id}`

**Summary:** DELETE /api/v1/access-matrix/rules/{rule_id}

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Revoke an access rule by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 899. `GET` `/api/v1/access-matrix/rules`

**Summary:** GET /api/v1/access-matrix/rules

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List access rules with optional filtering.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `role` | query | Optional | No | None |
| `resource_type` | query | Optional | No | None |
| `org_id` | query | Optional | No | None |
| `limit` | query | int | No | 200 |
| `offset` | query | int | No | 0 |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 900. `POST` `/api/v1/access-matrix/check`

**Summary:** POST /api/v1/access-matrix/check

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Check what access level a role has on a resource.  Returns the resolved AccessLevel
(none/read/write/admin/owner).

**Request Body:** `CheckAccessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_role` | str | Yes |  |  |
| `resource_type` | ResourceType | Yes |  |  |
| `resource_id` | Optional | No | None |  |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `CheckAccessResponse`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_role` | str | Yes |  |  |
| `resource_type` | str | Yes |  |  |
| `resource_id` | Optional | Yes |  |  |
| `access_level` | str | Yes |  |  |
| `granted` | bool | Yes |  |  |
| `org_id` | str | Yes |  |  |

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 901. `GET` `/api/v1/access-matrix/permissions/{role}`

**Summary:** GET /api/v1/access-matrix/permissions/{role}

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return all effective (wildcard) permissions for a role.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `role` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 902. `GET` `/api/v1/access-matrix/acl/{resource_type}`

**Summary:** GET /api/v1/access-matrix/acl/{resource_type}

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the ACL for a resource type (and optionally a specific resource ID).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `resource_type` | path | ResourceType | Yes | — |
| `resource_id` | query | Optional | No | None |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 903. `GET` `/api/v1/access-matrix/stats`

**Summary:** GET /api/v1/access-matrix/stats

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregated access-check statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 904. `GET` `/api/v1/access-matrix/matrix`

**Summary:** GET /api/v1/access-matrix/matrix

**Tags:** access-matrix

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return the complete access matrix — all roles x all resource types.  Useful for rendering a
permissions grid in the UI.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 905. `POST` `/api/v1/zero-trust-legacy/policies`

**Summary:** POST /api/v1/zero-trust-legacy/policies

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a zero-trust access policy.

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Human-readable policy name |
| `conditions` | Dict | No | PydanticUndefined | Policy conditions: min_trust_level, require_mfa, allowed_networks, allowed_time_ranges, require_compliant_device, max_risk_score |
| `action` | str | Yes |  | allow \| deny \| step_up_auth \| quarantine \| monitor |
| `priority` | int | No | 50 | Lower = higher priority |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 906. `GET` `/api/v1/zero-trust-legacy/policies`

**Summary:** GET /api/v1/zero-trust-legacy/policies

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List zero-trust policies.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `active_only` | query | bool | No | True |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 907. `GET` `/api/v1/zero-trust-legacy/policies/{policy_id}`

**Summary:** GET /api/v1/zero-trust-legacy/policies/{policy_id}

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single zero-trust policy by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 908. `PUT` `/api/v1/zero-trust-legacy/policies/{policy_id}`

**Summary:** PUT /api/v1/zero-trust-legacy/policies/{policy_id}

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Update a zero-trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |

**Request Body:** `UpdatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | Optional | No | None |  |
| `conditions` | Optional | No | None |  |
| `action` | Optional | No | None |  |
| `priority` | Optional | No | None |  |
| `active` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 909. `DELETE` `/api/v1/zero-trust-legacy/policies/{policy_id}`

**Summary:** DELETE /api/v1/zero-trust-legacy/policies/{policy_id}

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Delete a zero-trust policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 910. `POST` `/api/v1/zero-trust-legacy/evaluate`

**Summary:** POST /api/v1/zero-trust-legacy/evaluate

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Evaluate an access request against all active zero-trust policies.

**Request Body:** `EvaluateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `org_id` | str | No | default |  |
| `resource` | str | No |  |  |
| `device_id` | str | No |  |  |
| `device_compliant` | bool | No | False |  |
| `network_ip` | str | No |  |  |
| `mfa_verified` | bool | No | False |  |
| `user_risk_score` | float | No | 0.0 |  |
| `timestamp` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 911. `POST` `/api/v1/zero-trust-legacy/trust-score`

**Summary:** POST /api/v1/zero-trust-legacy/trust-score

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Compute trust score for a context without recording an access decision.

**Request Body:** `TrustScoreRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | No |  |  |
| `device_compliant` | bool | No | False |  |
| `mfa_verified` | bool | No | False |  |
| `user_risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 912. `GET` `/api/v1/zero-trust-legacy/access-log`

**Summary:** GET /api/v1/zero-trust-legacy/access-log

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Query the zero-trust access evaluation log.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | query | Optional | No | None |
| `org_id` | query | str | No | default |
| `decision` | query | Optional | No | None |
| `limit` | query | int | No | 100 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 913. `GET` `/api/v1/zero-trust-legacy/analytics`

**Summary:** GET /api/v1/zero-trust-legacy/analytics

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return trust analytics: rates, averages, decision breakdown.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 914. `GET` `/api/v1/zero-trust-legacy/trust-score/{subject_id}`

**Summary:** GET /api/v1/zero-trust-legacy/trust-score/{subject_id}

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get trust score and factor breakdown for a subject (user or device).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `subject_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 915. `GET` `/api/v1/zero-trust-legacy/stats`

**Summary:** GET /api/v1/zero-trust-legacy/stats

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return policy effectiveness stats: allows/denies/challenges today, top denied resources.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 916. `GET` `/api/v1/zero-trust-legacy/segments`

**Summary:** GET /api/v1/zero-trust-legacy/segments

**Tags:** zero-trust-legacy

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return network zone micro-segmentation map with allowed paths.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 917. `POST` `/api/v1/iot-security/devices`

**Summary:** POST /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Register a new IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `DeviceCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_name` | str | No |  |  |
| `device_category` | str | No | other |  |
| `protocol` | str | No | mqtt |  |
| `ip_address` | str | No |  |  |
| `mac_address` | str | No |  |  |
| `firmware_version` | str | No |  |  |
| `last_seen` | Optional | No | None |  |
| `risk_score` | float | No | 50.0 |  |
| `status` | str | No | online |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 918. `GET` `/api/v1/iot-security/devices`

**Summary:** GET /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT devices, optionally filtered by device_category and/or status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_category` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 919. `GET` `/api/v1/iot-security/devices/{device_id}`

**Summary:** GET /api/v1/iot-security/devices/{device_id}

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Get a single IoT device by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 920. `PUT` `/api/v1/iot-security/devices/{device_id}/status`

**Summary:** PUT /api/v1/iot-security/devices/{device_id}/status

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Update the status of an IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DeviceStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 921. `POST` `/api/v1/iot-security/anomalies`

**Summary:** POST /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Record an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_id` | str | No |  |  |
| `anomaly_type` | str | No | unusual_traffic |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 922. `GET` `/api/v1/iot-security/anomalies`

**Summary:** GET /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT anomalies, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 923. `PUT` `/api/v1/iot-security/anomalies/{anomaly_id}/resolve`

**Summary:** PUT /api/v1/iot-security/anomalies/{anomaly_id}/resolve

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Resolve an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyResolve`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolution_status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 924. `POST` `/api/v1/iot-security/policies`

**Summary:** POST /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Create an IoT security policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | No |  |  |
| `policy_type` | str | No | monitoring |  |
| `applies_to_category` | str | No | all |  |
| `enforcement` | str | No | recommended |  |
| `enabled` | bool | No | True |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 925. `GET` `/api/v1/iot-security/policies`

**Summary:** GET /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT security policies, optionally filtered by enabled flag.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 926. `GET` `/api/v1/iot-security/stats`

**Summary:** GET /api/v1/iot-security/stats

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Return aggregated IoT security statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 927. `POST` `/api/v1/waf/generate`

**Summary:** Auto-generate WAF rules from a vulnerability finding

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Given a vulnerability finding, generate block + log + rate-limit WAF rules using the matching
template catalog. Rules are stored in DRAFT status.

**Request Body:** `GenerateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `finding_id` | Optional | No | None |  |
| `title` | str | Yes |  |  |
| `vuln_type` | str | No | generic |  |
| `severity` | str | No | high |  |
| `endpoint` | Optional | No | None |  |
| `parameter` | Optional | No | None |  |
| `method` | Optional | No | None |  |
| `cve_id` | Optional | No | None |  |
| `cwe_id` | Optional | No | None |  |
| `description` | str | No |  |  |
| `attack_payload` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 928. `POST` `/api/v1/waf/virtual-patch`

**Summary:** Generate a virtual patch WAF rule for an unpatched CVE

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Create a high-priority WAF blocking rule as a temporary mitigation for a CVE that cannot be patched
immediately. Rule is stored in DRAFT status.

**Request Body:** `VirtualPatchRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cve_id` | str | Yes |  |  |
| `endpoint` | str | Yes |  |  |
| `attack_vector` | str | Yes |  |  |
| `description` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 929. `GET` `/api/v1/waf/rules`

**Summary:** List WAF rules

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Return all stored rules, optionally filtered by status and/or vuln_type.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `status` | query | Optional | No | Filter by status: draft\|testing\|active\|deprecated |
| `vuln_type` | query | Optional | No | Filter by vuln type |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 930. `GET` `/api/v1/waf/rules/{rule_id}`

**Summary:** Fetch a single WAF rule

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Return full rule detail including conditions and history.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 931. `PATCH` `/api/v1/waf/rules/{rule_id}/status`

**Summary:** Transition rule lifecycle status

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Move a rule through its lifecycle: draft → testing → active → deprecated. Each transition is
recorded in the rule's history for audit purposes.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Request Body:** `StatusUpdateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 932. `POST` `/api/v1/waf/rules/{rule_id}/test`

**Summary:** Simulate WAF rule against sample requests

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Simulate the rule against provided sample requests (malicious and legitimate). Returns match results
per request and overall false-positive rate.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |

**Request Body:** `TestRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `requests` | List | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 933. `POST` `/api/v1/waf/export`

**Summary:** Export WAF rules in provider-native, OWASP CRS, or Terraform format

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Export stored rules as AWS WAF JSON, Cloudflare JSON, ModSecurity SecRules, NGINX config, Apache
config, OWASP CRS JSON, or Terraform HCL.

**Request Body:** `ExportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_ids` | Optional | No | None |  |
| `provider` | str | No | aws_waf |  |
| `format` | str | No | provider_native |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 934. `GET` `/api/v1/waf/templates`

**Summary:** List all available WAF rule templates

**Tags:** WAF Rule Generator

**Auth:** API Key required

**Description:**

Return the built-in template catalog (50+ templates). Optionally filter by vulnerability type.
Templates can be instantiated via /generate.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `vuln_type` | query | Optional | No | Filter by vuln type |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 935. `POST` `/api/v1/ciem/analyze/policy`

**Summary:** Analyze a single AWS IAM policy

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Analyze a single AWS IAM policy document for entitlement risks.  Detects wildcard permissions, admin
access, privilege escalation actions, cross-account trust without conditions, and toxic permission
combinations.

**Request Body:** `AnalyzePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy` | Dict | Yes |  | AWS IAM policy document JSON |
| `principal` | str | Yes |  | IAM entity ARN or name this policy is attached to |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 936. `POST` `/api/v1/ciem/analyze/account`

**Summary:** Analyze all IAM policies for an AWS account

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Run a full entitlement analysis across all supplied policies for an account.  Returns a summary with
severity breakdown, type breakdown, average policy score, and the full list of risks.

**Request Body:** `AnalyzeAccountRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `account_id` | str | Yes |  | AWS account ID (12-digit) |
| `policies` | List | Yes |  | List of {principal: str, policy: dict} objects |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 937. `POST` `/api/v1/ciem/suggest/least-privilege`

**Summary:** Suggest a least-privilege rewrite of an IAM policy

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a trimmed IAM policy containing only the permissions that appear in the supplied
used_permissions list.  Wildcard Action statements are collapsed to only the observed actions.
Unused statements are dropped entirely.

**Request Body:** `LeastPrivilegeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy` | Dict | Yes |  | AWS IAM policy document JSON |
| `used_permissions` | List | Yes |  | Actions actually observed in CloudTrail / usage logs |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 938. `GET` `/api/v1/ciem/risks`

**Summary:** List persisted entitlement risks

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return previously identified entitlement risks from the local database.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `principal` | query | Optional | No | Filter by principal |
| `severity` | query | Optional | No | Filter by severity (critical/high/medium/low) |
| `limit` | query | int | No | Max results |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 939. `POST` `/api/v1/ciem/escalation-paths`

**Summary:** Detect privilege escalation chains across multiple policies

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Analyse a set of principals + policies for privilege escalation paths.  Identifies when a
principal's combined permissions can be chained to gain administrative access (e.g.
CreatePolicyVersion + AttachRolePolicy, or PassRole + EC2 launch).

**Request Body:** `EscalationPathsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policies` | List | Yes |  | List of {principal: str, policy: dict} objects |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 940. `POST` `/api/v1/ciem/analyze/azure`

**Summary:** Analyze an Azure role definition or assignment

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Analyse an Azure role definition or assignment for entitlement risks.  Detects admin built-in roles
(Owner, Contributor, UAA), wildcard actions, and privilege escalation via Microsoft.Authorization.

**Request Body:** `AzureAnalyzeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role_definition` | Dict | Yes |  | Azure role definition or assignment JSON |
| `principal` | str | Yes |  | Azure object ID, UPN, or display name |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 941. `POST` `/api/v1/ciem/score`

**Summary:** Score an IAM policy (0=over-privileged, 100=least-privilege)

**Tags:** ciem

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return a numeric score for an IAM policy.  100 = perfectly least-privilege. 0   =
AdministratorAccess (wildcard on everything).

**Request Body:** `AnalyzePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy` | Dict | Yes |  | AWS IAM policy document JSON |
| `principal` | str | Yes |  | IAM entity ARN or name this policy is attached to |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 942. `GET` `/api/v1/posture-advisor/analyze`

**Summary:** Get posture analysis summary (GET)

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return posture score, grade, and top recommendations — GET version for dashboard polling.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 943. `POST` `/api/v1/posture-advisor/analyze`

**Summary:** Analyze security posture and generate recommendations

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Analyze current security posture metrics and return prioritized recommendations.

**Request Body:** `AnalyzeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `posture_score` | float | No | 50.0 | Current posture score 0-100 |
| `open_critical_vulns` | int | No | 0 | Number of open critical vulnerabilities |
| `avg_patch_time_days` | float | No | 0.0 | Average patch time in days |
| `mfa_coverage_pct` | float | No | 100.0 | MFA coverage percentage |
| `avg_mttd_hours` | float | No | 0.0 | Average mean time to detect (hours) |
| `unencrypted_databases` | int | No | 0 | Number of unencrypted databases |
| `wildcard_permissions_count` | int | No | 0 | Number of wildcard IAM permissions |
| `sla_compliance_pct` | float | No | 100.0 | SLA compliance percentage |
| `org_id` | str | No | default | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 944. `GET` `/api/v1/posture-advisor/recommendations`

**Summary:** List posture improvement recommendations

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return recommendations with optional category/priority/status filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `category` | query | Optional | No | Filter by category |
| `priority` | query | Optional | No | Filter by priority level |
| `status` | query | Optional | No | Filter by status (open/accepted/completed/dismissed) |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 945. `GET` `/api/v1/posture-advisor/recommendations/{rec_id}`

**Summary:** Get a single recommendation

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Retrieve a recommendation by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rec_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 946. `POST` `/api/v1/posture-advisor/recommendations/{rec_id}/accept`

**Summary:** Accept a recommendation

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Accept a recommendation and assign an owner with a target completion date.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rec_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AcceptRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `owner` | str | Yes |  | Owner responsible for this recommendation |
| `target_date` | str | Yes |  | ISO-8601 target completion date |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 947. `POST` `/api/v1/posture-advisor/recommendations/{rec_id}/complete`

**Summary:** Complete a recommendation

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Mark a recommendation as completed with actual improvement achieved.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rec_id` | path | str | Yes | — |

**Request Body:** `CompleteRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `completed_by` | str | Yes |  | Person who completed the recommendation |
| `actual_improvement` | float | No | 0.0 | Actual score improvement achieved |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 948. `POST` `/api/v1/posture-advisor/recommendations/{rec_id}/dismiss`

**Summary:** Dismiss a recommendation

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Dismiss a recommendation with a justification reason.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rec_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DismissRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Justification for dismissal |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 949. `GET` `/api/v1/posture-advisor/roadmap`

**Summary:** Get prioritized improvement roadmap

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Generate a 3-phase prioritized security improvement roadmap.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 950. `GET` `/api/v1/posture-advisor/stats`

**Summary:** Get advisor statistics

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregate advisor stats: analyses run, recommendations accepted/completed, avg improvement.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 951. `GET` `/api/v1/posture-advisor/score`

**Summary:** Get current posture score summary

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return overall posture score, grade and trend from the posture score engine.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 952. `GET` `/api/v1/posture-advisor/components`

**Summary:** Get posture component scores

**Tags:** posture-advisor

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return per-domain component scores for the posture breakdown chart.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 953. `POST` `/api/v1/network-topology/nodes`

**Summary:** Add a network node

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `NodeCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `node_type` | str | No | server |  |
| `hostname` | str | No |  |  |
| `ip` | str | No |  |  |
| `os` | str | No |  |  |
| `location` | str | No |  |  |
| `criticality` | str | No | medium |  |
| `tags` | List | No | PydanticUndefined |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 954. `GET` `/api/v1/network-topology/nodes`

**Summary:** List network nodes

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `node_type` | query | Optional | No | None |
| `criticality` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 955. `GET` `/api/v1/network-topology/nodes/{node_id}/neighbors`

**Summary:** Get neighbors of a node

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `node_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 956. `POST` `/api/v1/network-topology/edges`

**Summary:** Add a network edge

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `EdgeCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `src_node_id` | str | Yes |  |  |
| `dst_node_id` | str | Yes |  |  |
| `protocol` | str | Yes |  |  |
| `port` | int | Yes |  |  |
| `bidirectional` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 957. `GET` `/api/v1/network-topology/edges`

**Summary:** List network edges

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `node_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 958. `POST` `/api/v1/network-topology/segments`

**Summary:** Add a network segment

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `SegmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  |  |
| `name` | str | No |  |  |
| `vlan` | str | No |  |  |
| `subnet` | str | No |  |  |
| `zone` | str | No | internal |  |
| `node_count` | int | No | 0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 959. `GET` `/api/v1/network-topology/segments`

**Summary:** List network segments

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 960. `GET` `/api/v1/network-topology/path/{src}/{dst}`

**Summary:** Find BFS path between two nodes

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `src` | path | str | Yes | — |
| `dst` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 961. `GET` `/api/v1/network-topology/stats`

**Summary:** Topology statistics

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 962. `GET` `/api/v1/network-topology/exposure`

**Summary:** Detect external exposure to critical nodes

**Tags:** network-topology

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 963. `POST` `/api/v1/cwpp/workloads`

**Summary:** Register a workload for protection

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RegisterWorkloadRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `workload_id` | str | Yes |  | Unique workload identifier |
| `workload_type` | str | Yes |  | One of: ['container', 'vm', 'lambda', 'cloud_run', 'ecs_task', 'kubernetes_pod'] |
| `name` | str | Yes |  | Human-readable workload name |
| `metadata` | Dict | No | PydanticUndefined | Optional metadata: image, namespace, node, labels, cloud_account |
| `org_id` | str | No | default | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 964. `DELETE` `/api/v1/cwpp/workloads/{workload_id}`

**Summary:** Deregister a workload

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 965. `GET` `/api/v1/cwpp/workloads`

**Summary:** List workloads

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `workload_type` | query | Optional | No | Filter by workload type |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 966. `GET` `/api/v1/cwpp/workloads/{workload_id}`

**Summary:** Get a specific workload

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 967. `POST` `/api/v1/cwpp/workloads/{workload_id}/detect`

**Summary:** Detect threats from runtime events

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |

**Request Body:** `DetectThreatsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `events` | List | Yes |  | List of runtime events: [{"event_type": "process_exec"\|"network_conn"\|"file_write", "details": {...}}] |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 968. `POST` `/api/v1/cwpp/workloads/{workload_id}/compliance`

**Summary:** Check workload compliance

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |

**Request Body:** `ComplianceCheckRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `framework` | str | No | cis_docker | Compliance framework. One of: ['cis_docker', 'cis_kubernetes', 'nist_800_190', 'pci_dss_container'] |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 969. `GET` `/api/v1/cwpp/threats`

**Summary:** Get threat events

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `workload_id` | query | Optional | No | Filter by workload ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 970. `GET` `/api/v1/cwpp/summary`

**Summary:** Protection summary for an org

**Tags:** cwpp

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 971. `POST` `/api/v1/config-benchmark/profiles`

**Summary:** Create a benchmark profile

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `ProfileRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `standard` | str | No | CIS |  |
| `target_type` | str | No | linux_server |  |
| `version` | str | No | 1.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 972. `GET` `/api/v1/config-benchmark/profiles`

**Summary:** List benchmark profiles

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `standard` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 973. `POST` `/api/v1/config-benchmark/profiles/{profile_id}/checks`

**Summary:** Add a check to a profile

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `profile_id` | path | str | Yes | — |

**Request Body:** `CheckRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `check_ref` | str | Yes |  |  |
| `title` | str | Yes |  |  |
| `description` | str | No |  |  |
| `category` | str | No |  |  |
| `severity` | str | No | medium |  |
| `expected_value` | str | No |  |  |
| `remediation` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 974. `GET` `/api/v1/config-benchmark/profiles/{profile_id}/checks`

**Summary:** List checks for a profile

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `profile_id` | path | str | Yes | — |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 975. `POST` `/api/v1/config-benchmark/profiles/{profile_id}/assess`

**Summary:** Run assessment against a profile

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `profile_id` | path | str | Yes | — |

**Request Body:** `AssessRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target_name` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 976. `GET` `/api/v1/config-benchmark/assessments`

**Summary:** List assessments

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `profile_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 977. `GET` `/api/v1/config-benchmark/assessments/{result_id}`

**Summary:** Get assessment detail with check results

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `result_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 978. `GET` `/api/v1/config-benchmark/assessments/{result_id}/failures`

**Summary:** List failed checks for an assessment

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `result_id` | path | str | Yes | — |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 979. `GET` `/api/v1/config-benchmark/stats`

**Summary:** Aggregate benchmark statistics

**Tags:** config-benchmark

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 980. `POST` `/api/v1/cnapp/workloads`

**Summary:** POST /api/v1/cnapp/workloads

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a new cloud workload.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation ID |

**Request Body:** `RegisterWorkloadRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `workload_type` | str | No | vm |  |
| `cloud_provider` | str | No | aws |  |
| `region` | str | No |  |  |
| `image_name` | str | No |  |  |
| `image_hash` | str | No |  |  |
| `running` | bool | No | True |  |
| `privileged` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 981. `GET` `/api/v1/cnapp/workloads`

**Summary:** GET /api/v1/cnapp/workloads

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud workloads with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `workload_type` | query | Optional | No | None |
| `cloud_provider` | query | Optional | No | None |
| `running_only` | query | bool | No | True |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 982. `POST` `/api/v1/cnapp/workloads/{workload_id}/findings`

**Summary:** POST /api/v1/cnapp/workloads/{workload_id}/findings

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Add a CNAPP finding to a workload. Auto-updates workload risk_score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `workload_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AddFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `category` | str | No | misconfiguration |  |
| `severity` | str | No | medium |  |
| `title` | str | No |  |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |
| `cve_id` | str | No |  |  |
| `status` | str | No | open |  |
| `detected_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 983. `GET` `/api/v1/cnapp/findings`

**Summary:** GET /api/v1/cnapp/findings

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List CNAPP findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `category` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 984. `POST` `/api/v1/cnapp/findings/{finding_id}/suppress`

**Summary:** POST /api/v1/cnapp/findings/{finding_id}/suppress

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Suppress a CNAPP finding.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `finding_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SuppressFindingRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 985. `POST` `/api/v1/cnapp/policies`

**Summary:** POST /api/v1/cnapp/policies

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a cloud security policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `policy_type` | str | No | network |  |
| `action` | str | No | alert |  |
| `severity` | str | No | medium |  |
| `cloud_provider` | str | No | aws |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 986. `GET` `/api/v1/cnapp/policies`

**Summary:** GET /api/v1/cnapp/policies

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud policies.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `cloud_provider` | query | Optional | No | None |
| `enabled_only` | query | bool | No | True |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 987. `POST` `/api/v1/cnapp/scores/calculate`

**Summary:** POST /api/v1/cnapp/scores/calculate

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Calculate and persist the composite CNAPP score (CSPM + CWPP + CIEM).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 988. `GET` `/api/v1/cnapp/scores`

**Summary:** GET /api/v1/cnapp/scores

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List historical CNAPP scores ordered by calculated_at descending.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `limit` | query | int | No | 10 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 989. `GET` `/api/v1/cnapp/stats`

**Summary:** GET /api/v1/cnapp/stats

**Tags:** cnapp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get aggregate CNAPP stats for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 990. `GET` `/api/v1/multi-csp/providers`

**Summary:** GET /api/v1/multi-csp/providers

**Tags:** multi-csp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return list of supported cloud providers.

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 991. `POST` `/api/v1/multi-csp/scan`

**Summary:** POST /api/v1/multi-csp/scan

**Tags:** multi-csp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Run a multi-CSP scan for a given provider + account.  Routes to the appropriate adapter in
CSPM/CNAPP. For AWS/Azure/GCP (native scanners), returns an empty resources list since they rely on
IaC text input. For OCI/Alibaba/IBM, returns seeded resources + findings.

**Request Body:** `ScanRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | str | Yes |  | Provider name: aws\|azure\|gcp\|oci\|alibaba\|ibm |
| `account_id` | str | Yes |  | Cloud account identifier |
| `org_id` | str | No | default |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 992. `GET` `/api/v1/multi-csp/coverage`

**Summary:** GET /api/v1/multi-csp/coverage

**Tags:** multi-csp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return per-provider asset counts and coverage summary.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 993. `GET` `/api/v1/multi-csp/stats`

**Summary:** GET /api/v1/multi-csp/stats

**Tags:** multi-csp

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregate stats across all supported providers.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 994. `POST` `/api/v1/identity-governance/reviews`

**Summary:** Create an access review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `ReviewIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `review_type` | str | No | quarterly |  |
| `reviewer_id` | str | No |  |  |
| `start_date` | str | No |  |  |
| `due_date` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 995. `GET` `/api/v1/identity-governance/reviews`

**Summary:** List access reviews

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 996. `GET` `/api/v1/identity-governance/reviews/{review_id}`

**Summary:** Get a review with item summary

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 997. `POST` `/api/v1/identity-governance/reviews/{review_id}/items`

**Summary:** Add an item to a review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Request Body:** `ReviewItemIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `identity_name` | str | No |  |  |
| `identity_type` | str | No | user |  |
| `entitlement` | str | No |  |  |
| `entitlement_level` | str | No | read |  |
| `last_used` | Optional | No | None |  |
| `risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 998. `POST` `/api/v1/identity-governance/items/{item_id}/decision`

**Summary:** Submit a reviewer decision

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `item_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Request Body:** `DecisionIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `decision` | str | Yes |  |  |
| `reviewer_id` | str | Yes |  |  |
| `notes` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 999. `POST` `/api/v1/identity-governance/reviews/{review_id}/complete`

**Summary:** Complete an access review

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1000. `POST` `/api/v1/identity-governance/entitlements`

**Summary:** Add an entitlement

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `EntitlementIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identity_id` | str | Yes |  |  |
| `identity_name` | str | No |  |  |
| `identity_type` | str | No | user |  |
| `entitlement` | str | No |  |  |
| `system` | str | No |  |  |
| `granted_date` | str | No |  |  |
| `last_used` | Optional | No | None |  |
| `is_orphaned` | bool | No | False |  |
| `is_excessive` | bool | No | False |  |
| `risk_score` | float | No | 0.0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1001. `GET` `/api/v1/identity-governance/entitlements`

**Summary:** List entitlements

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `identity_id` | query | Optional | No | None |
| `is_orphaned` | query | Optional | No | None |
| `is_excessive` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1002. `POST` `/api/v1/identity-governance/entitlements/flag-orphaned`

**Summary:** Flag all entitlements for an identity as orphaned

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |
| `identity_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1003. `POST` `/api/v1/identity-governance/policies`

**Summary:** Create an access policy

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Request Body:** `PolicyIn`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | Yes |  |  |
| `policy_type` | str | No | least_privilege |  |
| `conditions` | Dict | No | {} |  |
| `auto_remediate` | bool | No | False |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1004. `GET` `/api/v1/identity-governance/policies`

**Summary:** List access policies

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1005. `GET` `/api/v1/identity-governance/stats`

**Summary:** Get identity governance statistics

**Tags:** identity-governance

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1006. `POST` `/api/v1/cloud-compliance/assessments`

**Summary:** POST /api/v1/cloud-compliance/assessments

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Create a new cloud compliance assessment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Request Body:** `AssessmentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cloud_provider` | str | No | aws | aws/azure/gcp/multi |
| `framework` | str | Yes |  | cis_aws_v1.5 / nist_800_53 / soc2 / etc. |
| `scope` | Dict | No | PydanticUndefined |  |
| `total_controls` | int | No | 0 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1007. `GET` `/api/v1/cloud-compliance/assessments`

**Summary:** GET /api/v1/cloud-compliance/assessments

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List assessments, optionally filtered by framework or cloud provider.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1008. `GET` `/api/v1/cloud-compliance/assessments/{assessment_id}`

**Summary:** GET /api/v1/cloud-compliance/assessments/{assessment_id}

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return assessment details with control summary.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1009. `POST` `/api/v1/cloud-compliance/assessments/{assessment_id}/controls`

**Summary:** POST /api/v1/cloud-compliance/assessments/{assessment_id}/controls

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Record a control result against an assessment.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ControlResultCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_id` | str | Yes |  |  |
| `control_name` | str | No |  |  |
| `section` | str | No |  |  |
| `severity` | str | No | medium | critical/high/medium/low/info |
| `status` | str | No | manual_check | passed/failed/not_applicable/manual_check |
| `evidence` | str | No |  |  |
| `resource_id` | str | No |  |  |
| `resource_type` | str | No |  |  |
| `resource_name` | str | No |  |  |
| `region` | str | No |  |  |
| `remediation` | str | No |  |  |
| `auto_remediated` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1010. `POST` `/api/v1/cloud-compliance/assessments/{assessment_id}/complete`

**Summary:** POST /api/v1/cloud-compliance/assessments/{assessment_id}/complete

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Mark an assessment as completed and compute final score + drift.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1011. `GET` `/api/v1/cloud-compliance/controls`

**Summary:** GET /api/v1/cloud-compliance/controls

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List control results with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `assessment_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1012. `POST` `/api/v1/cloud-compliance/remediation-plans`

**Summary:** POST /api/v1/cloud-compliance/remediation-plans

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Create a remediation plan for a control failure.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RemediationPlanCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `assessment_id` | str | Yes |  |  |
| `control_id` | str | Yes |  |  |
| `priority` | str | No | p3 | p1/p2/p3/p4 |
| `assigned_team` | str | No |  |  |
| `estimated_effort` | str | No | medium | low/medium/high |
| `target_date` | str | No |  |  |
| `notes` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1013. `PATCH` `/api/v1/cloud-compliance/remediation-plans/{plan_id}/status`

**Summary:** PATCH /api/v1/cloud-compliance/remediation-plans/{plan_id}/status

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Update the status of a remediation plan.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `plan_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RemediationStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  | planned/in_progress/completed/deferred |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1014. `GET` `/api/v1/cloud-compliance/remediation-plans`

**Summary:** GET /api/v1/cloud-compliance/remediation-plans

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

List remediation plans with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `assessment_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1015. `GET` `/api/v1/cloud-compliance/drift`

**Summary:** GET /api/v1/cloud-compliance/drift

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return compliance drift history over time.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `limit` | query | int | No | 10 |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1016. `GET` `/api/v1/cloud-compliance/stats`

**Summary:** GET /api/v1/cloud-compliance/stats

**Tags:** cloud-compliance

**Auth:** API Key required

**Description:**

Return aggregated cloud compliance statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1017. `POST` `/api/v1/ddos-protection/resources`

**Summary:** Register a protected resource

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RegisterResourceRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `name` | str | Yes |  | Friendly name for the resource |
| `ip_or_fqdn` | str | Yes |  | IP address or fully-qualified domain name |
| `resource_type` | str | Yes |  | web \| api \| dns \| network |
| `protection_tier` | str | No | basic | basic \| standard \| premium |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1018. `GET` `/api/v1/ddos-protection/resources`

**Summary:** List protected resources

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1019. `POST` `/api/v1/ddos-protection/attacks`

**Summary:** Record a DDoS attack event

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RecordAttackRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `resource_id` | str | Yes |  | Protected resource UUID |
| `attack_type` | str | Yes |  | volumetric \| protocol \| application \| slowloris \| amplification |
| `source_ips` | List | No | PydanticUndefined | List of attacking source IPs |
| `peak_gbps` | float | No | 0.0 | Peak attack volume in Gbps |
| `duration_seconds` | int | No | 0 | Attack duration in seconds |
| `status` | str | No | detected | detected \| mitigating \| mitigated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1020. `GET` `/api/v1/ddos-protection/attacks`

**Summary:** List attack events

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |
| `resource_id` | query | Optional | No | Filter by resource UUID |
| `status` | query | Optional | No | Filter by status |
| `limit` | query | int | No | Maximum records to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1021. `PATCH` `/api/v1/ddos-protection/attacks/{attack_id}/status`

**Summary:** Update attack event status

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `attack_id` | path | str | Yes | — |

**Request Body:** `UpdateAttackStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `status` | str | Yes |  | detected \| mitigating \| mitigated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1022. `POST` `/api/v1/ddos-protection/rules`

**Summary:** Create a mitigation rule

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateMitigationRuleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `name` | str | Yes |  | Rule name |
| `rule_type` | str | Yes |  | rate_limit \| geo_block \| ip_block \| challenge |
| `threshold` | Any | Yes |  | Rule threshold value |
| `action` | str | Yes |  | Action to take when rule triggers |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1023. `GET` `/api/v1/ddos-protection/rules`

**Summary:** List mitigation rules

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1024. `GET` `/api/v1/ddos-protection/stats`

**Summary:** Get DDoS stats for an org

**Tags:** DDoS Protection

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1025. `POST` `/api/v1/ot-security/assets`

**Summary:** POST /api/v1/ot-security/assets

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Register a new OT asset (PLC, HMI, SCADA, RTU, sensor, or historian).

**Request Body:** `RegisterAssetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `name` | str | Yes |  | Asset name |
| `asset_type` | str | Yes |  | Asset type: plc/hmi/scada/rtu/sensor/historian |
| `criticality` | str | No | medium | Criticality: low/medium/high/critical |
| `vendor` | str | No |  | Vendor/manufacturer |
| `firmware_version` | str | No |  | Firmware version |
| `ip_address` | str | No |  | IP address |
| `zone` | str | No |  | Network zone or purdue level |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1026. `GET` `/api/v1/ot-security/assets`

**Summary:** GET /api/v1/ot-security/assets

**Tags:** ot-security

**Auth:** API Key required

**Description:**

List OT assets with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `asset_type` | query | Optional | No | Filter by asset type |
| `criticality` | query | Optional | No | Filter by criticality |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1027. `GET` `/api/v1/ot-security/assets/{asset_id}`

**Summary:** GET /api/v1/ot-security/assets/{asset_id}

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Get a single OT asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1028. `POST` `/api/v1/ot-security/anomalies`

**Summary:** POST /api/v1/ot-security/anomalies

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Record a new anomaly against an OT asset.

**Request Body:** `RecordAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `asset_id` | str | Yes |  | Target asset ID |
| `anomaly_type` | str | Yes |  | Type of anomaly |
| `severity` | str | Yes |  | Severity: low/medium/high/critical |
| `description` | str | No |  | Anomaly description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1029. `GET` `/api/v1/ot-security/anomalies`

**Summary:** GET /api/v1/ot-security/anomalies

**Tags:** ot-security

**Auth:** API Key required

**Description:**

List OT anomalies with optional status and severity filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |
| `status` | query | Optional | No | Filter by status |
| `severity` | query | Optional | No | Filter by severity |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1030. `PUT` `/api/v1/ot-security/anomalies/{anomaly_id}/resolve`

**Summary:** PUT /api/v1/ot-security/anomalies/{anomaly_id}/resolve

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Resolve an open anomaly with a resolution note.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |

**Request Body:** `ResolveAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `resolution` | str | Yes |  | Resolution notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1031. `GET` `/api/v1/ot-security/stats`

**Summary:** GET /api/v1/ot-security/stats

**Tags:** ot-security

**Auth:** API Key required

**Description:**

Get OT environment statistics: asset counts by type/criticality, open anomalies.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1032. `POST` `/api/v1/physical-security/locations`

**Summary:** POST /api/v1/physical-security/locations

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Register a new physical location.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterLocationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Location name |
| `location_type` | str | Yes |  | office \| datacenter \| warehouse \| facility \| remote |
| `address` | Optional | No | None | Physical address |
| `security_level` | str | No | medium | low \| medium \| high \| critical |
| `capacity` | Optional | No | None | Max occupancy |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1033. `GET` `/api/v1/physical-security/locations`

**Summary:** GET /api/v1/physical-security/locations

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

List physical locations, optionally filtered by type or security level.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `location_type` | query | Optional | No | None |
| `security_level` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1034. `GET` `/api/v1/physical-security/locations/{location_id}`

**Summary:** GET /api/v1/physical-security/locations/{location_id}

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Get a specific location by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `location_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1035. `POST` `/api/v1/physical-security/events`

**Summary:** POST /api/v1/physical-security/events

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Record a physical access event.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RecordAccessEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `location_id` | str | Yes |  | Target location ID |
| `person_id` | str | Yes |  | Person or badge ID |
| `access_type` | str | Yes |  | entry \| exit \| attempt \| denied |
| `method` | str | Yes |  | badge \| biometric \| pin \| key \| tailgate |
| `timestamp` | Optional | No | None | ISO timestamp (defaults to now) |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1036. `GET` `/api/v1/physical-security/events`

**Summary:** GET /api/v1/physical-security/events

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

List access events, optionally filtered by location or access type.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `location_id` | query | Optional | No | None |
| `access_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1037. `POST` `/api/v1/physical-security/incidents`

**Summary:** POST /api/v1/physical-security/incidents

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Record a new physical security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RecordIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `location_id` | str | Yes |  | Location where incident occurred |
| `incident_type` | str | Yes |  | tailgating \| unauthorized_access \| theft \| vandalism \| fire \| flood \| other |
| `severity` | str | Yes |  | low \| medium \| high \| critical |
| `description` | Optional | No | None | Incident details |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1038. `PUT` `/api/v1/physical-security/incidents/{incident_id}/resolve`

**Summary:** PUT /api/v1/physical-security/incidents/{incident_id}/resolve

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Resolve an open physical security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ResolveIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolution` | str | Yes |  | Description of resolution taken |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1039. `GET` `/api/v1/physical-security/stats`

**Summary:** GET /api/v1/physical-security/stats

**Tags:** Physical Security

**Auth:** API Key required

**Description:**

Return physical security overview stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1040. `POST` `/api/v1/cloud-governance/policies`

**Summary:** POST /api/v1/cloud-governance/policies

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Create a new cloud governance policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `policy_type` | str | Yes |  | access/cost/security/compliance/resource/tagging |
| `cloud_provider` | str | No | multi_cloud | aws/azure/gcp/multi_cloud/on_premise |
| `enforcement` | str | No | advisory | advisory/warning/blocking |
| `description` | str | No |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1041. `GET` `/api/v1/cloud-governance/policies`

**Summary:** GET /api/v1/cloud-governance/policies

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

List governance policies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `policy_type` | query | Optional | No | Filter by policy_type |
| `cloud_provider` | query | Optional | No | Filter by cloud_provider |
| `enforcement` | query | Optional | No | Filter by enforcement |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1042. `GET` `/api/v1/cloud-governance/policies/{policy_id}`

**Summary:** GET /api/v1/cloud-governance/policies/{policy_id}

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Return a single governance policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `policy_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1043. `POST` `/api/v1/cloud-governance/violations`

**Summary:** POST /api/v1/cloud-governance/violations

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Record a new policy violation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ViolationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_id` | str | Yes |  |  |
| `resource_id` | str | Yes |  |  |
| `resource_type` | str | Yes |  |  |
| `violation_details` | str | No |  |  |
| `severity` | str | No | medium | low/medium/high/critical |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1044. `GET` `/api/v1/cloud-governance/violations`

**Summary:** GET /api/v1/cloud-governance/violations

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

List violations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `policy_id` | query | Optional | No | Filter by policy_id |
| `severity` | query | Optional | No | Filter by severity |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1045. `PUT` `/api/v1/cloud-governance/violations/{violation_id}/remediate`

**Summary:** PUT /api/v1/cloud-governance/violations/{violation_id}/remediate

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Mark a violation as remediated.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `violation_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RemediateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `remediated_by` | str | Yes |  |  |
| `action_taken` | str | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1046. `GET` `/api/v1/cloud-governance/stats`

**Summary:** GET /api/v1/cloud-governance/stats

**Tags:** cloud-governance

**Auth:** API Key required

**Description:**

Return aggregated cloud governance statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1047. `POST` `/api/v1/cloud-identity/identities`

**Summary:** POST /api/v1/cloud-identity/identities

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a new cloud identity.

**Request Body:** `RegisterIdentityRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `identity_name` | str | Yes |  |  |
| `identity_type` | str | No | user |  |
| `cloud_provider` | str | No | aws |  |
| `account_id` | str | No |  |  |
| `permissions` | List | No | [] |  |
| `privilege_level` | str | No | none |  |
| `is_federated` | bool | No | False |  |
| `mfa_enabled` | bool | No | False |  |
| `last_activity` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1048. `GET` `/api/v1/cloud-identity/identities`

**Summary:** GET /api/v1/cloud-identity/identities

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud identities with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_type` | query | Optional | No | None |
| `cloud_provider` | query | Optional | No | None |
| `privilege_level` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1049. `GET` `/api/v1/cloud-identity/identities/{identity_id}`

**Summary:** GET /api/v1/cloud-identity/identities/{identity_id}

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single cloud identity by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `identity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1050. `PUT` `/api/v1/cloud-identity/identities/{identity_id}/permissions`

**Summary:** PUT /api/v1/cloud-identity/identities/{identity_id}/permissions

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Update permissions for a cloud identity (recalculates privilege_level).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `identity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdatePermissionsRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `permissions` | List | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1051. `POST` `/api/v1/cloud-identity/reviews`

**Summary:** POST /api/v1/cloud-identity/reviews

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record an access review for a cloud identity.

**Request Body:** `RecordAccessReviewRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `identity_id` | str | Yes |  |  |
| `reviewer` | str | No |  |  |
| `review_type` | str | No | periodic |  |
| `outcome` | str | No | no_action |  |
| `findings` | List | No | [] |  |
| `reviewed_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1052. `GET` `/api/v1/cloud-identity/reviews`

**Summary:** GET /api/v1/cloud-identity/reviews

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List access reviews with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_id` | query | Optional | No | None |
| `outcome` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1053. `POST` `/api/v1/cloud-identity/permission-changes`

**Summary:** POST /api/v1/cloud-identity/permission-changes

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record a permission change for a cloud identity.

**Request Body:** `RecordPermissionChangeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `identity_id` | str | Yes |  |  |
| `change_type` | str | No | grant |  |
| `permission_name` | str | Yes |  |  |
| `changed_by` | str | No |  |  |
| `changed_at` | Optional | No | None |  |
| `approved` | bool | No | False |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1054. `GET` `/api/v1/cloud-identity/permission-changes`

**Summary:** GET /api/v1/cloud-identity/permission-changes

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List permission changes with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `identity_id` | query | Optional | No | None |
| `approved` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1055. `GET` `/api/v1/cloud-identity/stats`

**Summary:** GET /api/v1/cloud-identity/stats

**Tags:** cloud-identity

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return aggregated cloud identity statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1056. `POST` `/api/v1/iot-security/devices`

**Summary:** POST /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Register a new IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `DeviceCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_name` | str | No |  |  |
| `device_category` | str | No | other |  |
| `protocol` | str | No | mqtt |  |
| `ip_address` | str | No |  |  |
| `mac_address` | str | No |  |  |
| `firmware_version` | str | No |  |  |
| `last_seen` | Optional | No | None |  |
| `risk_score` | float | No | 50.0 |  |
| `status` | str | No | online |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1057. `GET` `/api/v1/iot-security/devices`

**Summary:** GET /api/v1/iot-security/devices

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT devices, optionally filtered by device_category and/or status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_category` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1058. `GET` `/api/v1/iot-security/devices/{device_id}`

**Summary:** GET /api/v1/iot-security/devices/{device_id}

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Get a single IoT device by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1059. `PUT` `/api/v1/iot-security/devices/{device_id}/status`

**Summary:** PUT /api/v1/iot-security/devices/{device_id}/status

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Update the status of an IoT device.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `device_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DeviceStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1060. `POST` `/api/v1/iot-security/anomalies`

**Summary:** POST /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Record an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_id` | str | No |  |  |
| `anomaly_type` | str | No | unusual_traffic |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1061. `GET` `/api/v1/iot-security/anomalies`

**Summary:** GET /api/v1/iot-security/anomalies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT anomalies, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `device_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1062. `PUT` `/api/v1/iot-security/anomalies/{anomaly_id}/resolve`

**Summary:** PUT /api/v1/iot-security/anomalies/{anomaly_id}/resolve

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Resolve an IoT anomaly.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnomalyResolve`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resolution_status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1063. `POST` `/api/v1/iot-security/policies`

**Summary:** POST /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Create an IoT security policy.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `PolicyCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policy_name` | str | No |  |  |
| `policy_type` | str | No | monitoring |  |
| `applies_to_category` | str | No | all |  |
| `enforcement` | str | No | recommended |  |
| `enabled` | bool | No | True |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1064. `GET` `/api/v1/iot-security/policies`

**Summary:** GET /api/v1/iot-security/policies

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

List IoT security policies, optionally filtered by enabled flag.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1065. `GET` `/api/v1/iot-security/stats`

**Summary:** GET /api/v1/iot-security/stats

**Tags:** IoT Security

**Auth:** API Key required

**Description:**

Return aggregated IoT security statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1066. `POST` `/api/v1/posture-benchmarking/benchmarks`

**Summary:** POST /api/v1/posture-benchmarking/benchmarks

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Create a new security posture benchmark.

**Request Body:** `CreateBenchmarkRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `benchmark_name` | str | Yes |  | Name of the benchmark |
| `framework` | str | Yes |  | Framework: cis, nist, iso27001, soc2, pci_dss, hipaa, custom |
| `version` | str | No |  | Framework version |
| `category` | str | Yes |  | Category: network, endpoint, cloud, identity, application, data, operations, compliance |
| `total_controls` | int | No | 0 | Total number of controls |
| `score` | float | No | 0.0 | Initial score |
| `industry_avg_score` | float | No | 0.0 |  |
| `percentile` | int | No | 50 |  |
| `status` | str | No | draft | Status: active, archived, draft |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1067. `GET` `/api/v1/posture-benchmarking/benchmarks`

**Summary:** GET /api/v1/posture-benchmarking/benchmarks

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List benchmarks for the org, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `framework` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1068. `POST` `/api/v1/posture-benchmarking/import-cis`

**Summary:** POST /api/v1/posture-benchmarking/import-cis

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Import CIS Benchmark XCCDF controls into local catalog.  Source resolution order:   1.
``req.file_path`` (admin-uploaded XCCDF doc — used when CIS source is gated)   2. ``req.url``
(caller-supplied HTTP source)   3. Default public SCAP-Repository mirror (CIS Controls v8)

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `Optional`

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1069. `GET` `/api/v1/posture-benchmarking/cis-controls`

**Summary:** GET /api/v1/posture-benchmarking/cis-controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List imported CIS Benchmark controls with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | query | Optional | No | None |
| `profile` | query | Optional | No | e.g. L1, L2 |
| `severity` | query | Optional | No | informational\|low\|medium\|high |
| `page` | query | int | No | 1 |
| `page_size` | query | int | No | 100 |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1070. `GET` `/api/v1/posture-benchmarking/benchmarks/{benchmark_id}`

**Summary:** GET /api/v1/posture-benchmarking/benchmarks/{benchmark_id}

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Get a single benchmark by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1071. `PUT` `/api/v1/posture-benchmarking/benchmarks/{benchmark_id}/complete`

**Summary:** PUT /api/v1/posture-benchmarking/benchmarks/{benchmark_id}/complete

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Complete a benchmark assessment — sets status=active, recomputes score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `benchmark_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1072. `POST` `/api/v1/posture-benchmarking/controls`

**Summary:** POST /api/v1/posture-benchmarking/controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Record a control assessment result.

**Request Body:** `RecordControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `benchmark_id` | str | Yes |  | Parent benchmark ID |
| `control_id` | str | No |  | Control identifier (e.g. CIS 1.1) |
| `title` | str | No |  | Control title |
| `description` | str | No |  | Control description |
| `result` | str | Yes |  | Result: pass, fail, partial, not_applicable |
| `severity` | str | Yes |  | Severity: critical, high, medium, low |
| `remediation` | str | No |  | Remediation guidance |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1073. `GET` `/api/v1/posture-benchmarking/controls`

**Summary:** GET /api/v1/posture-benchmarking/controls

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List controls, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `benchmark_id` | query | Optional | No | None |
| `result` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1074. `POST` `/api/v1/posture-benchmarking/comparisons`

**Summary:** POST /api/v1/posture-benchmarking/comparisons

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Add a peer-group comparison for a benchmark.

**Request Body:** `AddComparisonRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `benchmark_id` | str | Yes |  | Benchmark to compare |
| `peer_group` | str | Yes |  | Peer group: enterprise, smb, startup, government, healthcare, finance, retail |
| `peer_avg_score` | float | No | 0.0 |  |
| `our_score` | float | No | 0.0 |  |
| `percentile_rank` | int | No | 50 |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1075. `GET` `/api/v1/posture-benchmarking/comparisons`

**Summary:** GET /api/v1/posture-benchmarking/comparisons

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

List peer-group comparisons, optionally filtered by benchmark.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `benchmark_id` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1076. `GET` `/api/v1/posture-benchmarking/stats`

**Summary:** GET /api/v1/posture-benchmarking/stats

**Tags:** Security Posture Benchmarking

**Auth:** API Key required

**Description:**

Return aggregate benchmarking statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1077. `GET` `/api/v1/security-posture-pdf/download`

**Summary:** Download comprehensive security posture PDF report

**Tags:** security-posture-pdf, security-posture-pdf

**Auth:** API Key required

**Description:**

Generate and stream a comprehensive security posture PDF report.  Aggregates data from: - Security
posture score engine (risk score, grade, trend, components) - Vulnerability intelligence engine (top
10 critical CVEs) - Alerting engine (open alerts, MTTR, severity breakdown) - Cloud compliance
engine (7 framework statuses) - Asset inventory (total assets, by type/criticality/environment) -
Executive reporting engine (KPIs)  Returns a professional PDF ready for executive review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1078. `POST` `/api/v1/quantum-crypto/assets`

**Summary:** POST /api/v1/quantum-crypto/assets

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Register a cryptographic asset for quantum vulnerability tracking.

**Request Body:** `RegisterAssetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation identifier |
| `asset_name` | str | Yes |  | Name of the cryptographic asset |
| `asset_type` | str | Yes |  | Type: tls_certificate, vpn, signing_key, encryption_key, code_signing, database_encryption, api_key, ssh_key |
| `current_algorithm` | str | Yes |  | Current algorithm: rsa, ecdsa, dh, aes, 3des, sha1, sha256, sha384, sha512 |
| `key_size` | int | No | 0 | Key size in bits |
| `risk_level` | str | No | low | Risk level: critical, high, medium, low |
| `migration_status` | str | No | not_started | Migration status: not_started, planned, in_progress, completed, exempt |
| `discovered_at` | Optional | No | None | ISO 8601 discovery timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1079. `GET` `/api/v1/quantum-crypto/assets`

**Summary:** GET /api/v1/quantum-crypto/assets

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List cryptographic assets, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_type` | query | Optional | No | None |
| `quantum_vulnerable` | query | Optional | No | None |
| `migration_status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1080. `GET` `/api/v1/quantum-crypto/assets/{asset_id}`

**Summary:** GET /api/v1/quantum-crypto/assets/{asset_id}

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Get a single cryptographic asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1081. `PUT` `/api/v1/quantum-crypto/assets/{asset_id}/migration-status`

**Summary:** PUT /api/v1/quantum-crypto/assets/{asset_id}/migration-status

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Update the migration status of a cryptographic asset.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |

**Request Body:** `UpdateMigrationStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `migration_status` | str | Yes |  | New status: not_started, planned, in_progress, completed, exempt |
| `migrated_at` | Optional | No | None | ISO 8601 migration timestamp |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1082. `POST` `/api/v1/quantum-crypto/assessments`

**Summary:** POST /api/v1/quantum-crypto/assessments

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Create a quantum readiness assessment.

**Request Body:** `CreateAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `assessment_name` | str | Yes |  | Assessment name |
| `scope` | str | No |  | Assessment scope description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1083. `PUT` `/api/v1/quantum-crypto/assessments/{assessment_id}/complete`

**Summary:** PUT /api/v1/quantum-crypto/assessments/{assessment_id}/complete

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Complete an assessment and compute the quantum readiness score.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |

**Request Body:** `CompleteAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `total_assets` | int | Yes |  |  |
| `vulnerable_assets` | int | Yes |  |  |
| `migrated_assets` | int | Yes |  |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1084. `GET` `/api/v1/quantum-crypto/assessments`

**Summary:** GET /api/v1/quantum-crypto/assessments

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List quantum readiness assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1085. `POST` `/api/v1/quantum-crypto/migrations`

**Summary:** POST /api/v1/quantum-crypto/migrations

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Create a PQC migration plan for an asset.

**Request Body:** `CreateMigrationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `asset_id` | str | Yes |  | Asset to migrate |
| `from_algorithm` | str | No |  | Source algorithm |
| `to_algorithm` | str | No |  | Target PQC algorithm |
| `priority` | str | No | medium | Priority: immediate, high, medium, low, scheduled |
| `planned_date` | Optional | No | None | ISO 8601 planned date |
| `migrated_by` | str | No |  | Operator or system performing migration |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1086. `GET` `/api/v1/quantum-crypto/migrations`

**Summary:** GET /api/v1/quantum-crypto/migrations

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

List PQC migration plans, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_id` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `priority` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1087. `GET` `/api/v1/quantum-crypto/stats`

**Summary:** GET /api/v1/quantum-crypto/stats

**Tags:** Quantum-Safe Crypto

**Auth:** API Key required

**Description:**

Return aggregate quantum crypto statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1088. `POST` `/api/v1/ot-sec/assets`

**Summary:** POST /api/v1/ot-sec/assets

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Register a new OT asset.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `AssetCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `asset_name` | str | No |  |  |
| `asset_type` | str | Yes |  |  |
| `vendor` | str | No |  |  |
| `model` | str | No |  |  |
| `firmware_version` | str | No |  |  |
| `zone` | str | Yes |  |  |
| `protocol` | str | No | other |  |
| `risk_score` | float | No | 50.0 |  |
| `status` | str | No | operational |  |
| `last_patched` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1089. `GET` `/api/v1/ot-sec/assets`

**Summary:** GET /api/v1/ot-sec/assets

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List OT assets with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_type` | query | Optional | No | None |
| `zone` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1090. `GET` `/api/v1/ot-sec/assets/{asset_id}`

**Summary:** GET /api/v1/ot-sec/assets/{asset_id}

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Get a single OT asset by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1091. `PUT` `/api/v1/ot-sec/assets/{asset_id}/status`

**Summary:** PUT /api/v1/ot-sec/assets/{asset_id}/status

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Update asset operational status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `asset_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AssetStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1092. `POST` `/api/v1/ot-sec/incidents`

**Summary:** POST /api/v1/ot-sec/incidents

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Record an OT security incident.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `IncidentCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `asset_id` | str | No |  |  |
| `incident_type` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `impact_level` | str | No | none |  |
| `detected_at` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1093. `GET` `/api/v1/ot-sec/incidents`

**Summary:** GET /api/v1/ot-sec/incidents

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List incidents with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `asset_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1094. `PUT` `/api/v1/ot-sec/incidents/{incident_id}/status`

**Summary:** PUT /api/v1/ot-sec/incidents/{incident_id}/status

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Update incident status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `IncidentStatusUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `status` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1095. `POST` `/api/v1/ot-sec/zones`

**Summary:** POST /api/v1/ot-sec/zones

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Create an OT network zone.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ZoneCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `zone_name` | str | No |  |  |
| `zone_type` | str | Yes |  |  |
| `asset_count` | int | No | 0 |  |
| `security_level` | str | No | sl1 |  |
| `purdue_level` | int | No | 0 |  |
| `conduit_count` | int | No | 0 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1096. `GET` `/api/v1/ot-sec/zones`

**Summary:** GET /api/v1/ot-sec/zones

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

List zones with optional zone_type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `zone_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1097. `GET` `/api/v1/ot-sec/stats`

**Summary:** GET /api/v1/ot-sec/stats

**Tags:** Operational Technology Security

**Auth:** API Key required

**Description:**

Return aggregated OT security statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1098. `GET` `/api/v1/network-forensics/`

**Summary:** GET /api/v1/network-forensics/

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List network forensics captures for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1099. `POST` `/api/v1/network-forensics/captures`

**Summary:** POST /api/v1/network-forensics/captures

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CaptureCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `interface` | str | Yes |  |  |
| `filter_bpf` | str | No |  |  |
| `duration_sec` | int | No | 60 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1100. `GET` `/api/v1/network-forensics/captures`

**Summary:** GET /api/v1/network-forensics/captures

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1101. `GET` `/api/v1/network-forensics/captures/{capture_id}`

**Summary:** GET /api/v1/network-forensics/captures/{capture_id}

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1102. `POST` `/api/v1/network-forensics/captures/{capture_id}/artifacts`

**Summary:** POST /api/v1/network-forensics/captures/{capture_id}/artifacts

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ArtifactCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `artifact_type` | str | No | pcap |  |
| `size_bytes` | int | No | 0 |  |
| `findings_count` | int | No | 0 |  |
| `analysis_json` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1103. `POST` `/api/v1/network-forensics/captures/{capture_id}/analyze`

**Summary:** POST /api/v1/network-forensics/captures/{capture_id}/analyze

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `capture_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `AnalyzeRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `suspicious_ips` | List | No | [] |  |
| `protocols_seen` | List | No | [] |  |
| `anomalies` | List | No | [] |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1104. `GET` `/api/v1/network-forensics/artifacts`

**Summary:** GET /api/v1/network-forensics/artifacts

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `capture_id` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1105. `GET` `/api/v1/network-forensics/stats`

**Summary:** GET /api/v1/network-forensics/stats

**Tags:** Network Forensics

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1106. `POST` `/api/v1/posture-scoring/controls`

**Summary:** POST /api/v1/posture-scoring/controls

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Register a new security control.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RegisterControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  | Control name |
| `domain` | str | No | governance | identity \| network \| endpoint \| cloud \| application \| data \| governance |
| `description` | str | No |  |  |
| `weight` | float | No | 1.0 | Relative importance weight |
| `control_status` | str | No | not_implemented | implemented \| partial \| not_implemented \| compensating |
| `evidence_url` | str | No |  |  |
| `last_assessed` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1107. `GET` `/api/v1/posture-scoring/controls`

**Summary:** GET /api/v1/posture-scoring/controls

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

List controls with optional domain/status filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `control_status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1108. `GET` `/api/v1/posture-scoring/controls/{control_id}`

**Summary:** GET /api/v1/posture-scoring/controls/{control_id}

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Retrieve a single control by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `control_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1109. `PATCH` `/api/v1/posture-scoring/controls/{control_id}/status`

**Summary:** PATCH /api/v1/posture-scoring/controls/{control_id}/status

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Update a control's status and optional evidence URL.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `control_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `UpdateControlStatusRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_status` | str | Yes |  | implemented \| partial \| not_implemented \| compensating |
| `evidence_url` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1110. `POST` `/api/v1/posture-scoring/score`

**Summary:** POST /api/v1/posture-scoring/score

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Compute weighted posture score and persist a snapshot.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CalculateScoreRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | Optional | No | None | Limit score to a specific domain; omit for all-domain score |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1111. `GET` `/api/v1/posture-scoring/history`

**Summary:** GET /api/v1/posture-scoring/history

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Retrieve posture score history snapshots.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `limit` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1112. `GET` `/api/v1/posture-scoring/stats`

**Summary:** GET /api/v1/posture-scoring/stats

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Return overall posture score, per-domain scores, and control gap counts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1113. `GET` `/api/v1/posture-scoring/context/{entity_id}`

**Summary:** GET /api/v1/posture-scoring/context/{entity_id}

**Tags:** Security Posture Scoring

**Auth:** API Key required

**Description:**

Return TrustGraph cross-domain context for a posture entity (related assets, findings, incidents).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entity_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1114. `POST` `/api/v1/cloud-access-security/apps`

**Summary:** POST /api/v1/cloud-access-security/apps

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Register a cloud application.

**Request Body:** `RegisterCloudAppRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | Yes |  |  |
| `app_category` | str | No | saas |  |
| `vendor` | str | No |  |  |
| `risk_level` | str | No | medium |  |
| `data_exposure_level` | str | No | internal |  |
| `sanctioned` | bool | No | True |  |
| `discovered_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1115. `GET` `/api/v1/cloud-access-security/apps`

**Summary:** GET /api/v1/cloud-access-security/apps

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List cloud apps with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `app_category` | query | Optional | No | None |
| `risk_level` | query | Optional | No | None |
| `sanctioned` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1116. `GET` `/api/v1/cloud-access-security/apps/{app_id}`

**Summary:** GET /api/v1/cloud-access-security/apps/{app_id}

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Get a single cloud app by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `app_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1117. `POST` `/api/v1/cloud-access-security/events`

**Summary:** POST /api/v1/cloud-access-security/events

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Record a cloud app access event.

**Request Body:** `RecordAccessEventRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `app_id` | str | Yes |  |  |
| `user_id` | str | No |  |  |
| `access_type` | str | No | oauth |  |
| `data_accessed` | str | No |  |  |
| `bytes_transferred` | int | No | 0 |  |
| `source_ip` | str | No |  |  |
| `success` | bool | No | True |  |
| `occurred_at` | Optional | No | None |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1118. `POST` `/api/v1/cloud-access-security/policies`

**Summary:** POST /api/v1/cloud-access-security/policies

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Create a cloud access policy.

**Request Body:** `CreatePolicyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default |  |
| `name` | str | No |  |  |
| `app_category` | str | No | saas |  |
| `policy_action` | str | No | monitor |  |
| `conditions_json` | Dict | No | {} |  |
| `enabled` | bool | No | True |  |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1119. `GET` `/api/v1/cloud-access-security/policies`

**Summary:** GET /api/v1/cloud-access-security/policies

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

List policies with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |
| `app_category` | query | Optional | No | None |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1120. `GET` `/api/v1/cloud-access-security/stats`

**Summary:** GET /api/v1/cloud-access-security/stats

**Tags:** cloud-access-security

**Auth:** See app-level auth (API Key via `X-API-Key` header)

**Description:**

Return cloud access security statistics for an org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1121. `POST` `/api/v1/digital-twin/twins`

**Summary:** POST /api/v1/digital-twin/twins

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Create a new digital twin.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `TwinCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | str | Yes |  |  |
| `twin_type` | str | No | network |  |
| `description` | str | No |  |  |
| `asset_count` | int | No | 0 |  |
| `fidelity_level` | str | No | medium |  |
| `sync_status` | str | No | stale |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1122. `GET` `/api/v1/digital-twin/twins`

**Summary:** GET /api/v1/digital-twin/twins

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List digital twins with optional type filter.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_type` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1123. `GET` `/api/v1/digital-twin/twins/{twin_id}`

**Summary:** GET /api/v1/digital-twin/twins/{twin_id}

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Get a single digital twin by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `twin_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1124. `POST` `/api/v1/digital-twin/twins/{twin_id}/simulations`

**Summary:** POST /api/v1/digital-twin/twins/{twin_id}/simulations

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Run a simulation on a digital twin.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `twin_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `SimulationCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `simulation_type` | str | No | attack_path |  |
| `parameters_json` | dict | No | {} |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1125. `GET` `/api/v1/digital-twin/simulations`

**Summary:** GET /api/v1/digital-twin/simulations

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List simulations with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_id` | query | Optional | No | None |
| `simulation_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1126. `POST` `/api/v1/digital-twin/simulations/{simulation_id}/findings`

**Summary:** POST /api/v1/digital-twin/simulations/{simulation_id}/findings

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Add a finding to a simulation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `simulation_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `FindingCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `title` | str | Yes |  |  |
| `severity` | str | No | medium |  |
| `description` | str | No |  |  |
| `remediation` | str | No |  |  |
| `twin_id` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1127. `GET` `/api/v1/digital-twin/findings`

**Summary:** GET /api/v1/digital-twin/findings

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

List findings with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `twin_id` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1128. `GET` `/api/v1/digital-twin/stats`

**Summary:** GET /api/v1/digital-twin/stats

**Tags:** Digital Twin Security

**Auth:** API Key required

**Description:**

Return aggregated digital twin statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1129. `POST` `/api/v1/access-requests/requests`

**Summary:** POST /api/v1/access-requests/requests

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Create a new access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CreateAccessRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `requester` | str | Yes |  | User making the request |
| `resource_id` | str | No |  | Target resource identifier |
| `resource_name` | str | No |  | Human-readable resource name |
| `resource_type` | str | No | application | database \| application \| server \| network \| cloud_resource \| file_share \| api |
| `access_type` | str | No | read | read \| write \| admin \| execute \| delete \| full_control |
| `justification` | str | No |  | Business justification |
| `priority` | str | No | normal | urgent \| high \| normal \| low |
| `duration_days` | int | No | 30 | Access duration in days |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1130. `GET` `/api/v1/access-requests/requests`

**Summary:** GET /api/v1/access-requests/requests

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

List access requests, optionally filtered.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `access_type` | query | Optional | No | None |
| `status` | query | Optional | No | None |
| `resource_type` | query | Optional | No | None |

**Responses:**

**200 OK** — `dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1131. `GET` `/api/v1/access-requests/requests/{request_id}`

**Summary:** GET /api/v1/access-requests/requests/{request_id}

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Fetch a single access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1132. `POST` `/api/v1/access-requests/requests/{request_id}/approve`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/approve

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Approve an access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ApproveRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  | Approver user ID |
| `notes` | str | No |  | Optional approval notes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1133. `POST` `/api/v1/access-requests/requests/{request_id}/reject`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/reject

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Reject an access request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RejectRequestBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `approver` | str | Yes |  | Approver user ID |
| `reason` | str | Yes |  | Rejection reason |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1134. `POST` `/api/v1/access-requests/requests/{request_id}/revoke`

**Summary:** POST /api/v1/access-requests/requests/{request_id}/revoke

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Revoke access for an approved request.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `request_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `RevokeAccessBody`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reason` | str | Yes |  | Revocation reason |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1135. `GET` `/api/v1/access-requests/stats`

**Summary:** GET /api/v1/access-requests/stats

**Tags:** Access Request Management

**Auth:** API Key required

**Description:**

Return aggregate stats for access requests.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1136. `POST` `/api/v1/access-reviews/reviews`

**Summary:** POST /api/v1/access-reviews/reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Create a new access review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ReviewCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `review_name` | str | Yes |  |  |
| `review_type` | str | No | quarterly |  |
| `reviewer_id` | str | No |  |  |
| `due_date` | Optional | No | None |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1137. `GET` `/api/v1/access-reviews/reviews`

**Summary:** GET /api/v1/access-reviews/reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

List access reviews, optionally filtered by status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1138. `GET` `/api/v1/access-reviews/reviews/{review_id}`

**Summary:** GET /api/v1/access-reviews/reviews/{review_id}

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get a review with all its items.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1139. `POST` `/api/v1/access-reviews/reviews/{review_id}/items`

**Summary:** POST /api/v1/access-reviews/reviews/{review_id}/items

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Add an item to an access review.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `ReviewItemCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  |  |
| `resource_id` | str | Yes |  |  |
| `resource_type` | str | No |  |  |
| `access_level` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1140. `POST` `/api/v1/access-reviews/reviews/{review_id}/items/{item_id}/decide`

**Summary:** POST /api/v1/access-reviews/reviews/{review_id}/items/{item_id}/decide

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Record a certify/revoke/modify/defer decision on a review item.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `review_id` | path | str | Yes | — |
| `item_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Request Body:** `DecisionCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `decision` | str | Yes |  |  |
| `decision_reason` | str | No |  |  |
| `decided_by` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1141. `GET` `/api/v1/access-reviews/overdue`

**Summary:** GET /api/v1/access-reviews/overdue

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get access reviews past their due date that are not completed.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1142. `POST` `/api/v1/access-reviews/campaigns`

**Summary:** POST /api/v1/access-reviews/campaigns

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Create a review campaign.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CampaignCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `campaign_name` | str | Yes |  |  |
| `frequency` | str | No | quarterly |  |
| `scope` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1143. `GET` `/api/v1/access-reviews/campaigns/stats`

**Summary:** GET /api/v1/access-reviews/campaigns/stats

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get aggregated campaign stats.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1144. `GET` `/api/v1/access-reviews/summary`

**Summary:** GET /api/v1/access-reviews/summary

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Get total/pending/completed/overdue review counts.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1145. `GET` `/api/v1/access-reviews`

**Summary:** GET /api/v1/access-reviews

**Tags:** User Access Review

**Auth:** API Key required

**Description:**

Root endpoint — returns reviews list for dashboard health-checks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1146. `GET` `/api/v1/posture-history/`

**Summary:** GET /api/v1/posture-history/

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get security posture history domain summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1147. `POST` `/api/v1/posture-history/snapshots`

**Summary:** POST /api/v1/posture-history/snapshots

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Record a posture snapshot for a domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `SnapshotCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `score` | float | Yes |  |  |
| `findings_count` | int | No | 0 |  |
| `critical_count` | int | No | 0 |  |
| `high_count` | int | No | 0 |  |
| `source` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1148. `GET` `/api/v1/posture-history/snapshots`

**Summary:** GET /api/v1/posture-history/snapshots

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get posture snapshots filtered by date range and optional domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |
| `days` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1149. `POST` `/api/v1/posture-history/trends/compute`

**Summary:** POST /api/v1/posture-history/trends/compute

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Compute and store a posture trend for a domain/period.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `TrendCompute`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `period` | str | No | monthly |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1150. `GET` `/api/v1/posture-history/trends`

**Summary:** GET /api/v1/posture-history/trends

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get computed posture trends, optionally filtered by domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1151. `PUT` `/api/v1/posture-history/baselines`

**Summary:** PUT /api/v1/posture-history/baselines

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Create or update a posture baseline for a domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BaselineSet`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | str | Yes |  |  |
| `baseline_score` | float | Yes |  |  |
| `target_score` | float | Yes |  |  |
| `set_by` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1152. `GET` `/api/v1/posture-history/baselines/{domain}`

**Summary:** GET /api/v1/posture-history/baselines/{domain}

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get the baseline for a specific domain.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `domain` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1153. `GET` `/api/v1/posture-history/delta`

**Summary:** GET /api/v1/posture-history/delta

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get score delta (oldest to newest) for a domain over N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `domain` | query | str | Yes |  |
| `days` | query | int | No | 30 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1154. `GET` `/api/v1/posture-history/summary`

**Summary:** GET /api/v1/posture-history/summary

**Tags:** Security Posture History

**Auth:** API Key required

**Description:**

Get per-domain latest score, trend, and baseline gap.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1155. `GET` `/api/v1/posture-trends/`

**Summary:** GET /api/v1/posture-trends/

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Get security posture velocity summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1156. `POST` `/api/v1/posture-trends/datapoints`

**Summary:** POST /api/v1/posture-trends/datapoints

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Record a new security posture data point.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `RecordDatapointRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  | Name of the security metric |
| `metric_category` | str | Yes |  | vulnerability \| compliance \| identity \| network \| endpoint \| cloud \| data \| awareness |
| `value` | float | Yes |  | Metric value |
| `unit` | str | No | score | score \| percentage \| count \| days \| hours |
| `source` | str | No |  | Source system or tool |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1157. `POST` `/api/v1/posture-trends/analyze/{metric_name}`

**Summary:** POST /api/v1/posture-trends/analyze/{metric_name}

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Run trend analysis for a metric over the given period.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AnalyzeTrendRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `period_days` | int | No | 30 | Number of days to analyze |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1158. `GET` `/api/v1/posture-trends/trends`

**Summary:** GET /api/v1/posture-trends/trends

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

List latest trend analyses per metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `trend_label` | query | Optional | No | Filter by: improving \| declining \| stable |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1159. `GET` `/api/v1/posture-trends/trends/{metric_name}`

**Summary:** GET /api/v1/posture-trends/trends/{metric_name}

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Get the latest trend analysis for a specific metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1160. `POST` `/api/v1/posture-trends/targets`

**Summary:** POST /api/v1/posture-trends/targets

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Set or update a posture target for a metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `SetTargetRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  | Metric to target |
| `target_value` | float | Yes |  | Desired target value |
| `current_value` | float | Yes |  | Current metric value |
| `set_by` | str | No |  | Who set the target |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1161. `PUT` `/api/v1/posture-trends/targets/{metric_name}/progress`

**Summary:** PUT /api/v1/posture-trends/targets/{metric_name}/progress

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Update the current value and recompute gap/ETA for a target.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `UpdateProgressRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `current_value` | float | Yes |  | Updated current metric value |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1162. `GET` `/api/v1/posture-trends/targets`

**Summary:** GET /api/v1/posture-trends/targets

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

List all posture targets with on_track boolean.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1163. `GET` `/api/v1/posture-trends/stagnating`

**Summary:** GET /api/v1/posture-trends/stagnating

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Return metric names with no datapoints in the last threshold_days days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `threshold_days` | query | int | No | Days without datapoints to be considered stagnating |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1164. `GET` `/api/v1/posture-trends/velocity-summary`

**Summary:** GET /api/v1/posture-trends/velocity-summary

**Tags:** Security Posture Trends

**Auth:** API Key required

**Description:**

Return avg velocity per category plus fastest improving/declining metrics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1165. `GET` `/api/v1/access-governance/`

**Summary:** GET /api/v1/access-governance/

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Get access governance summary for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1166. `POST` `/api/v1/access-governance/entitlements`

**Summary:** POST /api/v1/access-governance/entitlements

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Grant an entitlement to a user for a resource.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `GrantEntitlementRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User to grant access to |
| `resource_id` | str | Yes |  | Resource identifier |
| `resource_type` | str | Yes |  | application \| database \| server \| network \| cloud-service \| api \| data-store \| vault |
| `access_level` | str | Yes |  | read \| write \| admin \| execute \| delete \| full-control |
| `granted_by` | str | No |  | Approver username |
| `expires_at` | Optional | No | None | ISO 8601 expiry timestamp (optional) |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1167. `POST` `/api/v1/access-governance/entitlements/{entitlement_id}/revoke`

**Summary:** POST /api/v1/access-governance/entitlements/{entitlement_id}/revoke

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Revoke an entitlement by ID.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `entitlement_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1168. `POST` `/api/v1/access-governance/sod/detect`

**Summary:** POST /api/v1/access-governance/sod/detect

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Detect SoD violations for a user against provided rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `DetectSodRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User ID to check |
| `sod_rules` | List | Yes |  | List of SoD rules to evaluate |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1169. `POST` `/api/v1/access-governance/violations/{violation_id}/acknowledge`

**Summary:** POST /api/v1/access-governance/violations/{violation_id}/acknowledge

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Acknowledge a SoD violation.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `violation_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AcknowledgeViolationRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `acknowledged_by` | str | Yes |  | Who acknowledged the violation |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1170. `POST` `/api/v1/access-governance/roles`

**Summary:** POST /api/v1/access-governance/roles

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Create a new role definition.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `CreateRoleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role_name` | str | Yes |  | Unique role name |
| `role_type` | str | Yes |  | business \| technical \| privileged \| service-account \| emergency |
| `permissions` | List | No | PydanticUndefined | List of permission strings |
| `owner` | str | No |  | Role owner |
| `risk_level` | str | No | medium | critical \| high \| medium \| low |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1171. `POST` `/api/v1/access-governance/roles/{role_id}/assign`

**Summary:** POST /api/v1/access-governance/roles/{role_id}/assign

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Assign a role to a user (increments user_count, grants permissions).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `role_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AssignRoleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `user_id` | str | Yes |  | User ID to assign role to |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1172. `GET` `/api/v1/access-governance/users/{user_id}/entitlements`

**Summary:** GET /api/v1/access-governance/users/{user_id}/entitlements

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return all entitlements for a user.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `user_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |
| `status` | query | Optional | No | Filter: active \| revoked \| expired |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1173. `GET` `/api/v1/access-governance/expiring`

**Summary:** GET /api/v1/access-governance/expiring

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return active entitlements expiring within days_ahead days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `days_ahead` | query | int | No | Look-ahead window in days |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1174. `GET` `/api/v1/access-governance/summary`

**Summary:** GET /api/v1/access-governance/summary

**Tags:** Access Governance

**Auth:** API Key required

**Description:**

Return access governance summary statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1175. `GET` `/api/v1/network-threats/`

**Summary:** GET /api/v1/network-threats/

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Get network threat statistics for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1176. `POST` `/api/v1/network-threats/threats`

**Summary:** POST /api/v1/network-threats/threats

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Record or update a network threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `ThreatCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `threat_name` | str | Yes |  |  |
| `threat_type` | str | Yes |  |  |
| `source_ip` | str | Yes |  |  |
| `dest_ip` | str | Yes |  |  |
| `dest_port` | int | No | 0 |  |
| `protocol` | str | No | tcp |  |
| `severity` | str | No | medium |  |
| `confidence` | float | No | 0.5 |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1177. `POST` `/api/v1/network-threats/threats/{threat_id}/resolve`

**Summary:** POST /api/v1/network-threats/threats/{threat_id}/resolve

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Resolve an active threat.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `threat_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1178. `GET` `/api/v1/network-threats/threats/active`

**Summary:** GET /api/v1/network-threats/threats/active

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return active network threats with optional filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `threat_type` | query | Optional | No | None |
| `severity` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1179. `POST` `/api/v1/network-threats/rules`

**Summary:** POST /api/v1/network-threats/rules

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Create a new threat detection rule.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `RuleCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rule_name` | str | Yes |  |  |
| `rule_type` | str | Yes |  |  |
| `pattern` | str | Yes |  |  |
| `action` | str | No | alert |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1180. `POST` `/api/v1/network-threats/rules/{rule_id}/trigger`

**Summary:** POST /api/v1/network-threats/rules/{rule_id}/trigger

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Increment match_count for a rule.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `rule_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1181. `GET` `/api/v1/network-threats/rules`

**Summary:** GET /api/v1/network-threats/rules

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

List threat detection rules.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `enabled` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1182. `PUT` `/api/v1/network-threats/baselines`

**Summary:** PUT /api/v1/network-threats/baselines

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Upsert a network baseline metric.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BaselineUpdate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  |  |
| `baseline_value` | float | Yes |  |  |
| `current_value` | float | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1183. `GET` `/api/v1/network-threats/baselines/anomalous`

**Summary:** GET /api/v1/network-threats/baselines/anomalous

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return baselines flagged as anomalous.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1184. `GET` `/api/v1/network-threats/stats`

**Summary:** GET /api/v1/network-threats/stats

**Tags:** Network Threats

**Auth:** API Key required

**Description:**

Return aggregated network threat statistics.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1185. `POST` `/api/v1/security-benchmarks/benchmarks`

**Summary:** POST /api/v1/security-benchmarks/benchmarks

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Create an industry benchmark definition.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `BenchmarkCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `benchmark_name` | str | Yes |  |  |
| `benchmark_source` | str | Yes |  |  |
| `sector` | str | Yes |  |  |
| `metric_name` | str | Yes |  |  |
| `metric_category` | str | Yes |  |  |
| `p25` | float | Yes |  |  |
| `p50` | float | Yes |  |  |
| `p75` | float | Yes |  |  |
| `p90` | float | Yes |  |  |
| `unit` | str | No |  |  |
| `higher_is_better` | bool | No | True |  |
| `published_date` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1186. `GET` `/api/v1/security-benchmarks/benchmarks`

**Summary:** GET /api/v1/security-benchmarks/benchmarks

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

List benchmarks with optional sector and category filters.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `sector` | query | Optional | No | None |
| `metric_category` | query | Optional | No | None |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1187. `POST` `/api/v1/security-benchmarks/import-dbir`

**Summary:** POST /api/v1/security-benchmarks/import-dbir

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Import Verizon DBIR / VERIS Community Database breach incidents.  Pulls https://github.com/vz-
risk/VCDB and upserts every validated incident into the local dbir.db. The benchmark engine can then
derive industry breach-rate distributions from this incident corpus.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1188. `POST` `/api/v1/security-benchmarks/metrics`

**Summary:** POST /api/v1/security-benchmarks/metrics

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Record an org security metric measurement.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `OrgMetricCreate`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `metric_name` | str | Yes |  |  |
| `metric_category` | str | Yes |  |  |
| `value` | float | Yes |  |  |
| `unit` | str | No |  |  |
| `source` | str | No |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1189. `GET` `/api/v1/security-benchmarks/metrics/{metric_name}/trend`

**Summary:** GET /api/v1/security-benchmarks/metrics/{metric_name}/trend

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Return metric trend for an org over the past N days.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `metric_name` | path | str | Yes | — |
| `org_id` | query | str | No | default |
| `days` | query | int | No | 90 |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1190. `POST` `/api/v1/security-benchmarks/compare`

**Summary:** POST /api/v1/security-benchmarks/compare

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Compare an org metric to a benchmark and compute percentile rank.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Request Body:** `CompareRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `benchmark_id` | str | Yes |  |  |
| `org_metric_id` | str | Yes |  |  |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1191. `GET` `/api/v1/security-benchmarks/summary`

**Summary:** GET /api/v1/security-benchmarks/summary

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Return benchmark comparison summary with performance counts and overall percentile.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1192. `GET` `/api/v1/security-benchmarks/`

**Summary:** GET /api/v1/security-benchmarks/

**Tags:** Security Benchmarks

**Auth:** API Key required

**Description:**

Root endpoint — returns benchmarks list for dashboard health-checks.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**


**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1193. `POST` `/api/v1/posture-maturity/assessments`

**Summary:** Record a capability maturity assessment

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `RecordAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `domain` | str | Yes |  | Security domain |
| `capability` | str | Yes |  | Capability being assessed |
| `maturity_level` | int | Yes |  | Current maturity level (1–max_level) |
| `max_level` | int | No | 5 | Maximum maturity level (default 5) |
| `evidence` | str | No |  | Supporting evidence |
| `assessor` | str | No |  | Who performed the assessment |
| `next_review` | str | No |  | ISO-8601 date/time for next review |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1194. `PUT` `/api/v1/posture-maturity/assessments/{assessment_id}`

**Summary:** Update maturity level for an assessment

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `assessment_id` | path | str | Yes | — |

**Request Body:** `UpdateLevelRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `maturity_level` | int | Yes |  | New maturity level |
| `evidence` | str | No |  | Updated evidence |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1195. `POST` `/api/v1/posture-maturity/roadmap`

**Summary:** Create a roadmap item

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateRoadmapItemRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `domain` | str | Yes |  | Security domain |
| `capability` | str | Yes |  | Capability to improve |
| `current_level` | int | Yes |  | Current maturity level |
| `target_level` | int | Yes |  | Target maturity level |
| `priority` | str | No | medium | critical/high/medium/low |
| `effort` | str | No | medium | low/medium/high/very-high |
| `timeline` | str | No |  | Planned timeline (e.g. Q3 2026) |
| `owner` | str | No |  | Responsible owner |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1196. `PUT` `/api/v1/posture-maturity/roadmap/{item_id}/advance`

**Summary:** Advance roadmap item status

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `item_id` | path | str | Yes | — |

**Request Body:** `AdvanceRoadmapRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1197. `POST` `/api/v1/posture-maturity/snapshots`

**Summary:** Take a maturity snapshot

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `TakeSnapshotRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1198. `GET` `/api/v1/posture-maturity/overview`

**Summary:** Get maturity overview (snapshot + assessments + roadmap)

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1199. `GET` `/api/v1/posture-maturity/domains`

**Summary:** Get per-domain maturity breakdown

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1200. `GET` `/api/v1/posture-maturity/roadmap`

**Summary:** List roadmap items

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1201. `GET` `/api/v1/posture-maturity/overdue`

**Summary:** Get assessments with overdue reviews

**Tags:** Security Posture Maturity

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1202. `GET` `/api/v1/security-baselines/`

**Summary:** GET /api/v1/security-baselines/

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

List security baselines for the org.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1203. `POST` `/api/v1/security-baselines/baselines`

**Summary:** POST /api/v1/security-baselines/baselines

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Create a new security baseline in draft status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `CreateBaselineRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `baseline_name` | str | Yes |  | Descriptive name for the baseline |
| `target_type` | str | Yes |  | server \| workstation \| network_device \| cloud_instance \| container \| database \| application |
| `framework` | str | Yes |  | CIS \| NIST \| STIG \| ISO27001 \| PCI-DSS \| custom |
| `version` | str | No | 1.0 | Baseline version string |
| `created_by` | str | Yes |  | Username of creator |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1204. `POST` `/api/v1/security-baselines/baselines/{baseline_id}/controls`

**Summary:** POST /api/v1/security-baselines/baselines/{baseline_id}/controls

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Add a control to a baseline.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `AddControlRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `control_id` | str | Yes |  | Control identifier (e.g. CIS-1.1) |
| `control_name` | str | Yes |  | Human-readable control name |
| `category` | str | No |  | Control category |
| `description` | str | No |  | Detailed control description |
| `expected_value` | str | Yes |  | Expected configuration value |
| `severity` | str | No | medium | critical \| high \| medium \| low |
| `automated_check` | bool | No | False | Whether check can be automated |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1205. `PUT` `/api/v1/security-baselines/baselines/{baseline_id}/publish`

**Summary:** PUT /api/v1/security-baselines/baselines/{baseline_id}/publish

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Publish a baseline (status=active, published_at=now).

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1206. `POST` `/api/v1/security-baselines/baselines/{baseline_id}/assess`

**Summary:** POST /api/v1/security-baselines/baselines/{baseline_id}/assess

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Run a baseline assessment against a target system.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Request Body:** `RunAssessmentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target_name` | str | Yes |  | Target system/host name |
| `assessed_by` | str | Yes |  | Assessor username or tool name |
| `results` | List | Yes |  | Per-control assessment results |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1207. `GET` `/api/v1/security-baselines/baselines/{baseline_id}`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Return baseline detail with controls and last 5 assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1208. `GET` `/api/v1/security-baselines/baselines/{baseline_id}/drift`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}/drift

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Compare last 2 assessments to detect control drift.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1209. `GET` `/api/v1/security-baselines/baselines/{baseline_id}/trend`

**Summary:** GET /api/v1/security-baselines/baselines/{baseline_id}/trend

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

Return compliance trend across all assessments.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `baseline_id` | path | str | Yes | — |
| `org_id` | query | str | Yes | Organization ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1210. `GET` `/api/v1/security-baselines/baselines`

**Summary:** GET /api/v1/security-baselines/baselines

**Tags:** Security Baselines

**Auth:** API Key required

**Description:**

List baselines for an org, optionally filtered by status.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organization ID |
| `status` | query | Optional | No | draft \| active \| deprecated |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1211. `POST` `/api/v1/posture-reports/reports`

**Summary:** Create a new posture report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateReportRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `report_name` | str | Yes |  | Report name |
| `report_type` | str | No | monthly | executive/board/audit/compliance/operational/monthly/quarterly/annual |
| `audience` | str | No | ciso | ciso/board/executives/auditors/regulators/team |
| `period_start` | str | Yes |  | Period start ISO date |
| `period_end` | str | Yes |  | Period end ISO date |
| `generated_by` | str | No |  | Author or system that generated the report |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1212. `POST` `/api/v1/posture-reports/reports/{report_id}/sections`

**Summary:** Add a section to a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |

**Request Body:** `AddSectionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `section_name` | str | Yes |  | Section name |
| `section_type` | str | No | summary | summary/risk/compliance/incidents/vulnerabilities/recommendations/kpis |
| `content` | str | No |  | Section content / narrative |
| `score` | float | No | 0.0 | Section score 0-100 |
| `sort_order` | int | No | 0 | Display order |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1213. `POST` `/api/v1/posture-reports/reports/{report_id}/metrics`

**Summary:** Add a metric to a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |

**Request Body:** `AddMetricRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `metric_name` | str | Yes |  | Metric name |
| `metric_value` | float | Yes |  | Current metric value |
| `metric_unit` | str | No |  | Unit label (e.g. %, ms, count) |
| `previous_value` | float | No | 0.0 | Previous period value for trend computation |
| `benchmark_value` | float | No | 0.0 | Industry benchmark value |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1214. `PUT` `/api/v1/posture-reports/reports/{report_id}/publish`

**Summary:** Publish a report

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1215. `GET` `/api/v1/posture-reports/reports/{report_id}`

**Summary:** Get report detail with sections and metrics

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1216. `GET` `/api/v1/posture-reports/reports`

**Summary:** List posture reports

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `report_type` | query | Optional | No | Filter by report type |
| `status` | query | Optional | No | Filter by status |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1217. `GET` `/api/v1/posture-reports/reports/latest/{report_type}`

**Summary:** Get latest report of a given type

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `report_type` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1218. `GET` `/api/v1/posture-reports/trends`

**Summary:** Get metric trend summary across published reports

**Tags:** posture-reports

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1219. `POST` `/api/v1/network-anomaly/samples`

**Summary:** Record a traffic sample

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `TrafficSampleRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | TCP/UDP/ICMP/HTTP/HTTPS/DNS/SMTP/FTP/SSH/other |
| `direction` | str | No | inbound | inbound/outbound/lateral |
| `bytes_per_min` | float | No | 0.0 | Bytes per minute |
| `packets_per_min` | float | No | 0.0 | Packets per minute |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1220. `POST` `/api/v1/network-anomaly/baselines/update`

**Summary:** Update baseline from recent samples

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `BaselineUpdateRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | Protocol |
| `direction` | str | No | inbound | Traffic direction |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1221. `POST` `/api/v1/network-anomaly/detect`

**Summary:** Detect anomalies against current baseline

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `DetectAnomalyRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | No | default | Organisation ID |
| `segment` | str | Yes |  | Network segment name |
| `protocol` | str | No | TCP | Protocol |
| `direction` | str | No | inbound | Traffic direction |
| `bytes_per_min` | float | No | 0.0 | Observed bytes per minute |
| `packets_per_min` | float | No | 0.0 | Observed packets per minute |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1222. `PUT` `/api/v1/network-anomaly/anomalies/{anomaly_id}/resolve`

**Summary:** Resolve a network anomaly

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `anomaly_id` | path | str | Yes | — |
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1223. `GET` `/api/v1/network-anomaly/summary`

**Summary:** Get anomaly summary for org

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1224. `GET` `/api/v1/network-anomaly/baselines`

**Summary:** Get baseline health for org

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1225. `GET` `/api/v1/network-anomaly/traffic-trend`

**Summary:** Get traffic trend for segment/protocol

**Tags:** network-anomaly

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | No | Organisation ID |
| `segment` | query | str | Yes | Network segment |
| `protocol` | query | str | No | Protocol |
| `hours` | query | int | No | Hours of history to return |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1226. `POST` `/api/v1/cloud-ir/incidents`

**Summary:** Create a cloud incident

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreateIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `incident_name` | str | Yes |  | Descriptive incident name |
| `cloud_provider` | str | No | aws | Cloud provider |
| `incident_type` | str | Yes |  | Type of cloud incident |
| `severity` | str | No | medium | Severity: critical/high/medium/low |
| `affected_services` | Optional | No | None | List of affected services |
| `affected_regions` | Optional | No | None | List of affected regions |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1227. `GET` `/api/v1/cloud-ir/incidents`

**Summary:** List incidents for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |
| `status` | query | Optional | No | None |
| `cloud_provider` | query | Optional | No | None |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1228. `GET` `/api/v1/cloud-ir/incidents/{incident_id}`

**Summary:** Get a single incident with actions and playbooks

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |
| `org_id` | query | str | No | default |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1229. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/contain`

**Summary:** Mark incident as contained

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `ContainIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `blast_radius` | str | No | unknown | Blast radius description |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1230. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/actions`

**Summary:** Add a containment action to an incident

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `AddActionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `action_type` | str | Yes |  | Containment action type |
| `resource_id` | str | No |  | Affected resource identifier |
| `description` | str | No |  | Action description |
| `automated` | bool | No | False | Whether action was automated |
| `executed_by` | str | No |  | Who executed the action |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1231. `POST` `/api/v1/cloud-ir/actions/{action_id}/complete`

**Summary:** Mark a containment action as completed

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `action_id` | path | str | Yes | — |

**Request Body:** `CompleteActionRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `result` | str | No |  | Action result/outcome |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1232. `POST` `/api/v1/cloud-ir/incidents/{incident_id}/resolve`

**Summary:** Mark incident as resolved

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `incident_id` | path | str | Yes | — |

**Request Body:** `ResolveIncidentRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `root_cause` | str | No |  | Root cause analysis |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1233. `POST` `/api/v1/cloud-ir/playbooks`

**Summary:** Create an IR playbook

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Request Body:** `CreatePlaybookRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |
| `playbook_name` | str | Yes |  | Playbook name |
| `cloud_provider` | str | Yes |  | Target cloud provider |
| `incident_type` | str | Yes |  | Target incident type |
| `steps` | Optional | No | None | Ordered playbook steps |
| `estimated_mins` | int | No | 30 | Estimated execution time in minutes |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1234. `GET` `/api/v1/cloud-ir/playbooks`

**Summary:** List IR playbooks for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `List`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1235. `POST` `/api/v1/cloud-ir/playbooks/{playbook_id}/execute`

**Summary:** Execute a playbook (increments execution_count)

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `playbook_id` | path | str | Yes | — |

**Request Body:** `ExecutePlaybookRequest`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `org_id` | str | Yes |  | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---

### 1236. `GET` `/api/v1/cloud-ir/metrics`

**Summary:** Get IR metrics for an org

**Tags:** Cloud Incident Response

**Auth:** API Key required

**Description:**

[CITATION NEEDED — needs docstring]

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `org_id` | query | str | Yes | Organisation identifier |

**Responses:**

**200 OK** — `Dict`

**401** — Unauthorized (missing or invalid API key)
**403** — Forbidden (insufficient scope)
**422** — Validation Error (request body/params)
**500** — Internal Server Error

---
