# Integration Topology — graph audit report

- Nodes: 160
- Edges: 259
- Communities: 18

## Community labels
- **Tenant: bodgeit-edu** — 13 nodes, cohesion 0.150
- **Tenant: railsgoat-media** — 13 nodes, cohesion 0.150
- **Tenant: ssrf-lab-biotech** — 13 nodes, cohesion 0.150
- **Tenant: vampi-gov** — 12 nodes, cohesion 0.170
- **Tenant: altoro-bank** — 11 nodes, cohesion 0.180
- **Tenant: webgoat-health** — 8 nodes, cohesion 0.250
- **Tenant: juice-shop-corp** — 8 nodes, cohesion 0.250
- **Tenant: dvwa-mfg** — 8 nodes, cohesion 0.250
- **Tenant: petclinic-saas** — 8 nodes, cohesion 0.250
- **Tenant: nodegoat-retail** — 8 nodes, cohesion 0.250
- **Tenant: hackazon-ecom** — 8 nodes, cohesion 0.250
- **Tenant: vulnado-airlines** — 8 nodes, cohesion 0.250
- **Tenant: django-vuln-energy** — 8 nodes, cohesion 0.250
- **Tenant: graphql-pwn-telecom** — 8 nodes, cohesion 0.250
- **Tenant: log4shell-pos-grocery** — 8 nodes, cohesion 0.250
- **OSS Hub: owasp zap** — 6 nodes, cohesion 0.330
- **OSS Hub: keycloak scoutsuite** — 6 nodes, cohesion 0.330
- **OSS Hub: opensearch wazuh** — 6 nodes, cohesion 0.400

## God nodes (highest degree)

## Surprising bridges (cross-community connectors)
- `juice-shop-corp  snyk oss` <-> `trivy` (relation: uses_tool)
- `dvwa-mfg  snyk oss` <-> `trivy` (relation: uses_tool)
- `webgoat-health  snyk oss` <-> `trivy` (relation: uses_tool)
- `petclinic-saas  snyk oss` <-> `trivy` (relation: uses_tool)
- `nodegoat-retail  snyk oss` <-> `trivy` (relation: uses_tool)

## Sample shortest path (from TrustGraph BFS)

Query: `tenant_juice-shop-corp` -> `engine_security_event_correlation_engine`

```
  -> tenant_juice-shop-corp
  -> conn_juice-shop-corp__edr_xdr
  -> tool_wazuh
  -> engine_security_event_correlation_engine
```
_3 hops via the EDR/XDR connector + Wazuh OSS tool_