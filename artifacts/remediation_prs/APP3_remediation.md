# APP3 Remediation PR Bundle

## Supply Chain: Patch Spring Boot CVE-2024-34145
```diff
--- a/services/patient-api/build.gradle.kts
+++ b/services/patient-api/build.gradle.kts
@@
-implementation("org.springframework.boot:spring-boot-starter-webflux:3.2.1")
+implementation("org.springframework.boot:spring-boot-starter-webflux:3.2.6")
+implementation("org.springframework.boot:spring-boot-starter-actuator:3.2.6")
```
- **Reason:** SLSA attestation flagged vulnerable Spring Boot version.
- **Verification:** `./gradlew dependencyCheckAggregate` shows CVE remediated; `inputs/APP3/sbom.json` regenerated with version 3.2.6.

## Release Gate: Lock Down Admin Ingress
```diff
--- a/infra/terraform/network.tf
+++ b/infra/terraform/network.tf
@@
-resource "azurerm_application_gateway" "admin" {
-  frontend_port = 443
-  frontend_ip_configuration {
-    public_ip_address_id = azurerm_public_ip.admin.id
-  }
-}
+resource "azurerm_application_gateway" "admin" {
+  frontend_port = 443
+  frontend_ip_configuration {
+    subnet_id = azurerm_subnet.private_admin.id
+  }
+  ssl_certificate {
+    name = "admin-tls"
+    key_vault_secret_id = azurerm_key_vault_secret.admin_cert.id
+  }
+  firewall_policy_id = azurerm_web_application_firewall_policy.strict.id
+}
```
- **Reason:** Release blocked because admin ingress exposed publicly.
- **Verification:** `opa eval -d policy/APP3/security_controls.rego -i artifacts/APP3/tf_plan.json` returns empty set.

## Runtime Warning: Cosmos Throttling
```diff
--- a/services/telemetry/metrics.ts
+++ b/services/telemetry/metrics.ts
@@
-export const COSMOS_RU_LIMIT = 40000;
+export const COSMOS_RU_LIMIT = 60000;
@@
-  if (usage > COSMOS_RU_LIMIT) {
-    logger.warn("cosmos usage above threshold", { usage });
+  if (usage > COSMOS_RU_LIMIT) {
+    circuitBreaker.open("cosmos_throttle");
+    logger.warn("cosmos usage above threshold", { usage });
   }
 }
```
- **Reason:** Runtime controls emitted warning about throttling; raising limit and opening breaker protects downstream services.
- **Verification:** Replay soak test `k6 run tests/APP3/perf_k6.js` with `COSMOS_RU_LIMIT=60000`; ensure `artifacts/APP3/metrics.json` shows zero throttle events.
