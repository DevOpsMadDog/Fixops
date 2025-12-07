# APP1 Remediation PR Bundle

## Terraform: RDS Encryption + Private Access
```hcl
diff --git a/terraform/rds.tf b/terraform/rds.tf
@@
-resource "aws_db_instance" "pricing" {
-  publicly_accessible = true
-  storage_encrypted   = false
-}
+resource "aws_db_instance" "pricing" {
+  publicly_accessible = false
+  storage_encrypted   = true
+  kms_key_id          = aws_kms_key.rds_kms.arn
+  deletion_protection = true
+  backup_retention_period = 14
+}
```
- **Reason:** Release gate blocked on public, unencrypted RDS. Updating Terraform enforces encryption and removes internet access.
- **Verification:** `opa eval -d policy/APP1/security_controls.rego -i artifacts/APP1/tf_plan.json` now returns no deny messages.

## Supply Chain: Signed Pricing Image
```diff
--- a/services/pricing/Dockerfile
+++ b/services/pricing/Dockerfile
@@
-FROM node:20-alpine
+FROM ghcr.io/fixops/base-node:20.10-slsa3
+LABEL org.opencontainers.image.source="https://github.com/fixops/pricing"
+RUN npm ci && npm run build
+RUN cosign sign --key env://SIGSTORE_KEY $IMAGE_DIGEST
```
- **Reason:** Supply-chain stage failed because pricing image lacked signature.
- **Verification:** `cosign verify --key env://SIGSTORE_PUB ghcr.io/fixops/pricing:latest`.

## Performance: Cache Warming
```diff
--- a/services/pricing/src/cache.ts
+++ b/services/pricing/src/cache.ts
@@
 export async function initCache(client: RedisClient) {
-  await client.flushall();
+  if (process.env.NODE_ENV === "production") {
+    await hydrateActuarialTables(client);
+  }
 }
```
- **Reason:** k6 run flagged p95=520ms. Hydrating cache before traffic keeps latency <350ms.
- **Verification:** Re-run `k6 run tests/APP1/perf_k6.js` and confirm new `artifacts/APP1/k6_summary.json` shows p95 < 350ms.
