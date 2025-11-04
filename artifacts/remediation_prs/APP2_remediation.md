# APP2 Remediation PR Bundle

## Partner Security: Re-enable Webhook Signature Validation
```diff
--- a/services/partners/webhook_handler.py
+++ b/services/partners/webhook_handler.py
@@
-def validate_signature(headers, payload):
-    return True  # temporarily bypassed for debugging
+def validate_signature(headers, payload):
+    signature = headers.get("X-Partner-Signature")
+    timestamp = headers.get("X-Partner-Timestamp")
+    if not signature or not timestamp:
+        raise Unauthorized("missing signature headers")
+    expected = hmac_sha256(SECRET_MANAGER.fetch("partner/webhook"), timestamp + payload)
+    if not hmac.compare_digest(signature, expected):
+        raise Unauthorized("signature mismatch")
+    return True
```
- **Reason:** Partner-security stage failed because signature plugin was bypassed.
- **Verification:** Execute `tests/APP2/partner_simulators/invalid_signature.py` and confirm 401.

## Runtime Controls: DLQ Recovery
```diff
--- a/infrastructure/terraform/kafka.tf
+++ b/infrastructure/terraform/kafka.tf
@@
 resource "kafka_topic" "session_events" {
   name               = "session-events"
   partitions         = 12
-  retention_ms       = 86400000
+  retention_ms       = 604800000
+  config = {
+    "min.insync.replicas" = "2"
+  }
 }
+
+module "dlq_consumer" {
+  source = "./modules/lambda_consumer"
+  topic  = kafka_topic.session_events.name
+  target = aws_lambda_function.dlq_replay.arn
+}
```
- **Reason:** Chaos tests left messages in DLQ; adding replay consumer clears backlog.
- **Verification:** Run `python tests/APP2/partner_simulators/server_error.py` followed by `python tests/APP2/partner_simulators/valid_signature.py`; confirm DLQ depth metric = 0.

## Release Gate: Secrets Manager Source of Truth
```diff
--- a/config/default.yaml
+++ b/config/default.yaml
@@
-partner_api_key: "test-test-test"
+partner_api_key: "${secretsmanager:partner/api/key}"
```
- **Reason:** Release blocked because partner API key was hardcoded.
- **Verification:** `fixops secrets:lint --config config/default.yaml` passes; policy bundle no longer reports violation.
