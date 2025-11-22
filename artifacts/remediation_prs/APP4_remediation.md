# APP4 Remediation PR Bundle

## Supply Chain: Harden Go Service Image
```diff
--- a/services/payments/Dockerfile
+++ b/services/payments/Dockerfile
@@
-FROM golang:1.21-alpine
-RUN go build -o app ./cmd/payments
+FROM ghcr.io/fixops/base-go:1.21.5-slsa3 AS build
+RUN go build -trimpath -buildmode=pie -o /out/app ./cmd/payments
+
+FROM gcr.io/distroless/base-debian12
+COPY --from=build /out/app /usr/local/bin/payments
+ENTRYPOINT ["/usr/local/bin/payments"]
```
- **Reason:** Supply-chain gate failed because base image outdated and binary unsigned.
- **Verification:** `cosign verify --key env://SIGSTORE_PUB gcr.io/fixops/payments:prod` and `grype` scan shows no go-chi CVE.

## Runtime Controls: Broker Lag Mitigation
```diff
--- a/services/payments/stream/consumer.go
+++ b/services/payments/stream/consumer.go
@@
 func (c *Consumer) HandleBatch(ctx context.Context, msgs []Message) error {
-    for _, msg := range msgs {
-        process(msg)
-    }
+    g, ctx := errgroup.WithContext(ctx)
+    sem := make(chan struct{}, 8)
+    for _, msg := range msgs {
+        sem <- struct{}{}
+        m := msg
+        g.Go(func() error {
+            defer func() { <-sem }()
+            return processWithRetry(ctx, m)
+        })
+    }
+    if err := g.Wait(); err != nil {
+        return err
+    }
     return nil
 }
```
- **Reason:** Chaos broker failover left lag 210; concurrency + retries clear backlog faster.
- **Verification:** Re-run `python tests/APP4/chaos_playbooks/broker_failover.md` scenario; confirm `artifacts/APP4/metrics.json` shows max lag < 30.

## Release Gate: Secure MQTT Ingress
```diff
--- a/infra/terraform/mqtt.tf
+++ b/infra/terraform/mqtt.tf
@@
-resource "aws_iot_endpoint" "public" {}
+resource "aws_iot_endpoint" "private" {
+  endpoint_type = "iot:Data-ATS"
+}
 
-resource "aws_iot_policy" "all_devices" {
-  policy = jsonencode({
-    Version = "2012-10-17"
-    Statement = [{
-      Effect = "Allow"
-      Action = "iot:*"
-      Resource = "*"
-    }]
-  })
-}
+resource "aws_iot_policy" "payments_devices" {
+  policy = jsonencode({
+    Version = "2012-10-17"
+    Statement = [{
+      Effect   = "Allow"
+      Action   = ["iot:Connect", "iot:Publish"]
+      Resource = "arn:aws:iot:*:*:topic/payments/*"
+      Condition = {
+        "Bool": {"iot:Connection.Thing.IsAttached": "true"}
+      }
+    }]
+  })
+}
```
- **Reason:** Release blocked: MQTT endpoint was public with wildcard policy.
- **Verification:** `opa eval -d policy/APP4/security_controls.rego -i artifacts/APP4/tf_plan.json` -> no denies; integration smoke test uses mutual TLS certificates from AWS IoT.
