package app2.policy

violation[msg] {
  input.gateway.routes[_].path == "/api/webhooks/{partner}"
  not input.gateway.routes[_].plugins.signatures.enabled
  msg := "Webhook route must enforce HMAC signature plugin"
}

violation[msg] {
  some svc
  svc := input.kong_services[_]
  svc.protocol == "http"
  msg := sprintf("Service %s must use https", [svc.name])
}

violation[msg] {
  input.infrastructure.cdn.public_origin
  msg := "CDN origins cannot be public buckets"
}

violation[msg] {
  some image
  image := input.images[_]
  image.base_age_days > 180
  msg := sprintf("Image %s older than 180 days", [image.name])
}

violation[msg] {
  input.lambda_env[_].key == "PARTNER_SECRET"
  input.lambda_env[_].source != "secrets-manager"
  msg := "Partner secrets must be sourced from AWS Secrets Manager"
}
