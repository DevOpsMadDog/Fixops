package app3.policy

deny[msg] {
  input.kubernetes.ingress[_].spec.rules[_].host == "admin.app3.example.com"
  input.kubernetes.ingress[_].spec.rules[_].http.paths[_].backend.service.port.number == 8080
  input.kubernetes.ingress[_].spec.rules[_].http.paths[_].backend.service.allow_public
  msg := "Admin ingress cannot be publicly accessible"
}

deny[msg] {
  some deploy
  deploy := input.kubernetes.deployments[_]
  deploy.spec.template.spec.containers[_].securityContext.runAsNonRoot == false
  msg := sprintf("Deployment %s must run as non-root", [deploy.metadata.name])
}

deny[msg] {
  input.azure.traffic_manager.profile.protocols[_] != "https"
  msg := "Traffic manager endpoints must enforce HTTPS"
}

deny[msg] {
  input.cosmos.consistency != "Strong"
  msg := "CosmosDB must use Strong consistency for audit ledger"
}

deny[msg] {
  some image
  image := input.images[_]
  image.base_age_days > 180
  msg := sprintf("Base image %s older than 180 days", [image.name])
}
