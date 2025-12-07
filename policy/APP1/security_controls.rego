package app1.policy

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "aws_db_instance"
  change.change.after.publicly_accessible
  msg := "Database instances must not be publicly accessible."
}

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "aws_db_instance"
  not change.change.after.storage_encrypted
  msg := "Database must be encrypted at rest."
}

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "aws_security_group"
  some ingress
  ingress := change.change.after.ingress[_]
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  msg := "Ingress rules cannot expose 0.0.0.0/0."
}

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "kubernetes_secret"
  re_match("(?i)key|password|secret", change.change.after.metadata.name)
  msg := sprintf("Secret %s must be sourced from external vault", [change.change.after.metadata.name])
}

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "aws_lb_listener"
  not startswith(change.change.after.protocol, "TLS")
  msg := "Load balancers must enforce TLS 1.2+."
}

deny[msg] {
  some image
  image := input.images[_]
  now := time.now_ns() / 1000000000
  age := now - image.metadata.created
  age > 180 * 24 * 3600
  msg := sprintf("Base image %s older than 180 days", [image.name])
}
