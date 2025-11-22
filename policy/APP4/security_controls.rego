package app4.policy

deny[msg] {
  some change
  change := input.resource_changes[_]
  change.change.after.type == "aws_lambda_function"
  change.change.after.environment.variables.HSM_PASSWORD
  msg := "Lambda functions cannot store HSM credentials in environment variables"
}

deny[msg] {
  some sg
  sg := input.resource_changes[_]
  sg.change.after.type == "aws_security_group_rule"
  sg.change.after.cidr_blocks[_] == "0.0.0.0/0"
  sg.change.after.to_port == 8883
  msg := "MQTT listener cannot be public"
}

deny[msg] {
  some lb
  lb := input.load_balancers[_]
  lb.protocol != "TLS"
  msg := "Checkout load balancers must use TLS"
}

deny[msg] {
  some iam
  iam := input.iam_policies[_]
  iam.name == "settlement-batch"
  iam.allows["kms:Decrypt"]
  not iam.condition.source_vpce
  msg := "Settlement IAM must restrict KMS decrypt by VPC endpoint"
}

deny[msg] {
  input.images[_].base_age_days > 180
  msg := "Base image older than 180 days"
}
