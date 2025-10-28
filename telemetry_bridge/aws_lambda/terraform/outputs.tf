output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.telemetry_connector.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.telemetry_connector.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.telemetry_lambda.arn
}

output "log_group_name" {
  description = "CloudWatch Logs group name"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}
