terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  overlay_path = var.overlay_path != "" ? var.overlay_path : "${path.root}/../../../config/fixops.overlay.yml"
  overlay_data = yamldecode(file(local.overlay_path))
  telemetry_config = local.overlay_data.telemetry_bridge
  aws_config = local.telemetry_config.aws
}

resource "aws_iam_role" "telemetry_lambda" {
  name = "${var.prefix}-telemetry-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.telemetry_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.prefix}-telemetry-connector"
  retention_in_days = lookup(local.telemetry_config.retention_days, "summary", 30)

  tags = var.tags
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/lambda.zip"
  excludes    = ["terraform", "test_handler.py", "__pycache__", "*.pyc"]
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.prefix}-telemetry-dlq"
  message_retention_seconds = 1209600
  
  tags = var.tags
}

resource "aws_lambda_function" "telemetry_connector" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.prefix}-telemetry-connector"
  role            = aws_iam_role.telemetry_lambda.arn
  handler         = "handler.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 256

  environment {
    variables = {
      FIXOPS_OVERLAY_PATH = "/opt/config/fixops.overlay.yml"
      FIXOPS_API_KEY      = var.fixops_api_key
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = var.tags
}

resource "aws_iam_role_policy" "lambda_dlq" {
  name = "${var.prefix}-lambda-dlq-policy"
  role = aws_iam_role.telemetry_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:SendMessage"
      ]
      Resource = aws_sqs_queue.lambda_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.prefix}-telemetry-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Alert when Lambda function has more than 5 errors in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.telemetry_connector.function_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_subscription_filter" "telemetry" {
  count           = length(local.aws_config.cw_log_groups)
  name            = "${var.prefix}-telemetry-subscription-${count.index}"
  log_group_name  = local.aws_config.cw_log_groups[count.index]
  filter_pattern  = ""
  destination_arn = aws_lambda_function.telemetry_connector.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  count         = length(local.aws_config.cw_log_groups)
  statement_id  = "AllowExecutionFromCloudWatch-${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.telemetry_connector.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${local.aws_config.cw_log_groups[count.index]}:*"
}

data "aws_caller_identity" "current" {}
