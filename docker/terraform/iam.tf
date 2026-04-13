# =============================================================================
# ALDECI — IAM Roles for ECS Tasks
# Principle of least privilege: task execution role (AWS API calls by ECS
# agent) is separate from task role (runtime permissions used by the app).
# =============================================================================

# ---------------------------------------------------------------------------
# ECS Task Execution Role
# Used by the ECS agent to pull images, write logs, and fetch secrets.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "ecs_task_execution" {
  name        = "${var.project_name}-${var.environment}-ecs-execution-role"
  description = "Allows ECS tasks to pull container images and write CloudWatch logs."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow reading secrets from Secrets Manager (API keys, DB passwords)
resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "${var.project_name}-${var.environment}-ecs-execution-secrets"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = var.api_key_secret_arn != "" ? [var.api_key_secret_arn] : ["arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}/*"]
      },
      {
        Sid    = "ReadSSMParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/aldeci/${var.environment}/*"
      },
      {
        Sid    = "DecryptKMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ssm.${var.aws_region}.amazonaws.com"
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# ECS Task Role (runtime — used by the application code itself)
# Grants the ALDECI API access to AWS services it needs at runtime.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "ecs_task" {
  name        = "${var.project_name}-${var.environment}-ecs-task-role"
  description = "Runtime IAM role for ALDECI ECS tasks. Grants S3, SSM, CloudWatch access."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
        }
      }
    }]
  })
}

# S3: read/write backups bucket
resource "aws_iam_role_policy" "ecs_task_s3" {
  name = "${var.project_name}-${var.environment}-ecs-task-s3"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BackupBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/backups/*",
        ]
      },
    ]
  })
}

# CloudWatch: emit custom metrics from the application
resource "aws_iam_role_policy" "ecs_task_cloudwatch" {
  name = "${var.project_name}-${var.environment}-ecs-task-cloudwatch"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EmitMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "ALDECI/${var.environment}"
          }
        }
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = [
          "${aws_cloudwatch_log_group.api.arn}:*",
          "${aws_cloudwatch_log_group.ui.arn}:*",
        ]
      },
    ]
  })
}

# SSM: read application config parameters at runtime
resource "aws_iam_role_policy" "ecs_task_ssm" {
  name = "${var.project_name}-${var.environment}-ecs-task-ssm"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAppConfig"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/aldeci/${var.environment}/*"
      },
    ]
  })
}

# ECS Exec (optional — allows `aws ecs execute-command` for debugging)
resource "aws_iam_role_policy" "ecs_task_exec_command" {
  name = "${var.project_name}-${var.environment}-ecs-exec-command"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECSExec"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      },
    ]
  })
}
