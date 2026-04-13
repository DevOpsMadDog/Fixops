# =============================================================================
# ALDECI — S3 Bucket for Backups, ALB Access Logs, and Artifacts
# =============================================================================

locals {
  backup_bucket_name = var.backup_bucket_name != "" ? var.backup_bucket_name : "${var.project_name}-${var.environment}-backups-${random_id.suffix.hex}"
}

# ---------------------------------------------------------------------------
# Backup Bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "backups" {
  bucket        = local.backup_bucket_name
  force_destroy = var.environment != "production"

  tags = {
    Name    = local.backup_bucket_name
    Purpose = "backups"
  }
}

# Block all public access — backups must never be public
resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption with AES-256
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Versioning enabled — required for replication and point-in-time recovery
resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle: move older backups to Glacier, expire stale versions
resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "backup-transition"
    status = "Enabled"

    filter {
      prefix = "backups/"
    }

    transition {
      days          = var.backup_retention_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.backup_retention_days * 4
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "alb-logs-cleanup"
    status = "Enabled"

    filter {
      prefix = "alb-access-logs/"
    }

    expiration {
      days = 90
    }
  }
}

# Enforce TLS-only access
resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "AllowALBLogs"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::127311923021:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.backups.arn}/alb-access-logs/*"
      },
      {
        Sid    = "AllowECSTaskBackups"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ecs_task.arn
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/backups/*",
        ]
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.backups]
}

# ---------------------------------------------------------------------------
# Cross-Region Replication (optional, for disaster recovery)
# ---------------------------------------------------------------------------

resource "aws_s3_bucket_replication_configuration" "backups" {
  count = var.enable_backup_replication ? 1 : 0

  role   = aws_iam_role.s3_replication[0].arn
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "replicate-backups"
    status = "Enabled"

    filter {
      prefix = "backups/"
    }

    destination {
      bucket        = aws_s3_bucket.backups_replica[0].arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

resource "aws_s3_bucket" "backups_replica" {
  count    = var.enable_backup_replication ? 1 : 0
  provider = aws.replica

  bucket        = "${local.backup_bucket_name}-replica"
  force_destroy = var.environment != "production"

  tags = {
    Name    = "${local.backup_bucket_name}-replica"
    Purpose = "backup-replica"
  }
}

resource "aws_s3_bucket_versioning" "backups_replica" {
  count    = var.enable_backup_replication ? 1 : 0
  provider = aws.replica
  bucket   = aws_s3_bucket.backups_replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "backups_replica" {
  count    = var.enable_backup_replication ? 1 : 0
  provider = aws.replica
  bucket   = aws_s3_bucket.backups_replica[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Replica provider alias (only instantiated when replication is enabled)
provider "aws" {
  alias  = "replica"
  region = var.backup_replication_region
}

resource "aws_iam_role" "s3_replication" {
  count = var.enable_backup_replication ? 1 : 0

  name = "${var.project_name}-${var.environment}-s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.enable_backup_replication ? 1 : 0

  name = "${var.project_name}-${var.environment}-s3-replication-policy"
  role = aws_iam_role.s3_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = aws_s3_bucket.backups.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = "${aws_s3_bucket.backups.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
        ]
        Resource = "${aws_s3_bucket.backups_replica[0].arn}/*"
      },
    ]
  })
}
