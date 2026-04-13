# =============================================================================
# ALDECI — RDS PostgreSQL (optional, controlled by var.enable_rds)
# Future migration path from SQLite per domain → shared managed Postgres.
# =============================================================================

# ---------------------------------------------------------------------------
# DB Subnet Group
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "aldeci" {
  count = var.enable_rds ? 1 : 0

  name        = "${var.project_name}-${var.environment}-db-subnet-group"
  description = "Subnet group for ALDECI RDS PostgreSQL instance."
  subnet_ids  = aws_subnet.private[*].id

  tags = {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
  }
}

# ---------------------------------------------------------------------------
# DB Parameter Group (tuned for ALDECI workload)
# ---------------------------------------------------------------------------

resource "aws_db_parameter_group" "aldeci" {
  count = var.enable_rds ? 1 : 0

  name        = "${var.project_name}-${var.environment}-pg15"
  family      = "postgres15"
  description = "ALDECI PostgreSQL 15 parameter group."

  # Enable query logging for audit trail (security best practice)
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  # Performance
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  parameter {
    name  = "track_activity_query_size"
    value = "2048"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-pg15-params"
  }
}

# ---------------------------------------------------------------------------
# RDS Instance
# ---------------------------------------------------------------------------

resource "aws_db_instance" "aldeci" {
  count = var.enable_rds ? 1 : 0

  identifier = "${var.project_name}-${var.environment}-postgres"

  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.rds_instance_class

  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_allocated_storage * 3
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.rds_db_name
  username = var.rds_username
  password = var.rds_password

  db_subnet_group_name   = aws_db_subnet_group.aldeci[0].name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.aldeci[0].name

  multi_az               = var.rds_multi_az
  publicly_accessible    = false
  deletion_protection    = var.rds_deletion_protection

  backup_retention_period   = var.rds_backup_retention_days
  backup_window             = "03:00-04:00"
  maintenance_window        = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false

  # Enhanced monitoring (1-second granularity)
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring[0].arn

  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  auto_minor_version_upgrade = true
  apply_immediately          = false

  tags = {
    Name = "${var.project_name}-${var.environment}-postgres"
  }
}

# ---------------------------------------------------------------------------
# RDS Enhanced Monitoring Role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "rds_monitoring" {
  count = var.enable_rds ? 1 : 0

  name = "${var.project_name}-${var.environment}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  count = var.enable_rds ? 1 : 0

  role       = aws_iam_role.rds_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ---------------------------------------------------------------------------
# SSM Parameter — RDS connection string (no plaintext secrets in TF state)
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "rds_endpoint" {
  count = var.enable_rds ? 1 : 0

  name        = "/aldeci/${var.environment}/rds/endpoint"
  description = "ALDECI RDS PostgreSQL endpoint."
  type        = "String"
  value       = aws_db_instance.aldeci[0].endpoint

  tags = {
    Name = "${var.project_name}-${var.environment}-rds-endpoint"
  }
}

resource "aws_ssm_parameter" "rds_db_name" {
  count = var.enable_rds ? 1 : 0

  name        = "/aldeci/${var.environment}/rds/db_name"
  description = "ALDECI RDS database name."
  type        = "String"
  value       = var.rds_db_name

  tags = {
    Name = "${var.project_name}-${var.environment}-rds-dbname"
  }
}
