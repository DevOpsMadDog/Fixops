# =============================================================================
# ALDECI — VPC, Subnets, Security Groups
# =============================================================================

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------

resource "aws_vpc" "aldeci" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-${var.environment}-vpc"
  }
}

# ---------------------------------------------------------------------------
# Internet Gateway
# ---------------------------------------------------------------------------

resource "aws_internet_gateway" "aldeci" {
  vpc_id = aws_vpc.aldeci.id

  tags = {
    Name = "${var.project_name}-${var.environment}-igw"
  }
}

# ---------------------------------------------------------------------------
# Public Subnets (ALB)
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.aldeci.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-${var.environment}-public-${var.availability_zones[count.index]}"
    Tier = "public"
  }
}

# ---------------------------------------------------------------------------
# Private Subnets (ECS tasks, RDS)
# ---------------------------------------------------------------------------

resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id                  = aws_vpc.aldeci.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-${var.environment}-private-${var.availability_zones[count.index]}"
    Tier = "private"
  }
}

# ---------------------------------------------------------------------------
# NAT Gateways (one per AZ for HA — ECS tasks need internet for ECR/S3)
# ---------------------------------------------------------------------------

resource "aws_eip" "nat" {
  count  = length(var.public_subnet_cidrs)
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-${var.environment}-nat-eip-${count.index}"
  }

  depends_on = [aws_internet_gateway.aldeci]
}

resource "aws_nat_gateway" "aldeci" {
  count = length(var.public_subnet_cidrs)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.project_name}-${var.environment}-nat-${var.availability_zones[count.index]}"
  }

  depends_on = [aws_internet_gateway.aldeci]
}

# ---------------------------------------------------------------------------
# Route Tables
# ---------------------------------------------------------------------------

# Public route table — routes to IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.aldeci.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.aldeci.id
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = length(var.public_subnet_cidrs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route tables — one per AZ, routes to corresponding NAT GW
resource "aws_route_table" "private" {
  count  = length(var.private_subnet_cidrs)
  vpc_id = aws_vpc.aldeci.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.aldeci[count.index].id
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-private-rt-${var.availability_zones[count.index]}"
  }
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnet_cidrs)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------

# ALB: accepts HTTP/HTTPS from the internet
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Allow HTTP and HTTPS inbound to the ALB from the internet."
  vpc_id      = aws_vpc.aldeci.id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ECS API: accepts traffic only from the ALB
resource "aws_security_group" "ecs_api" {
  name        = "${var.project_name}-${var.environment}-ecs-api-sg"
  description = "Allow inbound from ALB to the API ECS tasks."
  vpc_id      = aws_vpc.aldeci.id

  ingress {
    description     = "API port from ALB"
    from_port       = var.api_port
    to_port         = var.api_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "All outbound (ECR pull, S3, external APIs)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-ecs-api-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ECS UI: accepts traffic only from the ALB
resource "aws_security_group" "ecs_ui" {
  name        = "${var.project_name}-${var.environment}-ecs-ui-sg"
  description = "Allow inbound from ALB to the UI ECS tasks."
  vpc_id      = aws_vpc.aldeci.id

  ingress {
    description     = "UI port from ALB"
    from_port       = var.ui_port
    to_port         = var.ui_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-ecs-ui-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# RDS: accepts traffic only from ECS API tasks
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-${var.environment}-rds-sg"
  description = "Allow PostgreSQL inbound from ECS API tasks only."
  vpc_id      = aws_vpc.aldeci.id

  ingress {
    description     = "PostgreSQL from ECS API"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_api.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------------------
# VPC Flow Logs (security best practice)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}-${var.environment}/flow-logs"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.project_name}-${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.project_name}-${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "aldeci" {
  vpc_id          = aws_vpc.aldeci.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name = "${var.project_name}-${var.environment}-vpc-flow-log"
  }
}
