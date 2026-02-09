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
  retention_days = local.telemetry_config.retention_days
  ring_buffer = local.telemetry_config.ring_buffer
  fluentbit = local.telemetry_config.fluentbit
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-vpc"
  })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-private-${count.index + 1}"
  })
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 101}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-public-${count.index + 1}"
  })
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-igw"
  })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-nat-eip"
  })
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-nat"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-public-rt"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-private-rt"
  })
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "alb" {
  name        = "${var.prefix}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-alb-sg"
  })
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.prefix}-ecs-tasks-sg"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.prefix}-ecs-tasks-sg"
  })
}

resource "aws_s3_bucket" "evidence" {
  bucket        = local.aws_config.s3_bucket
  force_destroy = false
  
  tags = var.tags
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  
  rule {
    id     = "raw-logs-retention"
    status = "Enabled"
    
    filter {
      prefix = "raw/"
    }
    
    expiration {
      days = local.retention_days.raw
    }
  }
  
  rule {
    id     = "summary-retention"
    status = "Enabled"
    
    filter {
      prefix = "summary/"
    }
    
    expiration {
      days = local.retention_days.summary
    }
  }
  
  rule {
    id     = "evidence-lifecycle"
    status = "Enabled"
    
    filter {
      prefix = "evidence/"
    }
    
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }
    
    transition {
      days          = local.retention_days.evidence
      storage_class = "DEEP_ARCHIVE"
    }
  }
}

resource "aws_cloudwatch_log_group" "collector" {
  name              = "/ecs/${var.prefix}-collector"
  retention_in_days = local.retention_days.summary
  
  tags = var.tags
}

resource "aws_ecs_cluster" "main" {
  name = "${var.prefix}-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = var.tags
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.prefix}-ecs-task-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task" {
  name = "${var.prefix}-ecs-task-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy" "ecs_task_s3" {
  name = "${var.prefix}-ecs-task-s3-policy"
  role = aws_iam_role.ecs_task.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.evidence.arn,
        "${aws_s3_bucket.evidence.arn}/*"
      ]
    }]
  })
}

resource "aws_ecr_repository" "collector_api" {
  name                 = "${var.prefix}-collector-api"
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  tags = var.tags
}

resource "aws_ecr_repository" "fluent_bit" {
  name                 = "${var.prefix}-fluent-bit"
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  tags = var.tags
}

resource "aws_ecs_task_definition" "collector" {
  family                   = "${var.prefix}-collector"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn
  
  container_definitions = jsonencode([
    {
      name      = "collector-api"
      image     = "${aws_ecr_repository.collector_api.repository_url}:latest"
      essential = true
      
      portMappings = [{
        containerPort = 8080
        protocol      = "tcp"
      }]
      
      environment = [
        {
          name  = "FIXOPS_OVERLAY_PATH"
          value = "/app/config/fixops.overlay.yml"
        },
        {
          name  = "CLOUD_PROVIDER"
          value = "aws"
        },
        {
          name  = "RING_BUFFER_MAX_LINES"
          value = tostring(local.ring_buffer.max_lines)
        },
        {
          name  = "RING_BUFFER_MAX_SECONDS"
          value = tostring(local.ring_buffer.max_seconds)
        }
      ]
      
      secrets = [{
        name      = "FIXOPS_API_KEY"
        valueFrom = var.fixops_api_key_secret_arn
      }]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.collector.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "collector-api"
        }
      }
    },
    {
      name      = "fluent-bit"
      image     = "${aws_ecr_repository.fluent_bit.repository_url}:latest"
      essential = false
      
      environment = [
        {
          name  = "INPUT_PATH"
          value = local.fluentbit.input_path
        },
        {
          name  = "AGGREGATION_INTERVAL"
          value = tostring(local.fluentbit.aggregation_interval)
        },
        {
          name  = "RETRY_LIMIT"
          value = tostring(local.fluentbit.retry_limit)
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.collector.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "fluent-bit"
        }
      }
    }
  ])
  
  tags = var.tags
}

resource "aws_lb" "main" {
  name               = "${var.prefix}-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  
  tags = var.tags
}

resource "aws_lb_target_group" "collector" {
  name        = "${var.prefix}-collector-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = var.tags
}

resource "aws_lb_listener" "collector" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.collector.arn
  }
}

resource "aws_ecs_service" "collector" {
  name            = "${var.prefix}-collector-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.collector.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  
  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.collector.arn
    container_name   = "collector-api"
    container_port   = 8080
  }
  
  depends_on = [aws_lb_listener.collector]
  
  tags = var.tags
}
