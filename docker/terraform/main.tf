# =============================================================================
# ALDECI — Main Terraform Configuration
# AWS ECS Fargate deployment: API + UI, ALB, Route53, ACM
#
# Usage:
#   terraform init
#   terraform plan -var-file=terraform.tfvars
#   terraform apply -var-file=terraform.tfvars
#
# Docs: docs/ALDECI_REARCHITECTURE_v2.md
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Remote state — uncomment and configure for team deployments
  # backend "s3" {
  #   bucket         = "aldeci-terraform-state"
  #   key            = "aldeci/production/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "aldeci-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        Environment = var.environment
        ManagedBy   = "terraform"
        Repository  = "DevOpsMadDog/Fixops"
      },
      var.tags
    )
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "aldeci" {
  name         = var.domain_name
  private_zone = false
}

# ---------------------------------------------------------------------------
# ACM Certificate (must be in us-east-1 for CloudFront; ALB uses same region)
# ---------------------------------------------------------------------------

resource "aws_acm_certificate" "aldeci" {
  domain_name = var.domain_name

  subject_alternative_names = [
    "*.${var.domain_name}",
    "${var.api_subdomain}.${var.domain_name}",
    "${var.ui_subdomain}.${var.domain_name}",
  ]

  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.aldeci.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.aldeci.zone_id
}

resource "aws_acm_certificate_validation" "aldeci" {
  certificate_arn         = aws_acm_certificate.aldeci.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ---------------------------------------------------------------------------
# Application Load Balancer
# ---------------------------------------------------------------------------

resource "aws_lb" "aldeci" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"

  security_groups = [aws_security_group.alb.id]
  subnets         = aws_subnet.public[*].id

  enable_deletion_protection       = var.environment == "production"
  enable_cross_zone_load_balancing = true
  drop_invalid_header_fields       = true

  access_logs {
    bucket  = aws_s3_bucket.backups.bucket
    prefix  = "alb-access-logs"
    enabled = true
  }
}

# HTTP → HTTPS redirect
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.aldeci.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# HTTPS listener — default 404 (routing by host header below)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.aldeci.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.aldeci.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

# API target group
resource "aws_lb_target_group" "api" {
  name        = "${var.project_name}-${var.environment}-api-tg"
  port        = var.api_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.aldeci.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  deregistration_delay = 30
}

# UI target group
resource "aws_lb_target_group" "ui" {
  name        = "${var.project_name}-${var.environment}-ui-tg"
  port        = var.ui_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.aldeci.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
  }

  deregistration_delay = 30
}

# Listener rule: api subdomain → API target group
resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    host_header {
      values = ["${var.api_subdomain}.${var.domain_name}"]
    }
  }
}

# Listener rule: ui subdomain → UI target group
resource "aws_lb_listener_rule" "ui" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ui.arn
  }

  condition {
    host_header {
      values = ["${var.ui_subdomain}.${var.domain_name}"]
    }
  }
}

# ---------------------------------------------------------------------------
# Route53 Records
# ---------------------------------------------------------------------------

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.aldeci.zone_id
  name    = "${var.api_subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.aldeci.dns_name
    zone_id                = aws_lb.aldeci.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "ui" {
  zone_id = data.aws_route53_zone.aldeci.zone_id
  name    = "${var.ui_subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.aldeci.dns_name
    zone_id                = aws_lb.aldeci.zone_id
    evaluate_target_health = true
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Log Groups
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.project_name}/${var.environment}/api"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "ui" {
  name              = "/ecs/${var.project_name}/${var.environment}/ui"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Random suffix for globally-unique resource names
# ---------------------------------------------------------------------------

resource "random_id" "suffix" {
  byte_length = 4
}
