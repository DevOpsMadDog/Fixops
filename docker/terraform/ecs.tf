# =============================================================================
# ALDECI — ECS Cluster, Task Definitions, Services, Auto-Scaling
# =============================================================================

# ---------------------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "aldeci" {
  name = "${var.project_name}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "aldeci" {
  cluster_name = aws_ecs_cluster.aldeci.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# ---------------------------------------------------------------------------
# API Task Definition
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.project_name}-${var.environment}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory

  execution_role_arn = aws_iam_role.ecs_task_execution.arn
  task_role_arn      = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "aldeci-api"
      image     = var.api_image
      essential = true

      portMappings = [
        {
          containerPort = var.api_port
          hostPort      = var.api_port
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "PORT", value = tostring(var.api_port) },
        { name = "FIXOPS_USE_COUNCIL", value = var.fixops_use_council },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "LOG_LEVEL", value = var.environment == "production" ? "INFO" : "DEBUG" },
      ]

      secrets = var.api_key_secret_arn != "" ? [
        {
          name      = "API_SECRET_KEY"
          valueFrom = var.api_key_secret_arn
        }
      ] : []

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "api"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.api_port}/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      readonlyRootFilesystem = false
      privileged             = false
      user                   = "1000"
    }
  ])

  tags = {
    Name = "${var.project_name}-${var.environment}-api-task"
  }
}

# ---------------------------------------------------------------------------
# UI Task Definition
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "ui" {
  family                   = "${var.project_name}-${var.environment}-ui"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.ui_cpu
  memory                   = var.ui_memory

  execution_role_arn = aws_iam_role.ecs_task_execution.arn
  task_role_arn      = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "aldeci-ui"
      image     = var.ui_image
      essential = true

      portMappings = [
        {
          containerPort = var.ui_port
          hostPort      = var.ui_port
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "VITE_API_URL", value = "https://${var.api_subdomain}.${var.domain_name}" },
        { name = "NODE_ENV", value = var.environment == "production" ? "production" : "development" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ui.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ui"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.ui_port}/ || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      readonlyRootFilesystem = false
      privileged             = false
      user                   = "1000"
    }
  ])

  tags = {
    Name = "${var.project_name}-${var.environment}-ui-task"
  }
}

# ---------------------------------------------------------------------------
# ECS Services
# ---------------------------------------------------------------------------

resource "aws_ecs_service" "api" {
  name            = "${var.project_name}-${var.environment}-api"
  cluster         = aws_ecs_cluster.aldeci.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count

  launch_type         = "FARGATE"
  platform_version    = "LATEST"
  scheduling_strategy = "REPLICA"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "aldeci-api"
    container_port   = var.api_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  health_check_grace_period_seconds = 60

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lb_listener_rule.api,
    aws_iam_role_policy_attachment.ecs_task_execution,
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-api-service"
  }
}

resource "aws_ecs_service" "ui" {
  name            = "${var.project_name}-${var.environment}-ui"
  cluster         = aws_ecs_cluster.aldeci.id
  task_definition = aws_ecs_task_definition.ui.arn
  desired_count   = var.ui_desired_count

  launch_type         = "FARGATE"
  platform_version    = "LATEST"
  scheduling_strategy = "REPLICA"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_ui.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ui.arn
    container_name   = "aldeci-ui"
    container_port   = var.ui_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  health_check_grace_period_seconds = 30

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lb_listener_rule.ui,
    aws_iam_role_policy_attachment.ecs_task_execution,
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-ui-service"
  }
}

# ---------------------------------------------------------------------------
# Auto-Scaling — API
# ---------------------------------------------------------------------------

resource "aws_appautoscaling_target" "api" {
  max_capacity       = var.api_max_count
  min_capacity       = var.api_min_count
  resource_id        = "service/${aws_ecs_cluster.aldeci.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "${var.project_name}-${var.environment}-api-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "api_memory" {
  name               = "${var.project_name}-${var.environment}-api-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 80.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ---------------------------------------------------------------------------
# Auto-Scaling — UI
# ---------------------------------------------------------------------------

resource "aws_appautoscaling_target" "ui" {
  max_capacity       = var.ui_max_count
  min_capacity       = var.ui_min_count
  resource_id        = "service/${aws_ecs_cluster.aldeci.name}/${aws_ecs_service.ui.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ui_cpu" {
  name               = "${var.project_name}-${var.environment}-ui-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ui.resource_id
  scalable_dimension = aws_appautoscaling_target.ui.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ui.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
