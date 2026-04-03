---
name: Infrastructure Development
description: Enterprise infrastructure patterns for AWS VPC, ECS, and PrivateLink deployments
---

# Infrastructure Development Skill

> Enterprise-grade infrastructure patterns for secure, scalable AWS deployments

## Overview

This skill provides patterns and best practices for infrastructure development in enterprise environments requiring network isolation, security, and compliance. Focus on AWS VPC with PrivateLink, ECS Fargate, and Terraform infrastructure-as-code.

## Core Patterns

### VPC Network Isolation

```hcl
# Zero-egress VPC pattern
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
    Environment = var.environment
  }
}

# No internet gateway - PrivateLink only
# Private subnets in multiple AZs
resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.project_name}-private-${count.index + 1}"
    Type = "Private"
  }
}
```

### PrivateLink Endpoints Pattern

```hcl
# Essential VPC endpoints for air-gapped deployment
locals {
  vpc_endpoints = {
    s3 = {
      service_name = "com.amazonaws.${var.region}.s3"
      type         = "Gateway"
    }
    bedrock = {
      service_name = "com.amazonaws.${var.region}.bedrock-runtime"
      type         = "Interface"
    }
    secrets_manager = {
      service_name = "com.amazonaws.${var.region}.secretsmanager"
      type         = "Interface"
    }
    ecr = {
      service_name = "com.amazonaws.${var.region}.ecr.dkr"
      type         = "Interface"
    }
    opensearch = {
      service_name = "com.amazonaws.${var.region}.opensearch-serverless"
      type         = "Interface"
    }
  }
}

resource "aws_vpc_endpoint" "endpoints" {
  for_each = local.vpc_endpoints

  vpc_id              = aws_vpc.main.id
  service_name        = each.value.service_name
  vpc_endpoint_type   = each.value.type
  subnet_ids          = each.value.type == "Interface" ? aws_subnet.private[*].id : null
  security_group_ids  = each.value.type == "Interface" ? [aws_security_group.vpc_endpoints.id] : null

  tags = {
    Name = "${var.project_name}-${each.key}-endpoint"
  }
}
```

### ECS Fargate Security Pattern

```hcl
# Task definition with minimal IAM permissions
resource "aws_ecs_task_definition" "secure_service" {
  family                   = "${var.project_name}-${var.service_name}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu_units
  memory                   = var.memory_mb
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn           = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name  = var.service_name
    image = "${var.ecr_repository_url}:${var.image_tag}"

    # Security configuration
    readonlyRootFilesystem = true

    # Resource limits
    cpu    = var.cpu_units
    memory = var.memory_mb

    # Logging
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.service.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs"
      }
    }

    # Environment variables
    environment = [
      for key, value in var.environment_variables : {
        name  = key
        value = value
      }
    ]

    # Secrets from AWS Secrets Manager
    secrets = [
      for key, secret_arn in var.secrets : {
        name      = key
        valueFrom = secret_arn
      }
    ]
  }])
}
```

### Security Group Least Privilege Pattern

```hcl
# Service-specific security groups with minimal access
resource "aws_security_group" "service" {
  name_prefix = "${var.project_name}-${var.service_name}"
  description = "Security group for ${var.service_name} service"
  vpc_id      = var.vpc_id

  # Only allow inbound traffic from ALB
  ingress {
    from_port       = var.service_port
    to_port         = var.service_port
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
    description     = "Traffic from ALB"
  }

  # Allow outbound to specific services only
  dynamic "egress" {
    for_each = var.allowed_outbound_services
    content {
      from_port       = egress.value.port
      to_port         = egress.value.port
      protocol        = "tcp"
      security_groups = [egress.value.security_group_id]
      description     = "Access to ${egress.value.description}"
    }
  }

  # VPC endpoint access
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS to VPC endpoints"
  }

  tags = {
    Name = "${var.project_name}-${var.service_name}-sg"
  }
}
```

### IAM Minimal Permissions Pattern

```hcl
# Service-specific IAM role with least privilege
data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Custom policy for specific service needs
data "aws_iam_policy_document" "service_policy" {
  # S3 access scoped to specific bucket/prefix
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = [
      "${var.workspace_bucket_arn}/${var.service_name}/*"
    ]
  }

  # Bedrock access for AI services
  dynamic "statement" {
    for_each = var.enable_bedrock_access ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ]
      resources = var.allowed_bedrock_models
    }
  }

  # Secrets Manager access for specific secrets
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = var.secret_arns
  }
}
```

## Infrastructure Testing Patterns

### Terraform Validation

```bash
# Infrastructure validation pipeline
terraform fmt -check
terraform validate
terraform plan -detailed-exitcode

# Security scanning
tfsec .
checkov -f terraform

# Cost estimation
infracost breakdown --path .
```

### Integration Testing

```python
# Infrastructure integration tests
import boto3
import pytest

class TestVPCConfiguration:
    def test_vpc_has_no_internet_gateway(self, vpc_id):
        ec2 = boto3.client('ec2')
        igws = ec2.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
        )
        assert len(igws['InternetGateways']) == 0

    def test_private_subnets_have_no_public_ips(self, subnet_ids):
        ec2 = boto3.client('ec2')
        for subnet_id in subnet_ids:
            subnet = ec2.describe_subnets(SubnetIds=[subnet_id])
            assert not subnet['Subnets'][0]['MapPublicIpOnLaunch']

    def test_vpc_endpoints_accessible(self, vpc_id):
        ec2 = boto3.client('ec2')
        endpoints = ec2.describe_vpc_endpoints(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        required_services = ['s3', 'bedrock-runtime', 'secretsmanager']
        endpoint_services = [ep['ServiceName'].split('.')[-1] for ep in endpoints['VpcEndpoints']]

        for service in required_services:
            assert any(service in eps for eps in endpoint_services)
```

## Cost Optimization Patterns

### Resource Tagging Strategy

```hcl
# Consistent tagging for cost allocation
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
    Service     = var.service_name
    ManagedBy   = "terraform"
  }
}

# Apply tags to all resources
resource "aws_instance" "example" {
  # ... other configuration
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.service_name}"
  })
}
```

### Auto-scaling Configuration

```hcl
# ECS service auto-scaling based on metrics
resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu_scaling" {
  name               = "${var.service_name}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}
```

## Monitoring and Observability

### CloudWatch Configuration

```hcl
# Comprehensive logging and monitoring
resource "aws_cloudwatch_log_group" "service" {
  name              = "/ecs/${var.project_name}/${var.service_name}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.service_name}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ecs cpu utilization"

  dimensions = {
    ServiceName = aws_ecs_service.main.name
    ClusterName = aws_ecs_cluster.main.name
  }

  alarm_actions = [var.sns_alarm_topic_arn]

  tags = local.common_tags
}
```

## Security Best Practices

### Network Security

- No internet gateway in VPC
- Private subnets only
- VPC endpoints for AWS services
- Security groups with least privilege
- NACLs for additional layer protection

### Access Control

- Service-specific IAM roles
- Minimal required permissions
- Secrets Manager for credentials
- Regular IAM access reviews
- Resource-based policies where appropriate

### Compliance

- Encryption in transit and at rest
- Audit logging for all actions
- Regular security assessments
- Compliance framework mapping
- Documentation and evidence collection

## Usage Guidelines

### When to Use

- Enterprise applications requiring network isolation
- Regulated industries with data sovereignty requirements
- Multi-tenant applications with strict isolation needs
- Applications handling sensitive data
- Production environments requiring high security

### Implementation Checklist

- [ ] VPC designed with no internet gateway
- [ ] VPC endpoints configured for all required AWS services
- [ ] Security groups implement least privilege access
- [ ] IAM roles scoped to specific service needs
- [ ] Encryption enabled for data at rest and in transit
- [ ] Logging configured for audit and monitoring
- [ ] Auto-scaling configured for cost optimization
- [ ] Resource tagging for cost allocation
- [ ] Infrastructure testing implemented
- [ ] Monitoring and alerting configured
