# Juro Tier 3 agent — AWS infrastructure module
#
# Provisions the full Juro agent stack inside the customer's AWS account.
# All resources are named with the engagement slug for isolation and auditability.
# See contracts/tier-3-install.md §Phase 1 for the expected resource set.
#
# Customer applies this in their own Terraform state. The PR and plan output
# are the customer's audit trail. Do NOT apply from Juro's environment.

locals {
  name_prefix = "juro-agent-${var.engagement_slug}"
  common_tags = {
    EngagementSlug = var.engagement_slug
    Purpose        = "juro-compliance-scan"
    ExpiresAt      = var.expires_at
    ManagedBy      = "juro-terraform-aws"
  }
}

# -----------------------------------------------------------------------------
# IAM — task role (read-only permissions the agent uses to enumerate resources)
# Source of truth for permissions: contracts/iam-policy-aws.md
# -----------------------------------------------------------------------------

resource "aws_iam_role" "agent" {
  name               = "${local.name_prefix}-task-role"
  description        = "Read-only task role for the Juro Tier 3 compliance agent. Expires ${var.expires_at}."
  assume_role_policy = data.aws_iam_policy_document.agent_trust.json
  permissions_boundary = aws_iam_policy.agent_boundary.arn
  tags               = local.common_tags
}

data "aws_iam_policy_document" "agent_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role_policy" "agent_readonly" {
  name   = "juro-agent-readonly"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent_readonly.json
}

data "aws_iam_policy_document" "agent_readonly" {
  statement {
    sid    = "IAMRead"
    effect = "Allow"
    actions = [
      "iam:Get*",
      "iam:List*",
      "iam:SimulatePrincipalPolicy",
      "iam:SimulateCustomPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "LambdaRead"
    effect = "Allow"
    actions = [
      "lambda:Get*",
      "lambda:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "S3BucketMetadataRead"
    effect = "Allow"
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketNotification",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetBucketWebsite",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "RDSRead"
    effect = "Allow"
    actions = [
      "rds:Describe*",
      "rds:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DynamoDBRead"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:ListGlobalTables",
      "dynamodb:ListTables",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudTrailRead"
    effect = "Allow"
    actions = [
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:Lookup*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "KMSReadNoDecrypt"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListGrants",
      "kms:ListKeyPolicies",
      "kms:ListKeys",
      "kms:ListResourceTags",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SecretsManagerMetadataRead"
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
      "secretsmanager:ListSecretVersionIds",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SSMMetadataRead"
    effect = "Allow"
    actions = [
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsRead"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:ListTagsLogGroup",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudFrontRead"
    effect = "Allow"
    actions = [
      "cloudfront:Describe*",
      "cloudfront:Get*",
      "cloudfront:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "APIGatewayRead"
    effect = "Allow"
    actions = [
      "apigateway:GET",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EC2VPCRead"
    effect = "Allow"
    actions = [
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeRouteTables",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeNatGateways",
    ]
    resources = ["*"]
  }

  # Artifact store write — agent writes signed findings to the customer-owned bucket
  statement {
    sid    = "ArtifactStorePutObject"
    effect = "Allow"
    actions = [
      "s3:PutObject",
    ]
    resources = ["arn:aws:s3:::${var.artifact_store_bucket}/juro/*"]
  }

  # SSM — read the rule-pack registry parameter that this module creates
  statement {
    sid    = "ReadOwnSSMParameter"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
    ]
    resources = ["arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/juro/${var.engagement_slug}/*"]
  }

  # STS — caller identity check in preflight
  statement {
    sid    = "STSCallerIdentity"
    effect = "Allow"
    actions = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

# -----------------------------------------------------------------------------
# Permission boundary — caps effective permissions even if role policy changes
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "agent_boundary" {
  name        = "${local.name_prefix}-boundary"
  description = "Permission boundary for Juro agent task role. Denies writes and PII-reading actions regardless of role policy."
  policy      = data.aws_iam_policy_document.agent_boundary.json
  tags        = local.common_tags
}

data "aws_iam_policy_document" "agent_boundary" {
  statement {
    sid    = "AllowReadOnlyAndArtifactWrite"
    effect = "Allow"
    actions = [
      "iam:Get*", "iam:List*", "iam:Simulate*",
      "lambda:Get*", "lambda:List*",
      "s3:Get*", "s3:List*",
      "s3:PutObject",
      "rds:Describe*", "rds:List*",
      "dynamodb:DescribeTable", "dynamodb:ListGlobalTables", "dynamodb:ListTables",
      "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*", "cloudtrail:Lookup*",
      "kms:Describe*", "kms:Get*", "kms:List*",
      "secretsmanager:Describe*", "secretsmanager:List*",
      "ssm:Describe*", "ssm:Get*", "ssm:List*",
      "cloudfront:Describe*", "cloudfront:Get*", "cloudfront:List*",
      "apigateway:GET",
      "logs:DescribeLogGroups", "logs:ListTagsLogGroup",
      "ec2:Describe*",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyPIIRead"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Scan",
      "dynamodb:Query",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyAllMutations"
    effect = "Deny"
    actions = [
      "*:Create*", "*:Delete*", "*:Put*", "*:Update*",
      "*:Modify*", "*:Attach*", "*:Detach*",
      "*:Start*", "*:Stop*", "*:Run*", "*:Terminate*",
    ]
    # Allow the one exception: PutObject to the artifact store
    not_resources = ["arn:aws:s3:::${var.artifact_store_bucket}/juro/*"]
  }
}

# -----------------------------------------------------------------------------
# IAM — ECS task execution role (pulls image, writes logs)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "execution" {
  name               = "${local.name_prefix}-exec-role"
  description        = "ECS task execution role for Juro agent. Pulls image from GHCR and writes to CloudWatch Logs."
  assume_role_policy = data.aws_iam_policy_document.execution_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "execution_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Execution role needs to read the rule-pack registry SSM parameter at task start
resource "aws_iam_role_policy" "execution_ssm" {
  name   = "juro-exec-ssm"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_ssm.json
}

data "aws_iam_policy_document" "execution_ssm" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/juro/${var.engagement_slug}/*"]
  }
}

# -----------------------------------------------------------------------------
# CloudWatch log group
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/juro/agent/${var.engagement_slug}"
  retention_in_days = 90
  tags              = local.common_tags
}

# -----------------------------------------------------------------------------
# SSM parameter — rule-pack registry URL
# Agent reads this at startup to know where to pull rule packs from.
# -----------------------------------------------------------------------------

resource "aws_ssm_parameter" "rule_pack_registry" {
  name        = "/juro/${var.engagement_slug}/rule-pack-registry"
  description = "OCI registry URL for Juro rule packs. Agent reads on startup."
  type        = "String"
  value       = var.rule_pack_registry
  tags        = local.common_tags
}

resource "aws_ssm_parameter" "telemetry_enabled" {
  name        = "/juro/${var.engagement_slug}/telemetry-enabled"
  description = "Telemetry kill-switch. Set to 'false' to disable transparency log publishing."
  type        = "String"
  value       = tostring(var.telemetry_enabled)
  tags        = local.common_tags
}

# -----------------------------------------------------------------------------
# ECS cluster
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "juro" {
  name = "juro-${var.engagement_slug}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = local.common_tags
}

resource "aws_ecs_cluster_capacity_providers" "juro" {
  cluster_name       = aws_ecs_cluster.juro.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# -----------------------------------------------------------------------------
# ECS task definition
# -----------------------------------------------------------------------------

resource "aws_ecs_task_definition" "agent" {
  family                   = local.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  task_role_arn            = aws_iam_role.agent.arn
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([
    {
      name      = "juro-agent"
      image     = "ghcr.io/jecertis/cloud-scanner:${var.agent_image_tag}"
      essential = true

      environment = [
        {
          name  = "JURO_ENGAGEMENT_SLUG"
          value = var.engagement_slug
        },
        {
          name  = "JURO_ARTIFACT_STORE"
          value = "s3://${var.artifact_store_bucket}/juro/${var.engagement_slug}"
        },
        {
          name  = "JURO_OIDC_ISSUER"
          value = var.oidc_issuer
        },
        {
          name  = "JURO_CLOUD"
          value = "aws"
        },
        {
          name  = "JURO_REGION"
          value = var.aws_region
        }
      ]

      secrets = [
        {
          name      = "JURO_RULE_PACK_REGISTRY"
          valueFrom = aws_ssm_parameter.rule_pack_registry.arn
        },
        {
          name      = "JURO_TELEMETRY_ENABLED"
          valueFrom = aws_ssm_parameter.telemetry_enabled.arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.agent.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent"
        }
      }

    }
  ])

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EventBridge — scheduled scan
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "scan_schedule" {
  name                = "${local.name_prefix}-schedule"
  description         = "Triggers the Juro compliance agent scan on the customer-configured schedule."
  schedule_expression = var.scan_schedule
  state               = "ENABLED"
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "scan_schedule" {
  rule     = aws_cloudwatch_event_rule.scan_schedule.name
  arn      = aws_ecs_cluster.juro.arn
  role_arn = aws_iam_role.events_invoke.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.agent.arn
    task_count          = 1
    launch_type         = "FARGATE"

    network_configuration {
      subnets          = var.subnet_ids
      security_groups  = var.security_group_ids
      assign_public_ip = false
    }
  }
}

# IAM role for EventBridge to run the ECS task
resource "aws_iam_role" "events_invoke" {
  name               = "${local.name_prefix}-events-role"
  description        = "Allows EventBridge to run the Juro agent ECS task on schedule."
  assume_role_policy = data.aws_iam_policy_document.events_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "events_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "events_invoke" {
  name   = "juro-events-run-task"
  role   = aws_iam_role.events_invoke.id
  policy = data.aws_iam_policy_document.events_invoke.json
}

data "aws_iam_policy_document" "events_invoke" {
  statement {
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = [aws_ecs_task_definition.agent.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.agent.arn, aws_iam_role.execution.arn]
    condition {
      test     = "StringLike"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}
