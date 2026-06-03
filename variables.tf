terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider
# -----------------------------------------------------------------------------

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region where the agent task and supporting resources are created."
  type        = string
}

variable "agent_image_tag" {
  description = "Pinned tag of the ghcr.io/jecertis/cloud-scanner image. Set from the SOW — must match the image digest listed there."
  type        = string
}

variable "rule_pack_registry" {
  description = "OCI registry URL for Juro rule packs. Override only when mirroring to an internal registry."
  type        = string
  default     = "ghcr.io/jecertis/juro-rules"
}

variable "artifact_store_bucket" {
  description = "Customer-owned S3 bucket where signed scan artifacts are written. The agent adds a PutObject-only policy to this bucket."
  type        = string
}

variable "oidc_issuer" {
  description = "OIDC provider URL bound to the customer's AWS account (e.g. https://token.actions.githubusercontent.com or a corporate IdP). Used by Fulcio to issue leaf certificates for cosign signatures."
  type        = string
}

variable "telemetry_enabled" {
  description = "When false, the agent does not publish records to the Juro transparency log. The kill-switch is intentional — customer can disable at any time without breaking scanning."
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "EventBridge cron expression for the scheduled scan. Default is daily at 03:00 UTC. Must be in EventBridge cron syntax: cron(minutes hours day-of-month month day-of-week year)."
  type        = string
  default     = "cron(0 3 * * ? *)"
}

variable "subnet_ids" {
  description = "List of private subnet IDs where the Fargate task runs. Must be in the same region as aws_region. Public-subnet deployment breaks the preflight egress attestation."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security group IDs to attach to the Fargate task. Must allow egress to cloud API endpoints, GHCR, and the Juro transparency log endpoint."
  type        = list(string)
}

variable "engagement_slug" {
  description = "Juro engagement slug (kebab-case). Used in resource names and tags."
  type        = string
}

# expires_at — engagement expiry (externally enforced)
#
# AWS IAM does not natively expire roles or policies. Enforcement is the customer's
# responsibility: when the engagement ends, run:
#
#   terraform destroy -var-file="terraform.tfvars"
#
# This removes all resources created by this module (IAM roles, ECS cluster, task
# definition, EventBridge rule, CloudWatch log group, SSM parameters). The artifact
# store bucket is customer-owned and is NOT destroyed — findings are retained by the
# customer per their own retention policy.
#
# Recommended: set a calendar reminder for the expires_at date at engagement start.
variable "expires_at" {
  description = "Engagement expiration date (RFC 3339). Externally enforced — AWS IAM does not natively expire roles. Run `terraform destroy -var-file=terraform.tfvars` when the engagement ends."
  type        = string
}
