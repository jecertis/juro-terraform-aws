output "ecs_task_definition_arn" {
  description = "ECS task definition ARN. Use to trigger a manual scan: aws ecs run-task --cluster <cluster> --task-definition <arn> --launch-type FARGATE --network-configuration ..."
  value       = aws_ecs_task_definition.agent.arn
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster the Juro agent task runs in."
  value       = aws_ecs_cluster.juro.name
}

output "agent_task_role_arn" {
  description = "ARN of the IAM task role the agent assumes. Record only the SHA-256 in engagement state, never the ARN itself."
  value       = aws_iam_role.agent.arn
  sensitive   = true
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name where agent logs are written."
  value       = aws_cloudwatch_log_group.agent.name
}

output "rule_pack_registry_parameter" {
  description = "SSM parameter name storing the rule-pack registry URL."
  value       = aws_ssm_parameter.rule_pack_registry.name
}

output "scan_schedule_rule_name" {
  description = "Name of the EventBridge rule that triggers scheduled scans. Use `aws events list-rules --name-prefix <name>` to verify State=ENABLED."
  value       = aws_cloudwatch_event_rule.scan_schedule.name
}

output "expires_at" {
  description = "Engagement expiration date — externally enforced."
  value       = var.expires_at
}
