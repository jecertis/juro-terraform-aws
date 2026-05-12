output "agent_task_arn" {
  description = "ARN of the most recently started Juro agent ECS task. Use this in Phase 2.1 (`aws ecs execute-command --task <arn>`) to run `juro preflight`."
  value       = "${aws_ecs_cluster.juro.arn}/${aws_ecs_task_definition.agent.family}"
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster the Juro agent runs in."
  value       = aws_ecs_cluster.juro.name
}

output "ecs_service_name" {
  description = "Name of the ECS service managing the Juro agent task."
  value       = aws_ecs_service.agent.name
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
