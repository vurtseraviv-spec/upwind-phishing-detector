output "application_url" {
  description = "Public URL of the PhishGuard AI Detector via ALB"
  value       = "http://${aws_lb.main.dns_name}"
}

output "cloudwatch_dashboard_url" {
  description = "Direct link to the CloudWatch Monitoring Dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "rds_endpoint" {
  value = aws_db_instance.main.endpoint
}

output "redis_endpoint" {
  value = var.enable_elasticache ? aws_elasticache_cluster.redis[0].cache_nodes[0].address : "disabled"
}
