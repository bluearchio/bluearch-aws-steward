output "account_id" {
  value     = data.aws_caller_identity.current.account_id
  sensitive = true
}

output "region" {
  value = var.region
}

output "run_id" {
  value = var.run_id
}

output "healthy_cluster_name" {
  value = aws_eks_cluster.healthy.name
}

output "vulnerable_cluster_name" {
  value = aws_eks_cluster.vulnerable.name
}

output "mcp_read_role_arn" {
  value = aws_iam_role.mcp_read.arn
}

output "node_role_arn" {
  value = aws_iam_role.node.arn
}

output "broken_subnet_id" {
  value = aws_subnet.broken.id
}

output "common_tags" {
  value = local.common_tags
}
