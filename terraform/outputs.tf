output "permission_boundary_arn" {
  description = "ARN of the permission boundary policy"
  value       = aws_iam_policy.permission_boundary.arn
}

output "break_glass_role_arn" {
  description = "ARN of the break-glass emergency role"
  value       = aws_iam_role.break_glass.arn
}

output "developers_group" {
  description = "IAM group for developers"
  value       = aws_iam_group.developers.name
}

output "security_analysts_group" {
  description = "IAM group for security analysts"
  value       = aws_iam_group.security_analysts.name
}
