terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ---------------------------
# IAM Groups
# ---------------------------
resource "aws_iam_group" "developers" {
  name = "${var.project_name}-developers"
}

resource "aws_iam_group" "security_analysts" {
  name = "${var.project_name}-security-analysts"
}

# ---------------------------
# Permission Boundary Policy
# ---------------------------
resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.project_name}-permission-boundary"
  description = "Maximum permissions cap — no IAM escalation, no security service modification"
  policy      = file("${path.module}/../policies/permission-boundary.json")
}

# ---------------------------
# MFA Enforcement Policy
# ---------------------------
resource "aws_iam_policy" "mfa_enforcement" {
  name        = "${var.project_name}-mfa-enforcement"
  description = "Denies all actions except MFA management without MFA"
  policy      = file("${path.module}/../policies/mfa-enforcement.json")
}

resource "aws_iam_group_policy_attachment" "mfa_developers" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.mfa_enforcement.arn
}

resource "aws_iam_group_policy_attachment" "mfa_analysts" {
  group      = aws_iam_group.security_analysts.name
  policy_arn = aws_iam_policy.mfa_enforcement.arn
}

# ---------------------------
# Least Privilege Policy
# ---------------------------
resource "aws_iam_policy" "least_privilege" {
  name        = "${var.project_name}-least-privilege"
  description = "Least privilege policy with ABAC tag-based access control"
  policy      = file("${path.module}/../policies/least-privilege.json")
}

resource "aws_iam_group_policy_attachment" "least_privilege_developers" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.least_privilege.arn
}

# ---------------------------
# Security Analyst Policy
# ---------------------------
resource "aws_iam_policy" "security_analyst" {
  name        = "${var.project_name}-security-analyst"
  description = "Read-only security monitoring policy — no data access"
  policy      = file("${path.module}/../policies/security-analyst.json")
}

resource "aws_iam_group_policy_attachment" "security_analyst_group" {
  group      = aws_iam_group.security_analysts.name
  policy_arn = aws_iam_policy.security_analyst.arn
}

# ---------------------------
# Break-Glass Emergency Role
# ---------------------------
resource "aws_iam_role" "break_glass" {
  name        = "${var.project_name}-break-glass-role"
  description = "Emergency access role — requires MFA and logs all activity"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "3600"
          }
        }
      }
    ]
  })

  permissions_boundary = aws_iam_policy.permission_boundary.arn

  tags = {
    Purpose     = "BreakGlass"
    MFARequired = "true"
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
