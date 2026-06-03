# Zero Trust & IAM Security Lab

## Overview
A production-grade Zero Trust architecture implementation on AWS demonstrating
enterprise identity and access management patterns used in regulated financial
environments. Covers least privilege IAM policies, Service Control Policies (SCPs),
Attribute-Based Access Control (ABAC), MFA enforcement, and automated IAM
security auditing.

## Zero Trust Principles Implemented

| Principle | Implementation |
|-----------|---------------|
| Never trust, always verify | MFA required for all sensitive operations |
| Least privilege access | Fine-grained IAM policies with permission boundaries |
| Assume breach | SCPs prevent privilege escalation even with admin credentials |
| Verify explicitly | ABAC — access granted based on resource tags and user attributes |
| Limit blast radius | Permission boundaries cap maximum permissions |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Organization                          │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Service Control Policies (SCPs)            │    │
│  │     (Account-level guardrails — cannot be bypassed) │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Dev Env    │  │  Staging Env │  │  Production Env  │  │
│  │              │  │              │  │                  │  │
│  │  IAM Roles   │  │  IAM Roles   │  │  IAM Roles       │  │
│  │  + Boundaries│  │  + Boundaries│  │  + Boundaries    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              ABAC Tag-Based Access                   │    │
│  │    Environment=prod + Team=security = Access         │    │
│  │    Environment=prod + Team=dev = Denied              │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Enterprise IAM Capabilities Demonstrated

| Capability | Implementation | Industry Standard |
|-----------|---------------|-------------------|
| Least Privilege | Fine-grained IAM policies | CIS AWS Benchmark |
| Permission Boundaries | IAM boundary policies | AWS Well-Architected |
| Service Control Policies | Org-level guardrails | AWS Organizations |
| ABAC | Tag-based access control | NIST 800-207 Zero Trust |
| MFA Enforcement | Conditional IAM policies | PCI-DSS, SOX |
| IAM Audit | Python security scanner | CIS Benchmark 1.x |
| Privileged Access | Break-glass emergency role | PAM best practices |

## Repository Structure
```
zero-trust-iam-lab/
├── terraform/
│   ├── main.tf              # Core IAM resources
│   ├── variables.tf
│   ├── outputs.tf
│   └── scp.tf               # Service Control Policies
├── policies/
│   ├── least-privilege.json      # App developer policy
│   ├── security-analyst.json     # Security team policy
│   ├── permission-boundary.json  # Maximum permission cap
│   └── mfa-enforcement.json      # Deny without MFA
├── src/
│   └── iam_auditor.py       # IAM security scanner
└── docs/
    ├── zero-trust-concepts.md
    └── iam-best-practices.md
```

## Skills Demonstrated
- Zero Trust architecture design
- AWS IAM least privilege implementation
- Service Control Policies (SCPs)
- Permission boundaries
- Attribute-Based Access Control (ABAC)
- MFA enforcement policies
- Automated IAM security auditing
- Python AWS SDK (boto3) scripting
