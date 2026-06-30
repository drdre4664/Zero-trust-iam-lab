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

## Lessons Learned

### Zero Trust Architecture
- Zero Trust is not a product you buy — it is a security model built on three principles: **never trust, always verify**; **assume breach**; **least privilege access**. Every access decision must be explicitly verified regardless of whether the request comes from inside or outside the network
- Traditional security models trusted everything inside the network perimeter — Zero Trust eliminates that assumption entirely, which is why it is critical in modern environments where employees, contractors, and services access resources from anywhere
- **MFA is the single most impactful control** in a Zero Trust model — it ensures that even if credentials are compromised (stolen, brute-forced, phished), an attacker cannot authenticate without the second factor

### IAM Policies vs Service Control Policies (SCPs)
- **IAM policies** control what a specific user or role is allowed to do — they are applied at the identity level
- **SCPs** are applied at the AWS Organization level and act as a ceiling — even if an IAM policy grants a permission, an SCP can prevent it from being used entirely; an SCP cannot be overridden by any user or role including account administrators
- This layered approach means a misconfigured or compromised IAM role cannot exceed the guardrails set by the SCP — this is the "assume breach" principle in practice

### Permission Boundaries
- A permission boundary sets the **maximum permissions** a role can ever have — even if someone tries to attach a more permissive policy later, the boundary caps what is actually effective
- This prevents privilege escalation — an attacker who gains access to an IAM role cannot grant themselves additional permissions beyond what the boundary allows
- Permission boundaries are particularly important for roles that can create other roles — without them, a developer role could create an admin role and escalate their own access

### ABAC vs RBAC
- **RBAC (Role-Based Access Control)** grants access based on a user's role — e.g., all developers get the same access
- **ABAC (Attribute-Based Access Control)** grants access based on attributes (tags) on both the user and the resource — e.g., a developer tagged `Team=security` can access resources tagged `Environment=prod`, while a developer tagged `Team=dev` cannot
- ABAC is more granular and scalable than RBAC in large environments — you do not need to create a new role for every combination of access; you just tag resources and identities correctly

### Least Privilege in Practice
- Least privilege means giving an identity **only the permissions it needs to do its job and nothing more** — not read access to all S3 buckets when it only needs one specific bucket
- The blast radius of a compromised identity is directly proportional to how much access it has — least privilege limits how much damage an attacker can do with a stolen credential
- IAM auditing (automated with the Python scanner in this lab) is essential because permissions accumulate over time — roles get permissions added and rarely have them removed, leading to privilege creep
