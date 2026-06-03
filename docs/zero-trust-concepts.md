# Zero Trust Architecture Concepts

## What is Zero Trust?
Zero Trust is a security model based on the principle of "never trust, always verify."
It assumes that threats exist both inside and outside the network — no user, device,
or service is trusted by default, even if they are inside the corporate network.

## Core Principles

### 1. Never Trust, Always Verify
Every access request must be authenticated and authorized regardless of location.
- Implemented via: MFA enforcement, conditional access policies

### 2. Least Privilege Access
Users and services get only the minimum permissions needed to do their job.
- Implemented via: Fine-grained IAM policies, ABAC, permission boundaries

### 3. Assume Breach
Design security controls as if an attacker is already inside.
- Implemented via: SCPs that prevent privilege escalation even for admins

### 4. Verify Explicitly
Use all available signals to make access decisions.
- Implemented via: ABAC using resource tags, MFA age conditions

### 5. Limit Blast Radius
If a credential is compromised, limit what the attacker can do.
- Implemented via: Permission boundaries, short-lived credentials

---

## AWS Zero Trust Implementation

### Service Control Policies (SCPs)
SCPs are the highest-level control in AWS. They apply to ALL principals in an
account — including root and admin users. Even if someone has AdministratorAccess,
an SCP can block specific actions.

**Use case:** Prevent disabling CloudTrail, restrict to approved regions.

### Permission Boundaries
A permission boundary sets the maximum permissions a role or user can have.
Even if a policy grants more permissions, the boundary caps what is actually allowed.

**Use case:** Prevent developers from escalating their own privileges.

### Attribute-Based Access Control (ABAC)
Instead of managing hundreds of static policies, ABAC grants access based on tags.
A developer with tag `Team=payments` can only access resources tagged `Team=payments`.

**Use case:** Dynamic, scalable access control without policy explosion.

### Break-Glass Role
An emergency role with elevated permissions, protected by:
- MFA required to assume
- MFA must be less than 1 hour old
- Permission boundary still applies
- All actions logged to CloudTrail

**Use case:** Emergency production access during an incident.

---

## CIS AWS Foundations Benchmark Controls
This lab implements checks for:
- 1.5: Ensure MFA is enabled for root account
- 1.8: Ensure IAM password policy requires strong passwords
- 1.10: Ensure MFA is enabled for all IAM users with console access
- 1.14: Ensure access keys are rotated every 90 days
- 1.16: Ensure IAM policies are attached only to groups or roles
