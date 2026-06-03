#!/usr/bin/env python3
"""
IAM Security Auditor
Scans AWS IAM configuration for security misconfigurations and
policy violations based on CIS AWS Foundations Benchmark.
Produces a structured security report with findings and remediation.
"""

import json
import boto3
from datetime import datetime, timezone, timedelta


def get_iam_client():
    return boto3.client("iam")


def check_root_mfa(iam):
    print("  [*] Checking root account MFA...")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        if mfa_enabled:
            return {"status": "PASS", "finding": "Root account MFA is enabled"}
        else:
            return {
                "status": "FAIL",
                "severity": "CRITICAL",
                "finding": "Root account MFA is NOT enabled",
                "remediation": "Enable MFA on the root account immediately via AWS Console"
            }
    except Exception as e:
        return {"status": "ERROR", "finding": str(e)}


def check_users_without_mfa(iam):
    print("  [*] Checking users without MFA...")
    findings = []
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                findings.append(username)
        if findings:
            return {
                "status": "FAIL",
                "severity": "HIGH",
                "finding": f"Users without MFA: {findings}",
                "remediation": "Enforce MFA for all IAM users via IAM policy or AWS SSO"
            }
        return {"status": "PASS", "finding": "All users have MFA enabled"}
    except Exception as e:
        return {"status": "ERROR", "finding": str(e)}


def check_old_access_keys(iam):
    print("  [*] Checking for old access keys (>90 days)...")
    old_keys = []
    try:
        users = iam.list_users()["Users"]
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active":
                    age = datetime.now(timezone.utc) - key["CreateDate"]
                    if age.days > 90:
                        old_keys.append({
                            "user": username,
                            "key_id": key["AccessKeyId"][:8] + "****",
                            "age_days": age.days
                        })
        if old_keys:
            return {
                "status": "FAIL",
                "severity": "HIGH",
                "finding": f"Access keys older than 90 days: {old_keys}",
                "remediation": "Rotate access keys every 90 days. Consider using IAM roles instead."
            }
        return {"status": "PASS", "finding": "All access keys are less than 90 days old"}
    except Exception as e:
        return {"status": "ERROR", "finding": str(e)}


def check_users_with_admin_policy(iam):
    print("  [*] Checking for users with AdministratorAccess policy...")
    admin_users = []
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyName"] == "AdministratorAccess":
                    admin_users.append(username)
        if admin_users:
            return {
                "status": "FAIL",
                "severity": "HIGH",
                "finding": f"Users with AdministratorAccess: {admin_users}",
                "remediation": "Remove AdministratorAccess from users. Use roles with permission boundaries instead."
            }
        return {"status": "PASS", "finding": "No users have AdministratorAccess directly attached"}
    except Exception as e:
        return {"status": "ERROR", "finding": str(e)}


def check_password_policy(iam):
    print("  [*] Checking password policy...")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("Minimum password length should be 14+")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase characters not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        if not policy.get("MaxPasswordAge") or policy.get("MaxPasswordAge", 999) > 90:
            issues.append("Password expiry should be set to 90 days or less")
        if not policy.get("PasswordReusePrevention") or policy.get("PasswordReusePrevention", 0) < 24:
            issues.append("Password reuse prevention should be set to 24+")

        if issues:
            return {
                "status": "FAIL",
                "severity": "MEDIUM",
                "finding": f"Password policy issues: {issues}",
                "remediation": "Update password policy to meet CIS AWS Benchmark requirements"
            }
        return {"status": "PASS", "finding": "Password policy meets CIS requirements"}
    except iam.exceptions.NoSuchEntityException:
        return {
            "status": "FAIL",
            "severity": "HIGH",
            "finding": "No password policy configured",
            "remediation": "Configure a strong password policy immediately"
        }
    except Exception as e:
        return {"status": "ERROR", "finding": str(e)}


def generate_report(results):
    total = len(results)
    passed = sum(1 for r in results.values() if r.get("status") == "PASS")
    failed = sum(1 for r in results.values() if r.get("status") == "FAIL")
    critical = sum(1 for r in results.values() if r.get("severity") == "CRITICAL")
    high = sum(1 for r in results.values() if r.get("severity") == "HIGH")

    print("\n" + "=" * 60)
    print(" IAM SECURITY AUDIT REPORT")
    print(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)
    print(f"\n SUMMARY")
    print(f" Total Checks : {total}")
    print(f" Passed       : {passed}")
    print(f" Failed       : {failed}")
    print(f" Critical     : {critical}")
    print(f" High         : {high}")
    print()
    print(" FINDINGS")
    print("-" * 60)
    for check_name, result in results.items():
        status = result.get("status", "UNKNOWN")
        severity = result.get("severity", "")
        finding = result.get("finding", "")
        remediation = result.get("remediation", "")

        status_icon = "✓" if status == "PASS" else "✗" if status == "FAIL" else "?"
        severity_str = f"[{severity}]" if severity else ""

        print(f"\n {status_icon} {check_name} {severity_str}")
        print(f"   Finding     : {finding}")
        if remediation:
            print(f"   Remediation : {remediation}")

    print("\n" + "=" * 60)
    if failed == 0:
        print(" RESULT: PASSED — No IAM security issues found")
    else:
        print(f" RESULT: FAILED — {failed} issue(s) require attention")
    print("=" * 60 + "\n")


def run():
    print("\n" + "=" * 60)
    print(" IAM SECURITY AUDITOR — CIS AWS Foundations Benchmark")
    print("=" * 60 + "\n")
    print("[*] Connecting to AWS IAM...\n")
    print("[*] Running security checks...\n")

    iam = get_iam_client()

    results = {
        "1.5 Root Account MFA": check_root_mfa(iam),
        "1.10 Users Without MFA": check_users_without_mfa(iam),
        "1.14 Access Key Rotation": check_old_access_keys(iam),
        "1.16 No Admin Policies on Users": check_users_with_admin_policy(iam),
        "1.8 Password Policy": check_password_policy(iam),
    }

    generate_report(results)


if __name__ == "__main__":
    run()
