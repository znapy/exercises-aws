#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common functions for calling from modules.
"""

from configparser import ConfigParser
import json
import subprocess
from pathlib import Path

config = ConfigParser()
config.read("/root/.aws/config")

PROJECTNAME = config.sections()[1].replace("profile ", "")
IAM_USER = config[f"profile {PROJECTNAME}"]["IAM_USER"]
IAM_USER_MAIL = config[f"profile {PROJECTNAME}"]["IAM_USER_MAIL"]
REGION = config[f"profile {PROJECTNAME}"]["REGION"]
ACCOUNT_ID = subprocess.run(
    ["aws", "sts", "get-caller-identity", "--query", "Account",
     "--output", "text"], capture_output=True, check=True)\
        .stdout.decode().rstrip()

REPO_NAME = "wildrydes-site"
ACTIVE_TIME = 50*60  # 50 minutes in seconds - time before delete instances


def run(command: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(command, capture_output=True, cwd=cwd, check=False)


def conf_get(variable: str, profile=PROJECTNAME) -> str:
    """Get a value from the aws config file for IAM user."""
    result = run(["aws", "configure", "get", variable,
                  "--profile", profile])
    return result.stdout.decode().rstrip()


def conf_set(variable: str, value: str) -> None:
    """Set a value to the aws config file for IAM user."""
    result = run(["aws", "configure", "set", variable, value,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError("Error setting the variable: {result}")


def arns_user_policies() -> list:
    """Get attached user policies."""
    command = ["aws", "iam", "list-attached-user-policies",
               "--user-name", IAM_USER]
    result = subprocess.run(command, capture_output=True, check=True)
    policies = json.loads(result.stdout.decode())["AttachedPolicies"]
    return [policy["PolicyArn"] for policy in policies]


def attach_policy(arn: str) -> None:
    """Attach a policy to the user."""
    result = run(["aws", "iam", "attach-user-policy",
                  "--user-name", IAM_USER, "--policy-arn", arn])
    if result.returncode != 0:
        raise ValueError("Error attaching the user policy: {result}")
    print(f"User {IAM_USER} has been attached the policy {arn}")


def attach_role_policy(role: str, arn: str) -> None:
    """Attach a policy to the role."""
    result = run(["aws", "iam", "attach-role-policy",
                  "--role-name", role, "--policy-arn", arn])
    if result.returncode != 0:
        raise ValueError("Error attaching the role policy: {result}")
    print(f"Role {role} has been attached the policy {arn}")


def push_to_git(message: str) -> None:
    """Push all files to repository."""
    repo_path = Path(REPO_NAME)
    # I don't want to install the git module in python
    result = run(["git", "status", "--porcelain"], repo_path)
    if result.returncode != 0:
        raise ValueError("Error getting the git status: {result}")
    if not result.stdout.decode():
        print(f"Nothing to commit and push with message '{message}'")
        return

    run(["git", "add", "."], repo_path)
    run(["git", "commit", "-m", f'"{message}"'], repo_path)
    run(["git", "push"], repo_path)
    print("Website content have been pushed to the repository with message"
          f" '{message}'")
