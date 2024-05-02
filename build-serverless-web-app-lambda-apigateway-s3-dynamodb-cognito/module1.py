#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 1 - API calls according to the tutorial.

https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-1/
"""

import json
import subprocess
from pathlib import Path

PROJECTNAME = "aws-serverless-web-app"
REPO_NAME = "wildrydes-site"
IAM_USER = "exercise"

###########
# Helpers #

def run(command:str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(command, capture_output=True, cwd=cwd)

def conf_get(variable: str) -> str:
    """Get a value from the aws config file for IAM user."""
    result = run(["aws", "configure", "get", variable,
                  "--profile", PROJECTNAME])
    return result.stdout.decode().rstrip()

def conf_set(variable: str, value: str) -> None:
    """Set a value to the aws config file for IAM user."""
    result = run(["aws", "configure", "set", variable, value,
                  "--profile", PROJECTNAME])

def attach_policy(arn: str) -> None:
    """Attach a policy to the user."""
    result = run(["aws", "iam", "attach-user-policy", 
                  "--user-name", IAM_USER, "--policy-arn", arn])
    if result.returncode != 0:
        raise ValueError("Error attaching the user policy: {result}")
    print(f"User {IAM_USER} has been attached the policy {arn}")

################
# Script steps #

def create_repo() -> str:
    """Create a repository."""
    CODECOMMIT = ["aws", "codecommit"]
    result = run(CODECOMMIT + 
                 ["get-repository", "--repository-name", REPO_NAME])
    if not (result.returncode == 254 \
            and "RepositoryDoesNotExistException" in result.stderr.decode()):
        print(f"Repository {REPO_NAME} was created earlier")

    else:
        result = run(CODECOMMIT + 
                    ["create-repository", "--repository-name", REPO_NAME])
        if result.returncode != 0:
            raise ValueError("Error creating the repository: {result}")
        print(f"Repository {REPO_NAME} has been created")

    return json.loads(result.stdout.decode()
                          )["repositoryMetadata"]["cloneUrlHttp"]

def create_iam_user() -> None:
    """Create IAM user in AWS."""
    result = run(["aws", "iam", "get-user", "--user-name", IAM_USER])
    if result.returncode == 254 \
            and "NoSuchEntity" in result.stderr.decode():
        result = run(["aws", "iam", "create-user", "--user-name", IAM_USER])
        if result.returncode != 0:
            raise ValueError("Error creating the user: {result}")
        print(f"User {IAM_USER} has been created")
    else:
        print(f"User {IAM_USER} was created earlier")

def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AWSCodeCommitPowerUser",
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]

    result = run(["aws", "iam", "list-attached-user-policies", 
                  "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError("Error listing the user policies: {result}")
    
    policies = json.loads(result.stdout.decode())["AttachedPolicies"]
    attached_policy_arns = [policy["PolicyArn"] for policy in policies]

    new_policies = []
    for arn in arns:
        if arn not in attached_policy_arns:
            attach_policy(arn)
            new_policies.append(arn)

    if new_policies:
        print(f"User {IAM_USER} has been attached the policies {new_policies}")

def create_access_key():
    """Create an access key."""
    result = run(["aws", "configure", "list-profiles"])
    if result.returncode != 0:
        raise ValueError("Error listing the profiles: {result}")
    if PROJECTNAME in result.stdout.decode():
        print(f"Access key for profile {PROJECTNAME} was created earlier")
        return

    result = run(["aws", "iam", "create-access-key", "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError("Error creating the access key: {result}")
    access_key = json.loads(result.stdout.decode())["AccessKey"]

    tags = f"Key={access_key['AccessKeyId']},Value='created by {PROJECTNAME}'"
    result = run(["aws", "iam", "tag-user", 
                  "--user-name", IAM_USER, "--tags", tags])
    if result.returncode != 0:
        raise ValueError("Error adding the description to access key: {result}")

    conf_set("aws_access_key_id", access_key['AccessKeyId'])
    conf_set("aws_secret_access_key", access_key['SecretAccessKey'])
    
    print(f"Access key for profile {PROJECTNAME} has been created")

def create_HTTPS_git_credentials() -> None:
    """Create HTTPS git credentials."""
    result = run(["aws", "iam", "list-service-specific-credentials",
                  "--user-name", IAM_USER,
                  "--service-name", "codecommit.amazonaws.com"])
    if result.returncode != 0:
        raise ValueError("Error listing the codecommit credentials: {result}")
    
    https_service_username = conf_get("https-service-username")
    https_service_password = conf_get("https-service-password")
    if https_service_username and https_service_password:
        print("Codecommit https credentials were obtained from conf")
        return
    
    credentials = json.loads(result.stdout.decode()
                             )["ServiceSpecificCredentials"]
    if credentials:
        credential_id = credentials[0]['ServiceSpecificCredentialId']
        result = run(["aws", "iam", "reset-service-specific-credential",
                      "--user-name", IAM_USER,
                      "--service-specific-credential-id", credential_id])
        if result.returncode != 0:
            raise ValueError(
                "Error reset the codecommit credentials: {result}")
        print(f"Codecommit https credentials for user {IAM_USER}"
              " have been reset")
        
    if not credentials:
        result = run(["aws", "iam", "create-service-specific-credential",
                      "--user-name", IAM_USER,
                      "--service-name", "codecommit.amazonaws.com"])
        if result.returncode != 0:
            raise ValueError(
                "Error creating the codecommit credentials: {result}")
        print(f"Codecommit https credentials for user {IAM_USER}"
              " have been created")
        
    credential_new = json.loads(result.stdout.decode()
                                )["ServiceSpecificCredential"]
    conf_set("https-service-username", credential_new["ServiceUserName"])
    conf_set("https-service-password", credential_new["ServicePassword"])

def configure_git() -> None:
    """Configure git."""
    result = run(["git", "config", "--list"])
    if "aws codecommit credential" in result.stdout.decode():
        print("Git was configured earlier")
        return
    
    # TODO: in "git config" add a profile <PROJECTNAME> to run it as <IAM_USER>?
    result = run(["git", "config", "--global", "credential.helper",
                    "!aws codecommit credential-helper $@"])
    if result.returncode != 0:
        raise ValueError("Error setting the credential helper: {result}")

    result = run(["git", "config", "--global", "credential.UseHttpPath",
                  "true"])
    if result.returncode != 0:
        raise ValueError("Error setting the UseHttpPath: {result}")
    print("Git has been configured")

def git_clone(url: str) -> None:
    """Clone the repository."""
    # FIXME: Figure out why it works without user and password for https
    # https_service_username = conf_get("https-service-username")
    # https_service_password = conf_get("https-service-password")
    # url_with_credential = url.replace(
    #     "https://",
    #     f"https://{https_service_username}:{https_service_password}@")
    parts = url.split("/")
    if parts[0] != "https:":
        raise ValueError("Error url protocol for 'git clone': {parts[0]}")
    if Path(parts[-1]).exists():
        print(f"Repo directory {parts[-1]} already exists")
        return
    result = run(["git", "clone", url])
    if result.returncode != 0:
        raise ValueError("Error cloning the repository: {result}")
    print(f"Repository {parts[-1]} has been cloned")

def copy_website_content() -> None:
    """Copy the website content to a local repo."""
    repo_path = Path(REPO_NAME)
    if not repo_path.is_dir():
        raise ValueError(f"Directory {REPO_NAME} does not exist")
    
    if repo_path.joinpath("index.html").exists():
        print("Website content was copied earlier")
        return
    
    region = conf_get("region")
    SOURCE = \
        f"s3://wildrydes-{region}/WebApplication/1_StaticWebHosting/website"
    # result = run(["aws", "s3", "cp", SOURCE, "./", "--recursive",
    #               "--profile", PROJECTNAME], repo_path)
    """
    Following the tutorial leads to an error:
    > fatal error: An error occurred (AccessDenied) when calling
    > the ListObjectsV2 operation: Access Denied

    I tried to add "AmazonS3ReadOnlyAccess" policy to the user, but it
    does not work. The problem is commented here:
    https://github.com/aws-samples/aws-serverless-workshops/issues/292
    so I used another backet:
    > aws s3 cp s3://ttt-wildrydes/wildrydes-site ./ --recursive --profile aws-serverless-web-app

    delete ".git" directory from it and make archive "wildrydes-site.tar.gz".
    """
    # I don't want to install the tar module in python
    run(["tar", "-xf", "wildrydes-site.tar.gz"])
    print("Website content has been copied to the directory")

def push_to_git() -> None:
    """Push all fales to repository."""
    repo_path = Path(REPO_NAME)
    # I don't want to install the git module in python
    result = run(["git", "status"], repo_path)
    if result.returncode != 0:
        raise ValueError("Error getting the git status: {result}")
    if "nothing to commit, working tree clean" in result.stdout.decode():
        print("Nothing to commit and push")
        return

    run(["git", "add", "."], repo_path)
    run(["git", "commit", "-m", '"new files"'], repo_path)
    run(["git", "push"], repo_path)
    print("Website content have been pushed to the repository")

def clean() -> None:
    """Clean up in aws cloud what we have created in this module"""
    # TODO: delete repo "wildrydes-site"
    # TODO: delete access key from user <IAM_USER>
    # TODO: delete HTTPS git credentials from user <IAM_USER>
    pass


if __name__ == "__main__":
    url = create_repo()
    create_iam_user()
    add_policies()
    create_access_key()
    create_HTTPS_git_credentials()
    configure_git()
    git_clone(url)
    copy_website_content()
    push_to_git()
