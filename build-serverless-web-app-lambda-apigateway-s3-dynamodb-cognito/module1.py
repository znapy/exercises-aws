#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 1 - Static Web Hosting with Continuous Deployment.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-1/
"""

import json
import subprocess
from pathlib import Path
from time import sleep

# TODO: take PROJECTNAME from install.sh
PROJECTNAME = "aws-serverless-web-app"
REPO_NAME = "wildrydes-site"
IAM_USER = "exercise"
ACTIVE_TIME = 50*60  # 50 minutes in seconds - time before delete instances


###########
# Helpers #

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


def get_ampify_app_id() -> str:
    """Get the Ampify app ID."""
    result = run(["aws", "amplify", "list-apps",
                  "--query", "apps[?name=='wildrydes-site'].appId"])
    if result.returncode != 0:
        raise ValueError("Error getting the list of amplify apps: {result}")
    values = json.loads(result.stdout.decode())
    if values:
        return values[0]
    return ""


################
# Script steps #

def create_repo() -> str:
    """Create a repository."""
    CODECOMMIT = ["aws", "codecommit"]  # pylint: disable=invalid-name
    result = run(CODECOMMIT +
                 ["get-repository", "--repository-name", REPO_NAME])
    if not (result.returncode == 254
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
        raise ValueError("Error adding the description to access key:"
                         f" {result}")

    conf_set("aws_access_key_id", access_key['AccessKeyId'])
    conf_set("aws_secret_access_key", access_key['SecretAccessKey'])
    conf_set("region", conf_get("region", "default"))

    print(f"Access key for profile {PROJECTNAME} has been created")


def create_https_git_credentials() -> None:
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

    # TODO: in "git config" add a profile <PROJECTNAME> to run it as IAM USER?
    result = run(["git", "config", "--global", "credential.helper",
                  "!aws codecommit credential-helper $@"])
    if result.returncode != 0:
        raise ValueError("Error setting the credential helper: {result}")

    result = run(["git", "config", "--global", "credential.UseHttpPath",
                  "true"])
    if result.returncode != 0:
        raise ValueError("Error setting the UseHttpPath: {result}")
    print("Git has been configured")


def clone_git(url: str) -> None:
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

    # region = conf_get("region")
    # SOURCE = \
    #     f"s3://wildrydes-{region}/WebApplication/1_StaticWebHosting/website"
    # result = run(["aws", "s3", "cp", SOURCE, "./", "--recursive",
    #               "--profile", PROJECTNAME], repo_path)
    # pylint: disable=pointless-string-statement
    """
    Following the tutorial leads to an error:
    > fatal error: An error occurred (AccessDenied) when calling
    > the ListObjectsV2 operation: Access Denied

    I tried to add "AmazonS3ReadOnlyAccess" policy to the user, but it
    does not work. The problem is commented here:
    https://github.com/aws-samples/aws-serverless-workshops/issues/292
    so I used another backet:
    > aws s3 cp s3://ttt-wildrydes/wildrydes-site ./ --recursive --profile aws-serverless-web-app  # noqa: E501

    delete ".git" directory from it and make archive "wildrydes-site.tar.gz".
    """
    # I don't want to install the tar module in python
    run(["tar", "-xf", "wildrydes-site.tar.gz"])
    print("Website content has been copied to the directory")


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


def _create_amplify_role() -> str:
    """Create amplify role."""
    amplify_role_name = "amplifyconsole-backend-role"
    result = run(["aws", "iam", "get-role", "--role-name", amplify_role_name])
    if result.returncode == 254 \
            and "NoSuchEntity" in result.stderr.decode():

        result = run(["aws", "iam", "create-role", "--role-name",
                      amplify_role_name, "--assume-role-policy-document",
                      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                      '"Principal":{"Service":"amplify.amazonaws.com"},'
                      '"Action":"sts:AssumeRole"}]}'])
        if result.returncode != 0:
            raise ValueError("Error creating the role: {result}")
        print(f"Role {amplify_role_name} has been created")

    else:
        print(f"Role {amplify_role_name} was created earlier")

    arn_role = json.loads(result.stdout.decode())["Role"]["Arn"]
    arn_policy = "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"
    # no error if policy already attached
    attach_role_policy(amplify_role_name, arn_policy)

    return arn_role


def create_amplify(repo_url: str) -> None:
    """Create amplify app with data from repo."""
    if get_ampify_app_id():
        print(f"Amplify app {REPO_NAME} was created earlier")
        return

    iam_service_role_arn = _create_amplify_role()
    result = run(["aws", "amplify", "create-app", "--name", REPO_NAME,
                  "--repository", repo_url, "--platform", "WEB",
                  "--iam-service-role-arn", iam_service_role_arn])
    if result.returncode != 0:
        raise ValueError("Error creating the amplify app: {result}")
    app = json.loads(result.stdout.decode())["app"]

    result = run(["aws", "amplify", "create-branch", "--app-id", app.appId,
                  "--branch-name", "master", "--stage", "PRODUCTION"])
    if result.returncode != 0:
        raise ValueError("Error creating the branch in amplify app: {result}")
    print(f"Amplify app {REPO_NAME} has been created with address"
          f" https://master.{app.defaultDomain}/")


def modify_file() -> None:
    """Modify the index.html file."""
    file_path = Path(REPO_NAME) / "index.html"
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    title_new = "<title>Wild Rydes - Rydes of the Future!</title>"
    if title_new in content:
        print("Title of the index.html file was modified earlier")
        return

    title_original = "<title>Wild Rydes</title>"
    if title_original not in content:
        raise ValueError("Title of the index.html file was not found")
    content = content.replace(title_original, title_new)

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)
    print("Title of the index.html file has been modified")


def clean() -> None:
    """Clean up in aws cloud what we have created in this module"""
    # TODO: delete repo "wildrydes-site"
    # TODO: delete access key from user <IAM_USER>
    # TODO: delete HTTPS git credentials from user <IAM_USER>
    # TODO: delete amplify_role_name = "amplifyconsole-backend-role"

    app_id = get_ampify_app_id()
    if app_id:
        result = run(["aws", "amplify", "delete-app", "--app-id", app_id])
        if result.returncode != 0:
            raise ValueError("Error deleting the amplify app: {result}")
        print(f"Amplify app {REPO_NAME} has been deleted")


def main() -> None:
    """Main function."""
    url = create_repo()
    create_iam_user()
    add_policies()
    create_access_key()
    create_https_git_credentials()
    configure_git()
    clone_git(url)
    copy_website_content()
    push_to_git("new files")
    create_amplify(url)
    modify_file()
    push_to_git("updated title")

    sleep(ACTIVE_TIME)  # TODO: maybe wait for any key to be pressed?
    clean()


if __name__ == "__main__":
    main()
