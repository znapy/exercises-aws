#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 1 - Static Web Hosting with Continuous Deployment.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-1/
"""

import json

from helpers import BASE_DIR, PROJECTNAME, REPO_NAME, IAM_USER, REGION, \
                    run, conf_get, conf_set, create_role, attach_policy, \
                    arns_user_policies, push_to_git


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
            raise ValueError(f"Error creating the repository: {result}")
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
            raise ValueError(f"Error creating the user: {result}")
        print(f"User {IAM_USER} has been created")
    else:
        print(f"User {IAM_USER} was created earlier")


def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AWSCodeCommitPowerUser",
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"]
    attached_policy_arns = arns_user_policies()
    new_policies = []
    for arn in arns:

        if arn not in attached_policy_arns:
            attach_policy(arn)
            new_policies.append(arn)

    if new_policies:
        print(f"User {IAM_USER} has been attached the policies {new_policies}")


def create_access_key():
    """Create an access key."""
    if conf_get("aws_access_key_id"):
        print(f"Access key for profile {PROJECTNAME} was created earlier")
        return

    result = run(["aws", "iam", "list-access-keys", "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError(f"Error listing the access keys: {result}")
    keys = json.loads(result.stdout.decode())["AccessKeyMetadata"]
    if len(keys):
        run(["aws", "iam", "delete-access-key", "--user-name", IAM_USER,
             "--access-key-id", keys[0]['AccessKeyId']])

    result = run(["aws", "iam", "create-access-key", "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError(f"Error creating the access key: {result}")
    access_key = json.loads(result.stdout.decode())["AccessKey"]

    tags = f"Key={access_key['AccessKeyId']},Value='created by {PROJECTNAME}'"
    result = run(["aws", "iam", "tag-user",
                  "--user-name", IAM_USER, "--tags", tags])
    if result.returncode != 0:
        raise ValueError("Error adding the description to access key:"
                         f" {result}")

    conf_set("aws_access_key_id", access_key['AccessKeyId'])
    conf_set("aws_secret_access_key", access_key['SecretAccessKey'])
    conf_set("region", REGION)

    print(f"Access key for profile {PROJECTNAME} has been created")


def create_https_git_credentials() -> None:
    """Create HTTPS git credentials."""
    result = run(["aws", "iam", "list-service-specific-credentials",
                  "--user-name", IAM_USER,
                  "--service-name", "codecommit.amazonaws.com"])
    if result.returncode != 0:
        raise ValueError(f"Error listing the codecommit credentials: {result}")

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
                f"Error reset the codecommit credentials: {result}")
        print(f"Codecommit https credentials for user {IAM_USER}"
              " have been reset")

    if not credentials:
        result = run(["aws", "iam", "create-service-specific-credential",
                      "--user-name", IAM_USER,
                      "--service-name", "codecommit.amazonaws.com"])
        if result.returncode != 0:
            raise ValueError(
                f"Error creating the codecommit credentials: {result}")
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
        raise ValueError(f"Error setting the credential helper: {result}")

    result = run(["git", "config", "--global", "credential.UseHttpPath",
                  "true"])
    if result.returncode != 0:
        raise ValueError(f"Error setting the UseHttpPath: {result}")
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
        raise ValueError(f"Error url protocol for 'git clone': {parts[0]}")
    if (BASE_DIR / REPO_NAME).exists():
        print(f"Repo directory {REPO_NAME} already exists")
        return
    result = run(["git", "clone", url])
    if result.returncode != 0:
        raise ValueError(f"Error cloning the repository: {result}")
    print(f"Repository {REPO_NAME} has been cloned")


def copy_website_content() -> None:
    """Copy the website content to a local repo."""
    repo_path = BASE_DIR / REPO_NAME
    if not repo_path.is_dir():
        raise ValueError(f"Directory {REPO_NAME} does not exist")

    if repo_path.joinpath("index.html").exists():
        print("Website content was copied earlier")
        return

    # SOURCE = \
    #     f"s3://wildrydes-{REGION}/WebApplication/1_StaticWebHosting/website"
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


def _get_ampify_app_id() -> str:
    """Get the Ampify app ID."""
    result = run(["aws", "amplify", "list-apps",
                  "--query", "apps[?name=='wildrydes-site'].appId"])
    if result.returncode != 0:
        raise ValueError(f"Error getting the list of amplify apps: {result}")
    values = json.loads(result.stdout.decode())
    if values:
        return values[0]
    return ""


def create_amplify(repo_url: str) -> None:
    """Create amplify app with data from repo."""
    if _get_ampify_app_id():
        print(f"Amplify app {REPO_NAME} was created earlier")
        return

    iam_service_role_arn = create_role(
        "amplifyconsole-backend-role",
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"amplify.amazonaws.com"},'
        '"Action":"sts:AssumeRole"}]}',
        "arn:aws:iam::aws:policy/AdministratorAccess-Amplify")
    result = run(["aws", "amplify", "create-app", "--name", REPO_NAME,
                  "--repository", repo_url, "--platform", "WEB",
                  "--iam-service-role-arn", iam_service_role_arn,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating the amplify app: {result}")
    app = json.loads(result.stdout.decode())["app"]

    result = run(["aws", "amplify", "create-branch", "--app-id", app["appId"],
                  "--branch-name", "master", "--stage", "PRODUCTION",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating the branch in amplify app: {result}")
    result = run(["aws", "amplify", "start-job", "--app-id", app["appId"],
                  "--branch-name", "master", "--job-type", "RELEASE",
                  "--profile", PROJECTNAME])
    print(f"Amplify app {REPO_NAME} has been created with address"
          f" https://master.{app['defaultDomain']}/ (wait during deployment)")


def modify_file() -> None:
    """Modify the wildryde-site/index.html file."""
    file_path = BASE_DIR / REPO_NAME / "index.html"
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
    # TODO: clean module 1
    # delete repo "wildrydes-site"
    # delete policies from user <IAM_USER>
    # delete access key from user <IAM_USER>
    # delete HTTPS git credentials from user <IAM_USER>
    # delete amplify_role_name = "amplifyconsole-backend-role"

    app_id = _get_ampify_app_id()
    if app_id:
        result = run(["aws", "amplify", "delete-app", "--app-id", app_id])
        if result.returncode != 0:
            raise ValueError(f"Error deleting the amplify app: {result}")
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


if __name__ == "__main__":
    main()
