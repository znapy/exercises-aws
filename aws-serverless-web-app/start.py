#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exercise modules with 5th part - cleaning.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-5/
"""

import json

from helpers import IAM_USER, PROJECTNAME, REGION, run, conf_get, conf_set, \
    State
import module1
import module2
import module3
import module4


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


def _delete_access_keys() -> None:
    """Delete access keys."""
    result = run(["aws", "iam", "list-access-keys", "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError(f"Error listing the access keys: {result}")
    keys = json.loads(result.stdout.decode())["AccessKeyMetadata"]
    if len(keys):
        run(["aws", "iam", "delete-access-key", "--user-name", IAM_USER,
             "--access-key-id", keys[0]['AccessKeyId']])


def create_access_key() -> None:
    """Create an access key."""
    if conf_get("aws_access_key_id"):
        print(f"Access key for profile {PROJECTNAME} was created earlier")
        return

    _delete_access_keys()

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


def _delete_iam_user() -> None:
    """Delete IAM user."""
    result = run(["aws", "iam", "get-user", "--user-name", IAM_USER])
    if result.returncode == 254 \
            and "NoSuchEntity" in result.stderr.decode():
        print(f"User {IAM_USER} was deleted earlier")
        return

    # get login profile, if it exist - delete
    result = run(["aws", "iam", "get-login-profile", "--user-name", IAM_USER])
    if result.returncode == 0:
        result = run(["aws", "iam", "delete-login-profile",
                      "--user-name", IAM_USER])
        if result.returncode != 0:
            raise ValueError(f"Error deleting the login profile: {result}")

    result = run(["aws", "iam", "list-attached-user-policies",
                  "--user-name", IAM_USER])
    if result.returncode == 0:
        for policy in json.loads(result.stdout.decode())["AttachedPolicies"]:
            result = run(["aws", "iam", "detach-user-policy",
                          "--user-name", IAM_USER,
                          "--policy-arn", policy["PolicyArn"]])
            if result.returncode != 0:
                raise ValueError(
                    f"Error detaching the user policy: {result}")

    result = run(["aws", "iam", "list-groups-for-user",
                  "--user-name", IAM_USER])
    if result.returncode == 0:
        for group in json.loads(result.stdout.decode())["Groups"]:
            result = run(["aws", "iam", "remove-user-from-group",
                          "--user-name", IAM_USER,
                          "--group-name", group["GroupName"]])
            if result.returncode != 0:
                raise ValueError(
                    f"Error removing the user from the group: {result}")

    result = run(["aws", "iam", "list-signing-certificates",
                  "--user-name", IAM_USER])
    if result.returncode == 0:
        for cert in json.loads(result.stdout.decode())["Certificates"]:
            result = run(["aws", "iam", "delete-signing-certificate",
                          "--user-name", IAM_USER,
                          "--certificate-id", cert["CertificateId"]])
            if result.returncode != 0:
                raise ValueError("Error deleting the signing"
                                 f" certificate: {result}")

    result = run(["aws", "iam", "list-ssh-public-keys",
                  "--user-name", IAM_USER])
    if result.returncode == 0:
        for key in json.loads(result.stdout.decode())["SSHPublicKeys"]:
            result = run(["aws", "iam", "delete-ssh-public-key",
                          "--user-name", IAM_USER,
                          "--ssh-public-key-id", key["SSHPublicKeyId"]])
            if result.returncode != 0:
                raise ValueError(f"Error deleting the SSH pub-key: {result}")

    result = run(["aws", "iam", "list-service-specific-credentials",
                  "--user-name", IAM_USER])
    if result.returncode == 0:
        for cred in json.loads(result.stdout.decode()
                               )["ServiceSpecificCredentials"]:
            result = run(["aws", "iam", "delete-service-specific-credential",
                          "--user-name", IAM_USER,
                          "--service-specific-credential-id",
                          cred["ServiceSpecificCredentialId"]])
            if result.returncode != 0:
                raise ValueError(f"Error deleting the ss-credential: {result}")

    result = run(["aws", "iam", "delete-user", "--user-name", IAM_USER])
    if result.returncode != 0:
        raise ValueError(f"Error deleting the user: {result}")


def main(state: State) -> None:
    """Main function."""
    # create IAM user and set first policies
    create_iam_user()
    create_access_key()

    # apply the policies immediately, so as not to expect them
    #   to be applied later
    module1.add_policies()
    module2.add_policies()
    module3.add_policies()
    module4.add_policies()

    module1.main(state)
    module2.main(state)
    module3.main(state)
    module4.main(state)

    input("press Enter to delete user and apps (Ampify, lambda, dynamoDB, etc)"
          " or Ctrl+C to leave them running...")

    module4.clean(state)
    module3.clean(state)
    module2.clean(state)
    module1.clean(state)

    _delete_access_keys()
    print(f"Access keys for user {IAM_USER} have been deleted")

    _delete_iam_user()
    print(f"User {IAM_USER} has been deleted")


if __name__ == "__main__":
    main(State())
