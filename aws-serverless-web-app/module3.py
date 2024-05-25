#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 3 - Serverless Service Backend.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-3/
"""

import time
import json

from helpers import BASE_DIR, PROJECTNAME, REPO_NAME, IAM_USER_MAIL, REGION, \
                    ACCOUNT_ID, run, arns_user_policies, attach_policy, \
                    create_role
# import module1
# import module2

def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess"]
    attached_policy_arns = arns_user_policies()
    for arn in arns:
        if arn not in attached_policy_arns:
            attach_policy(arn)


def create_dynamodb_table() -> str:
    """Create 'Rides' - a DynamoDB table."""
    table_name = "Rides"
    table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/{table_name}"

    result = run(["aws", "dynamodb", "list-tables",
                  "--query", f"TableNames[?contains(@, '{table_name}')]",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error listing tables: {result}")
    if result.stdout.decode().strip() != "[]":
        print(f"Table '{table_name}' already exists")
        return table_arn

    result = run([
        "aws", "dynamodb", "create-table", "--table-name", table_name,
        "--attribute-definitions", "AttributeName=RideId,AttributeType=S",
        "--key-schema", "AttributeName=RideId,KeyType=HASH",
        "--provisioned-throughput", "ReadCapacityUnits=1,WriteCapacityUnits=1",
        "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating table: {result.stderr.decode()}")

    while True:  # wait until table is created
        time.sleep(5)
        result = run(["aws", "dynamodb", "describe-table",
                      "--table-name", table_name,
                      "--query", "Table.TableStatus",
                      "--profile", PROJECTNAME])
        if result.returncode != 0:
            raise ValueError(f"Error check table status: {result}")
        status = result.stdout.decode().strip()
        if status != "CREATING":
            break
    if status != "ACTIVE":
        raise ValueError(f"Error creating table, status: {status}")

    print(f"Table '{table_name}' has been created")
    return table_arn


# def create_policy(name: str, document: str) -> str:
#     """Create policy."""
#     result = run(["aws", "iam", "list-policies", "--max-items", "1",
#         "--query", f"Policies[?PolicyName=='{name}'].Arn",
#         "--profile", PROJECTNAME])
#     if result.returncode == 0 and result.stdout.decode().strip() != "[]":
#         print(f"Policy {name} already exists")
#         return  json.loads(result.stdout.decode())[0]

#     result = run(["aws", "iam", "create-policy",
#                   "--policy-name", name,
#                   "--policy-document", document,
#                   "--profile", PROJECTNAME])
#     if result.returncode != 0:
#         raise ValueError(f"Error creating policy: {result}")
#     print(f"Policy {name} has been created")
#     return json.loads(result.stdout.decode())["Policy"]["Arn"]


def create_inlile_policy_in_role(role_name: str, policy_name: str,
                                 document: str) -> None:
    """Create inline policy in the role."""
    result = run(["aws", "iam", "list-role-policies", "--role-name", role_name,
                  "--query", f"PolicyNames[?contains(@, '{policy_name}')]",
                  "--profile", PROJECTNAME])
    if result.returncode == 0 and result.stdout.decode().strip() != "[]":
        print(f"Inline policy {policy_name} already exists")
        return

    result = run(["aws", "iam", "put-role-policy",
                  "--role-name", role_name,
                  "--policy-name", policy_name,
                  "--policy-document", document,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating inline policy: {result}")
    print(f"Inline policy {policy_name} has been created",
          result.stdout.decode())
    return


def clean() -> None:
    """Clean up in aws cloud what we have created in this module"""
    # TODO: clean module 3
    # delete DynamoDB table
    # Delete role


def main() -> None:
    """Main function."""
    # module1.main()
    # module2.main()
    add_policies()
    table_arn = create_dynamodb_table()
    role_name = "WildRydesLambda"
    iam_service_role_arn = create_role(
        role_name,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"lambda.amazonaws.com"},'
        '"Action":"sts:AssumeRole"}]}',
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    create_inlile_policy_in_role(
        role_name,
        "DynamoDBWriteAccess",
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":'
        f'["dynamodb:PutItem"],"Resource":"{table_arn}"' + '}]}')

    #input("press Enter to delete apps (amplify)"
    #      " or Ctrl+C to leave them running...")
    #clean()
    #module1.clean()


if __name__ == "__main__":
    main()
