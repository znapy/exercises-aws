#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 3 - Serverless Service Backend.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-3/
"""

import time
import json

from helpers import BASE_DIR, PROJECTNAME, REGION, ACCOUNT_ID, DYNAMODB_NAME, \
    LAMBDA_NAME, LAMBDA_ROLE_NAME, run, arns_user_policies, attach_policy, \
    create_role, delete_role, State


def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
            "arn:aws:iam::aws:policy/AWSLambda_FullAccess"]
    attached_policy_arns = arns_user_policies()
    for arn in arns:
        if arn not in attached_policy_arns:
            attach_policy(arn)


def _get_dynamodb_stream_arn(table_name: str) -> str:
    """Get DynamoDB stream ARN."""
    result = run(["aws", "dynamodb", "describe-table",
                  "--table-name", table_name,
                  "--query", "Table.LatestStreamArn",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error describe table: {result}")
    return result.stdout.decode().strip().replace('"', '')


def create_dynamodb_table() -> str:
    """Create 'Rides' - a DynamoDB table."""
    result = run(["aws", "dynamodb", "list-tables",
                  "--query", f"TableNames[?contains(@, '{DYNAMODB_NAME}')]",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error listing tables: {result}")
    if result.stdout.decode().strip().replace('"', '') != "[]":
        print(f"Table '{DYNAMODB_NAME}' already exists")
        return _get_dynamodb_stream_arn(DYNAMODB_NAME)

    result = run([
        "aws", "dynamodb", "create-table", "--table-name", DYNAMODB_NAME,
        "--attribute-definitions", "AttributeName=RideId,AttributeType=S",
        "--key-schema", "AttributeName=RideId,KeyType=HASH",
        "--provisioned-throughput", "ReadCapacityUnits=1,WriteCapacityUnits=1",
        "--stream-specification",
        "StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES",
        "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating table: {result.stderr.decode()}")

    while True:  # wait until table is created
        time.sleep(5)
        result = run(["aws", "dynamodb", "describe-table",
                      "--table-name", DYNAMODB_NAME,
                      "--query", "Table.TableStatus",
                      "--profile", PROJECTNAME])
        if result.returncode != 0:
            raise ValueError(f"Error check table status: {result}")
        status = result.stdout.decode().strip().replace('"', "")
        if status != "CREATING":
            break
    if status != "ACTIVE":
        raise ValueError(f"Error creating table, status: '{status}'")

    print(f"Table '{DYNAMODB_NAME}' has been created")
    return _get_dynamodb_stream_arn(DYNAMODB_NAME)


def create_inlile_policy_in_role(role_name: str, policy_name: str,
                                 document: str) -> None:
    """Create inline policy in the role."""
    result = run(["aws", "iam", "list-role-policies", "--role-name", role_name,
                  "--query", f"PolicyNames[?contains(@, '{policy_name}')]",
                  "--profile", PROJECTNAME])
    if result.returncode == 0 and \
            result.stdout.decode().strip().replace('"', '') != "[]":
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
    # wait 5 seconds for the policy to be applied
    time.sleep(5)
    return


def create_lambda_function(role_arn: str) -> str:
    """Create lambda function."""
    result = run(["aws", "lambda", "list-functions",
                  "--query", f"Functions[?FunctionName=='{LAMBDA_NAME}']."
                  "FunctionName",
                  "--profile", PROJECTNAME])
    if result.returncode == 0 and result.stdout.decode().strip() != "[]":
        print(f"Lambda function {LAMBDA_NAME} already exists")
        return f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{LAMBDA_NAME}"

    result = run(["aws", "lambda", "create-function",
                  "--function-name", LAMBDA_NAME,
                  "--runtime", "nodejs16.x",
                  "--role", role_arn,
                  "--handler", "requestUnicorn.handler",
                  "--zip-file", "fileb://./lambda.zip",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating lambda function: {result}")
    print(f"Lambda function {LAMBDA_NAME} has been created")
    return json.loads(result.stdout.decode())["FunctionArn"]


def create_test_event() -> None:
    """Create test event."""
    response_file = BASE_DIR / "response.json"
    result = run(["aws", "lambda", "invoke",
                  "--function-name", LAMBDA_NAME,
                  "--cli-binary-format", "raw-in-base64-out",
                  "--payload", "file://./TestRequestEvent.js",
                  "--profile", PROJECTNAME, response_file])
    if result.returncode != 0:
        raise ValueError(f"Error creating event: {result}")
    if not response_file.is_file():
        raise ValueError(f"Error creating file {response_file}")

    with open(response_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    if data["statusCode"] != 201:
        raise ValueError(f"Error in: {response_file}")
    response_file.unlink()
    print("Test event has been checked:", data["body"])


def clean(state: State) -> None:  # pylint: disable=unused-argument
    """Clean up in aws cloud what we have created in this module"""
    result = run(["aws", "lambda", "delete-function",
                  "--function-name", LAMBDA_NAME, "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating event: {result}")
    print(f"Lambda function {LAMBDA_NAME} has been deleted")

    # need another rights for "--profile", PROJECTNAME - so delete as admin
    result = run(["aws", "logs", "delete-log-group",
                  "--log-group-name", f"/aws/lambda/{LAMBDA_NAME}"])
    if result.returncode != 0:
        raise ValueError(f"Error creating event: {result}")
    print(f"Log group for lambda {LAMBDA_NAME} has been deleted")

    result = run(["aws", "dynamodb", "delete-table",
                  "--table-name", DYNAMODB_NAME, "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating event: {result}")
    print(f"DynamoDB table {DYNAMODB_NAME} has been deleted")

    delete_role(LAMBDA_ROLE_NAME)


def main(state: State) -> None:  # pylint: disable=unused-argument
    """Main function."""
    stream_arn = create_dynamodb_table()
    table_arn = stream_arn.split("/stream/")[0]
    iam_service_role_arn = create_role(
        LAMBDA_ROLE_NAME,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"lambda.amazonaws.com"},'
        '"Action":"sts:AssumeRole"}]}',
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    create_inlile_policy_in_role(
        LAMBDA_ROLE_NAME,
        "DynamoDBWriteAccess",
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":'
        f'["dynamodb:PutItem"],"Resource":"{table_arn}"' + '}]}')
    create_lambda_function(iam_service_role_arn)
    create_test_event()
