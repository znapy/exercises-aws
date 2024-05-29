#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 4 - Deploy a RESTful API.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-4/
"""

import json
import re

from helpers import BASE_DIR, PROJECTNAME, REPO_NAME, REGION,  ACCOUNT_ID, \
    LAMBDA_NAME, GATEWAY_API_NAME, run, arns_user_policies, attach_policy, \
    push_to_git, State


def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator"]
    attached_policy_arns = arns_user_policies()
    for arn in arns:
        if arn not in attached_policy_arns:
            attach_policy(arn)


def create_gateway_api() -> str:
    """Create REST API in Amazon API Gateway."""
    result = run(["aws", "apigateway", "get-rest-apis",
                  "--query", f"items[?name=='{GATEWAY_API_NAME}'].id",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting API: {result}")
    result_json = json.loads(result.stdout.decode())
    if result_json != []:
        print(f"API '{GATEWAY_API_NAME}' already exists")
        return result_json[0]

    result = run(["aws", "apigateway", "create-rest-api",
                  "--name", GATEWAY_API_NAME,
                  "--endpoint-configuration", "types=EDGE",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating API: {result}")
    api_id = json.loads(result.stdout.decode())["id"]
    print(f"API '{GATEWAY_API_NAME}' has been created with id {api_id}")
    return api_id


def create_uthorizer(api_id: str, authorizer_name: str, user_pool_id: str
                     ) -> str:
    """Create authorizer."""
    result = run(["aws", "apigateway", "get-authorizers",
                  "--rest-api-id", api_id,
                  "--query", f"items[?name=='{authorizer_name}'].id",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting authorizer: {result}")
    result_json = json.loads(result.stdout.decode())
    if result_json != []:
        print(f"Authorizer '{authorizer_name}' already exists")
        return result_json[0]

    userpool_arn = f"arn:aws:cognito-idp:{REGION}:{ACCOUNT_ID}" \
                   f":userpool/{user_pool_id}"
    result = run(["aws", "apigateway", "create-authorizer",
                  "--rest-api-id", api_id,
                  "--name", authorizer_name,
                  "--type", "COGNITO_USER_POOLS",
                  "--provider-arns", userpool_arn,
                  "--identity-source", "method.request.header.Authorization",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating authorizer: {result}")
    return json.loads(result.stdout.decode())["id"]


def test_authorizer(api_id: str, authorizer_id: str, auth_token: str) -> None:
    """Test authorizer."""
    result = run(["aws", "apigateway", "test-invoke-authorizer",
                  "--rest-api-id", api_id,
                  "--authorizer-id", authorizer_id,
                  "--headers", json.dumps({"Authorization": auth_token}),
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error testing authorizer: {result}")
    result_json = json.loads(result.stdout.decode())
    if result_json["clientStatus"] != 0:
        raise ValueError(
            f"Error clientStatus in testing authorizer: {result_json}")
    print(f"Authorizer '{authorizer_id}' has been tested")


def create_resource(api_id: str, path_part: str) -> str:
    """Create resource."""
    result = run(["aws", "apigateway", "get-resources",
                  "--rest-api-id", api_id,
                  "--query", "items",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting resource: {result}")
    ids = {element["path"][1:]: element["id"]
           for element in json.loads(result.stdout.decode())}

    if ids.get(path_part) is not None:
        print(f"Resource '{path_part}' already exists")
        return ids[path_part]

    result = run(["aws", "apigateway", "create-resource",
                  "--rest-api-id", api_id,
                  "--parent-id", ids[""],  # root resource
                  "--path-part", path_part,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating resource: {result}")
    print(f"Resource '{path_part}' has been created")
    resource_id = json.loads(result.stdout.decode())["id"]

    # How to create CORS method and realy need it?
    # result = run(["aws", "apigateway", "put-method",
    #               "--rest-api-id", api_id,
    #               "--resource-id", resource_id,
    #               "--http-method", "OPTIONS",
    #               "--authorization-type", "NONE",
    #               "--profile", PROJECTNAME])
    # print(f"Resource '{path_part}' has been updated for CORS", result)

    return resource_id


def create_method(api_id: str, resource_id: str, authorizer_id: str,
                  lambda_name: str) -> None:
    """Create method for lambda function."""
    result = run(["aws", "apigateway", "get-integration",
                  "--rest-api-id", api_id,
                  "--resource-id", resource_id,
                  "--http-method", "POST",
                  "--profile", PROJECTNAME])
    if result.returncode == 0:
        print(f"Method for lambda '{lambda_name}' already exists")
        return

    result = run(["aws", "apigateway", "put-method",
                  "--rest-api-id", api_id,
                  "--resource-id", resource_id,
                  "--http-method", "POST",
                  "--authorization-type", "COGNITO_USER_POOLS",
                  "--authorizer-id", authorizer_id,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating method: {result}")

    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/" \
          f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{lambda_name}" \
          "/invocations"
    result = run(["aws", "apigateway", "put-integration",
                  "--rest-api-id", api_id,
                  "--resource-id", resource_id,
                  "--http-method", "POST",
                  "--type", "AWS_PROXY",
                  "--integration-http-method", "POST",
                  "--uri", uri, "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error put integration to method: {result}")

    print(f"Method for lambda '{lambda_name}' has been created")


def add_permission_to_lambda_for_gateway(lambda_name: str, api_id: str,
                                         resource_ride_id: str) -> None:
    """Add permission for lambda function to invoke gateway."""
    source_arn = f"arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:{api_id}/POST/" +\
                 resource_ride_id
    result = run
    result = run(["aws", "lambda", "add-permission",
                  "--function-name", lambda_name,
                  "--statement-id", "AllowAPIGatewayInvoke",
                  "--action", "lambda:InvokeFunction",
                  "--principal", "apigateway.amazonaws.com",
                  "--source-arn", source_arn, "--profile", PROJECTNAME])
    if "The statement id (AllowAPIGatewayInvoke) provided already exists." \
            in result.stderr.decode():
        print("Permission for gateway has already been added")
        return
    if result.returncode != 0:
        raise ValueError(f"Error adding permission for gateway: {result}")
    print("Permission for gateway has been added")


def deploy_api(api_id: str) -> str:
    """Deploy api."""
    stage_name = "prod"
    invoke_url = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/" + \
                 stage_name
    result = run(["aws", "apigateway", "get-deployments",
                  "--rest-api-id", api_id,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting deployments: {result}")
    if json.loads(result.stdout.decode())["items"]:
        print(f"Api {invoke_url} has already been deployed")
        return invoke_url
    result = run(["aws", "apigateway", "create-deployment",
                  "--rest-api-id", api_id,
                  "--stage-name", stage_name,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error deploying api: {result}")
    print(f"Api {invoke_url} has been deployed")
    return invoke_url


def update_website(invoke_url: str) -> None:
    """Insert invokeUrl to website config."""
    file_path = BASE_DIR / REPO_NAME / "js" / "config.js"
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    correct = f"invokeUrl: '{invoke_url}'"
    if correct in content:
        print("invokeUrl in the js/config.js file was modified earlier")
        return

    message = "invokeUrl in the js/config.js has been setted"
    if "invokeUrl: ''" in content:
        content = content.replace("invokeUrl: ''", correct)
    else:
        old_url = re.search('invokeUrl: \'(.*)\'', content)
        content = content.replace(old_url, invoke_url)
        message = "invokeUrl in the js/config.js has been modified from" + \
                  f" {old_url} to {correct}"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)
    print(message)


def change_arcgis_version() -> None:
    """Change version from 4.3 to 4.6."""
    file_path = BASE_DIR / REPO_NAME / "ride.html"
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    content_new = content.replace("https://js.arcgis.com/4.3/",
                                  "https://js.arcgis.com/4.6/")
    if content_new == content:
        print("Arcgis version has already been changed")
        return
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content_new)
    print("Arcgis version has been changed")


def clean(state: State) -> None:
    """Clean up in aws cloud what we have created in this module"""
    result = run(["aws", "apigateway", "delete-rest-api",
                  "--rest-api-id", state.api_id, "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error deleting api: {result}")
    print(f"Api {state.api_id} has been deleted")


def main(state: State) -> None:
    """Main function."""
    state.api_id = create_gateway_api()

    authorizer_name = "WildRydes"
    authorizer_id = create_uthorizer(state.api_id, authorizer_name,
                                     state.user_pool_id)
    test_authorizer(state.api_id, authorizer_id, state.auth_token)

    resource_ride_id = create_resource(state.api_id, "ride")
    create_method(state.api_id, resource_ride_id, authorizer_id, LAMBDA_NAME)
    add_permission_to_lambda_for_gateway(
        LAMBDA_NAME, state.api_id, resource_ride_id)
    invoke_url = deploy_api(state.api_id)
    update_website(invoke_url)
    push_to_git("new_configuration")

    input(f"Check site {state.site_url}signin.html before change version"
          " (wait during deployment). There is problem with login - register"
          " a new user better. Press Enter to continue")

    change_arcgis_version()
    push_to_git("change arcgis version")
