#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module 2 - manage users.

API calls according to the tutorial:
https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/module-2/
"""


import base64
import binascii
import datetime
import hashlib
import hmac
import os
import json
import secrets
import string

from helpers import BASE_DIR, PROJECTNAME, REPO_NAME, IAM_USER_MAIL, REGION, \
                    ACCOUNT_ID, run, arns_user_policies, attach_policy, \
                    push_to_git, State


def add_policies() -> None:
    """Add module policies to the user."""
    arns = ["arn:aws:iam::aws:policy/AmazonSESFullAccess",
            "arn:aws:iam::aws:policy/AmazonCognitoPowerUser",
            # for configure cognito-idp
            "arn:aws:iam::aws:policy/IAMFullAccess"
            ]
    attached_policy_arns = arns_user_policies()
    for arn in arns:
        if arn not in attached_policy_arns:
            attach_policy(arn)


def create_email_identity() -> None:
    """Create email identity."""
    result = run(["aws", "sesv2", "get-email-identity",
                  "--email-identity", IAM_USER_MAIL,
                  "--profile", PROJECTNAME])
    if result.returncode == 0:
        print(f"Email identity {IAM_USER_MAIL} already exists."
              " You can change the identity manualy by url: "
              f"https://{REGION}.console.aws.amazon.com/ses/")
        return
    else:
        result = run(["aws", "sesv2", "create-email-identity",
                      "--email-identity", IAM_USER_MAIL,
                      "--profile", PROJECTNAME])
        if result.returncode != 0:
            raise ValueError(f"Error creating email identity: {result}")
    print(f"Email identity {IAM_USER_MAIL} has been created")
    input("CONFIRM EMAIL ADDRESS! and press Enter to continue...")


def _user_pool_policy_document(email_arn: str) -> str:
    """Create user pool policy document."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cognito-idp.amazonaws.com"
                },
                "Action": ["ses:SendRawEmail", "ses:SendEmail"],
                "Resource": email_arn
            }
        ]}, separators=(', ', ':'))


def _put_identity_policy(identity: str, policy_name: str, document: str
                         ) -> None:
    """Put identity policy."""
    result = run(["aws", "ses", "put-identity-policy",
                  "--identity", identity,
                  "--policy-name", policy_name,
                  "--policy", document,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error putting policy to identity: {result}")
    print(f"Policy {policy_name} has been putted to {identity}")


def create_user_pool() -> str:
    """Create user pool."""
    pool_name = "WildRydes"
    result = run(["aws", "cognito-idp", "list-user-pools",
                  "--max-results", "1",
                  "--query", f"UserPools[?Name=='{pool_name}'].Id",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting cognito user pools: {result}")

    ids = json.loads(result.stdout.decode())
    if ids:
        print("User pool already exists")
        return ids[0]

    email_arn = f"arn:aws:ses:{REGION}:{ACCOUNT_ID}:identity/{IAM_USER_MAIL}"
    _put_identity_policy(email_arn, f"{PROJECTNAME}-cognito",
                         _user_pool_policy_document(email_arn))
    result = run(["aws", "cognito-idp", "create-user-pool",
                  "--pool-name", pool_name,
                  # there is username in exercise ("preferred_username"),
                  # but site login form is with email ("email"), both variants
                  # don't work from XXX.amplifyapp.com/signin.html - so use
                  # already logined session via regestation.
                  "--alias-attributes", "email",
                  "--mfa-configuration", "OFF",
                  f"--email-configuration=SourceArn='{email_arn}'",
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating user pool: {result}")
    user_pool_id = json.loads(result.stdout.decode())["UserPool"]["Id"]
    print(f"User pool {user_pool_id} has been created")
    return user_pool_id


def create_user_pool_client(user_pool_id: str) -> str:
    """Create user pool client."""
    client_name = "WildRydesWebApp"
    query = f"UserPoolClients[?ClientName=='{client_name}'].ClientId"
    result = run(["aws", "cognito-idp", "list-user-pool-clients",
                  "--user-pool-id", user_pool_id, "--max-results", "1",
                  "--query", query, "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error getting cognito user pool clients: {result}")
    ids = json.loads(result.stdout.decode())
    if ids:
        print("User pool client already exists")
        return ids[0]

    result = run(["aws", "cognito-idp", "create-user-pool-client",
                  "--user-pool-id", user_pool_id,
                  "--client-name", client_name,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error creating user pool client: {result}")
    client_id = json.loads(result.stdout.decode())["UserPoolClient"]["ClientId"]
    print(f"User pool client {client_id} has been created")
    return client_id


def modify_file(user_pool_id: str, client_id: str) -> None:
    """Modify the wildryde-site/js/config.js file."""
    file_path = BASE_DIR / REPO_NAME / "js" / "config.js"
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    config_new = """window._config = {
        cognito: {
            userPoolId: '{user_pool_id}',
            userPoolClientId: '{client_id}',
            region: '{REGION}'
        },
        api: {
            invokeUrl: ''
        }""".replace("{user_pool_id}", user_pool_id)\
            .replace('{client_id}', client_id)\
            .replace('{REGION}', REGION) + "\n};"
    if content == config_new:
        print("Variables in the js/config.js file was modified earlier")
        return

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(config_new)
    print("Variables in the js/config.js file has been modified")


def register_new_user(user_pool_id) -> tuple[str, str]:
    """
    Register a new user in cognito user pool and return auth token.
    """
    new_user_name = "user"
    new_user_email = "user@domain"
    result = run(["aws", "cognito-idp", "admin-get-user",
                  "--user-pool-id", user_pool_id,
                  "--username", new_user_name,
                  "--profile", PROJECTNAME])
    if result.returncode == 0:
        print("Cognito user already exists")
    else:
        result = run([
            "aws", "cognito-idp", "admin-create-user",
            "--user-pool-id", user_pool_id, "--username", new_user_name,
            "--user-attributes", f"Name=email,Value={new_user_email}",
            "--message-action", "SUPPRESS", "--profile", PROJECTNAME])
        if result.returncode != 0:
            raise ValueError(f"Error creating new user: {result}")
        print("Cognito user has been created")

    # There is problem to escape apostrophe and comma in password,
    # so use only few special symbols and suffix "aA1!" for symbol requrements
    alphabet = string.digits + string.ascii_letters + "!-+*"
    password = ''.join(secrets.choice(alphabet) for _ in range(8)) + "aA1!"

    result = run(["aws", "cognito-idp", "admin-set-user-password",
                  "--user-pool-id", user_pool_id,
                  "--username", new_user_name,
                  "--password", password,
                  "--permanent",
                  "--profile", PROJECTNAME])
    print(f"New password '{password}' has been setted"
          f" for Cognito user '{new_user_name}' (email: {new_user_email})")

    return (new_user_name, password)


class AWSSRP:
    """
    Adopted AWS version of SRP realisation.

    See pycognito/aws_srp.py from https://pypi.org/project/pycognito/#files
    Package license is Apache License 2.0
    Learning by copying how it works.
    """
    # pylint: disable=missing-function-docstring

    # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
    N_HEX = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
    )
    # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
    G_HEX = "2"

    val_g = int(G_HEX, 16)
    big_n = int(N_HEX, 16)

    @staticmethod
    def calculate_a() -> tuple[int, int]:
        """
        Calculate the client's public value A = g^a%N
        with the generated random number a
        :param {Long integer} a Randomly generated small A.
        :return {Long integer} Computed large A.
        """
        def generate_random_small_a():
            """
            helper function to generate a random big integer
            :return {Long integer} a random value.
            """
            def get_random(nbytes):
                random_hex = binascii.hexlify(os.urandom(nbytes))
                return AWSSRP.hex_to_long(random_hex)

            random_long_int = get_random(128)
            return random_long_int % AWSSRP.big_n

        small_a_value = generate_random_small_a()

        big_a = pow(AWSSRP.val_g, small_a_value, AWSSRP.big_n)
        # safety check
        if (big_a % AWSSRP.big_n) == 0:
            raise ValueError("Safety check for A failed")
        return (small_a_value, big_a)

    def __init__(self, pool_id: str) -> None:
        self.pool_id = pool_id
        self.val_k = AWSSRP.hex_to_long(AWSSRP.hex_hash(
            "00" + AWSSRP.N_HEX + "0" + AWSSRP.G_HEX))
        self.small_a_value, self.large_a_value = AWSSRP.calculate_a()

    @staticmethod
    def hex_to_long(hex_string: str) -> int:
        return int(hex_string, 16)

    @staticmethod
    def hash_sha256(buf: str) -> str:
        """AuthenticationHelper.hash"""
        value = hashlib.sha256(buf).hexdigest()
        return (64 - len(value)) * "0" + value

    @staticmethod
    def pad_hex(long_int: int | str) -> str:
        """
        Converts a Long integer (or hex string) to hex format padded
            with zeroes for hashing
        :param {Long integer|String} long_int Number or string to pad.
        :return {String} Padded hex string.
        """
        if not isinstance(long_int, str):
            hash_str = AWSSRP.long_to_hex(long_int)
        else:
            hash_str = long_int
        if len(hash_str) % 2 == 1:
            hash_str = f"0{hash_str}"
        elif hash_str[0] in "89ABCDEFabcdef":
            hash_str = f"00{hash_str}"
        return hash_str

    @staticmethod
    def hex_hash(hex_string: str) -> str:
        return AWSSRP.hash_sha256(bytearray.fromhex(hex_string))

    @staticmethod
    def long_to_hex(long_num: int) -> str:
        return f"{long_num:x}"

    @staticmethod
    def calculate_u(big_a: int, big_b: int) -> int:
        """
        Calculate the client's value U which is the hash of A and B
        :param {Long integer} big_a Large A value.
        :param {Long integer} big_b Server B value.
        :return {Long integer} Computed U value.
        """
        u_hex_hash = AWSSRP.hex_hash(
            AWSSRP.pad_hex(big_a) + AWSSRP.pad_hex(big_b))
        return AWSSRP.hex_to_long(u_hex_hash)

    @staticmethod
    def compute_hkdf(ikm: bytearray, salt: bytes) -> bytes:
        """
        Standard hkdf algorithm
        :param {Buffer} ikm Input key material.
        :param {Buffer} salt Salt value.
        :return {Buffer} Strong key material.
        @private
        """
        # pylint: disable=invalid-name
        INFO_BITS = bytearray("Caldera Derived Key", "utf-8")
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        info_bits_update = INFO_BITS + bytearray(chr(1), "utf-8")
        hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
        return hmac_hash[:16]

    @staticmethod
    def get_cognito_formatted_timestamp(input_datetime):
        # pylint: disable=invalid-name
        WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        MONTH_NAMES = [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ]
        return f"{WEEKDAY_NAMES[input_datetime.weekday()]} " \
               f"{MONTH_NAMES[input_datetime.month - 1]} " \
               f"{input_datetime.day:d} " \
               f"{input_datetime.hour:02d}:{input_datetime.minute:02d}:" \
               f"{input_datetime.second:02d} UTC {input_datetime.year:d}"

    def get_password_authentication_key(
            self, username: str, password: str, server_b_value: int, salt: str
            ) -> bytes:
        """
        Calculates the final hkdf based on computed S value,
            and computed U value and the key
        :param {String} username Username.
        :param {String} password Password.
        :param {Long integer} server_b_value Server B value.
        :param {Long integer} salt Generated salt.
        :return {Buffer} Computed HKDF value.
        """
        u_value = self.calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError("U cannot be zero.")
        username_password = \
            f"{self.pool_id.split('_')[1]}{username}:{password}"
        username_password_hash = AWSSRP.hash_sha256(
            username_password.encode("utf-8"))

        x_value = AWSSRP.hex_to_long(AWSSRP.hex_hash(
            AWSSRP.pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self.val_g, x_value, self.big_n)
        int_value2 = server_b_value - self.val_k * g_mod_pow_xn
        s_value = pow(int_value2,
                      self.small_a_value + u_value * x_value,
                      self.big_n)
        hkdf = AWSSRP.compute_hkdf(
            bytearray.fromhex(AWSSRP.pad_hex(s_value)),
            bytearray.fromhex(AWSSRP.pad_hex(AWSSRP.long_to_hex(u_value))),
        )
        return hkdf

    def response(self, password: str,
                 challenge_parameters: dict[str, str]) -> str:
        """The responses to the challenge for SRP second step."""
        timestamp = AWSSRP.get_cognito_formatted_timestamp(
            datetime.datetime.now(datetime.UTC))
        hkdf = self.get_password_authentication_key(
                challenge_parameters["USER_ID_FOR_SRP"],
                password,
                AWSSRP.hex_to_long(challenge_parameters["SRP_B"]),
                challenge_parameters["SALT"]
            )
        secret_block_bytes = base64.standard_b64decode(
            challenge_parameters["SECRET_BLOCK"])
        msg = (
            bytearray(self.pool_id.split("_")[1], "utf-8")
            + bytearray(challenge_parameters["USER_ID_FOR_SRP"], "utf-8")
            + bytearray(secret_block_bytes)
            + bytearray(timestamp, "utf-8")
        )

        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())
        response = {
            "TIMESTAMP": timestamp,
            "USERNAME": challenge_parameters["USERNAME"],
            "PASSWORD_CLAIM_SECRET_BLOCK":
                challenge_parameters["SECRET_BLOCK"],
            "PASSWORD_CLAIM_SIGNATURE": signature_string.decode("utf-8"),
        }
        return json.dumps(response, separators=(', ', ':'))


def authenticate_user(user_pool_id: str, client_id: str,
                      login: str, password: str) -> str:
    """Authenticate user in AWS cognito."""
    aws_srp = AWSSRP(user_pool_id)
    srp_a = AWSSRP.long_to_hex(aws_srp.large_a_value)
    result = run([
        "aws", "cognito-idp", "initiate-auth",
        "--auth-flow", "USER_SRP_AUTH",
        "--client-id", client_id,
        "--auth-parameters", f"USERNAME={login},SRP_A={srp_a}",
        "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error initiating auth: {result}")

    initiating = json.loads(result.stdout.decode())
    if initiating["ChallengeName"] != "PASSWORD_VERIFIER" \
            or "ChallengeParameters" not in initiating:
        raise ValueError(f"Error ChallengeName in initiating auth: {result}")

    response = aws_srp.response(password, initiating["ChallengeParameters"])
    result = run(["aws", "cognito-idp", "respond-to-auth-challenge",
                  "--client-id", client_id,
                  "--challenge-name", "PASSWORD_VERIFIER",
                  "--challenge-responses", response,
                  "--profile", PROJECTNAME])
    if result.returncode != 0:
        raise ValueError(f"Error PASSWORD_VERIFIER: {result}")
    authentication = json.loads(result.stdout.decode())["AuthenticationResult"]
    print("User authentificated with token", authentication["IdToken"])
    return authentication["IdToken"]


def clean() -> None:
    """Clean up in aws cloud what we have created in this module"""
    # TODO: clean module 2
    # delete policies from user <IAM_USER> and confirmed email?
    # Delete identities
    # Delete user pool (with user pool clients)


def main(state: State) -> None:
    """Main function."""
    add_policies()
    create_email_identity()
    state.user_pool_id = create_user_pool()
    client_id = create_user_pool_client(state.user_pool_id)
    modify_file(state.user_pool_id, client_id)
    push_to_git("new_config")
    login, password = register_new_user(state.user_pool_id)
    state.auth_token = authenticate_user(
        state.user_pool_id, client_id, login, password)


if __name__ == "__main__":
    main(State())
