import base64
import urllib.parse

import boto3
import requests
from botocore.exceptions import ClientError

from aegis.errors import UpstreamError

TIMEOUT = 10  # seconds for all HTTP calls

# Response bodies never travel in an exception. For CyberArk and Conjur the
# body of a successful GET *is* the secret, so a failure path that echoed the
# body would be one upstream misbehaviour away from returning a credential to
# the caller and writing it to the audit log. Status code and operation are
# enough to diagnose; the body is not ours to repeat.

## HashiCorp Vault

def vault_get(secret_name, auth):
    addr = auth.get("addr")
    token = auth.get("token")
    mount = auth.get("mount", "secret")
    url = f"{addr}/v1/{mount}/data/{secret_name}"
    response = requests.get(url, headers={"X-Vault-Token": token}, timeout=TIMEOUT)
    if not response.ok:
        raise UpstreamError("vault", "GET", response.status_code)
    return response.json()["data"]["data"]["value"]


def vault_put(secret_name, value, auth):
    addr = auth.get("addr")
    token = auth.get("token")
    mount = auth.get("mount", "secret")
    url = f"{addr}/v1/{mount}/data/{secret_name}"
    response = requests.post(url, json={"data": {"value": value}}, headers={"X-Vault-Token": token}, timeout=TIMEOUT)
    if not response.ok:
        raise UpstreamError("vault", "PUT", response.status_code)


# CyberArk — CCP retrieves svc account creds → PVWA Logon → PVWA operations

def _auth_key(auth, name, legacy):
    """Read a CyberArk auth.json key, tolerating the pre-existing legacy spelling."""
    for key in (name, legacy):
        if auth.get(key):
            return auth[key]
    raise ValueError(f"CyberArk auth config missing '{name}'")


def cyberark_logon(auth):
    """
    Two-step logon:
      1. CCP: retrieve service account username + password stored in CyberArk.
      2. PVWA: exchange those credentials for a session token.
    auth keys: host, app_id, auth_safe, auth_object
      (the legacy spellings "safe" and "svc_object" are still accepted)
    Returns {"token": <pvwa_session_token>}
    """
    host = auth["host"]
    app_id = auth["app_id"]
    safe = _auth_key(auth, "auth_safe", "safe")
    svc_object = _auth_key(auth, "auth_object", "svc_object")

    # Step 1: CCP — fetch stored service account credentials
    ccp = requests.get(
        f"https://{host}/AIMWebService/api/Accounts",
        params={"AppID": app_id, "Safe": safe, "Object": svc_object},
        timeout=TIMEOUT,
    )
    if not ccp.ok:
        raise UpstreamError("cyberark", "CCP fetch", ccp.status_code)
    ccp_data = ccp.json()
    username = ccp_data.get("UserName")
    password = ccp_data.get("Content")
    if not username or not password:
        raise UpstreamError("cyberark", "CCP fetch", ccp.status_code,
                            reason="response missing UserName or Content")

    # Step 2: PVWA — exchange credentials for a session token
    logon = requests.post(
        f"https://{host}/PasswordVault/API/Auth/CyberArk/Logon",
        json={"username": username, "password": password},
        timeout=TIMEOUT,
    )
    if not logon.ok:
        raise UpstreamError("cyberark", "PVWA logon", logon.status_code)
    token = logon.json()  # PVWA returns a bare JSON string
    if not token:
        raise UpstreamError("cyberark", "PVWA logon", logon.status_code,
                            reason="empty token returned")
    return {"token": token}


def cyberark_find_account(platform, safe, name, token, host):
    """Search PVWA for an account by platform + safe + name. Returns account ID."""
    response = requests.get(
        f"https://{host}/PasswordVault/API/Accounts",
        params={"filter": f"safeName eq {safe} AND platformId eq {platform}", "search": name},
        headers={"Authorization": token},
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("cyberark", "account lookup", response.status_code)
    accounts = response.json().get("value", [])
    if not accounts:
        raise UpstreamError("cyberark", "account lookup",
                            reason=f"no account '{name}' on platform '{platform}' in safe '{safe}'")
    if len(accounts) > 1:
        # Ambiguity here is cross-secret retrieval, not a nuisance: the object
        # definition has to resolve to exactly one account.
        raise UpstreamError("cyberark", "account lookup",
                            reason=f"{len(accounts)} accounts match '{name}' on platform "
                                   f"'{platform}' in safe '{safe}'; the object definition must be unique")
    return accounts[0]["id"]


def cyberark_get(account_id, token, host):
    """Retrieve a secret value from PVWA by account ID."""
    response = requests.post(
        f"https://{host}/PasswordVault/API/Accounts/{account_id}/Password/Retrieve",
        json={},
        headers={"Authorization": token},
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("cyberark", "GET", response.status_code)
    return response.text  # PVWA returns the password as a plain string


def cyberark_put(account_id, value, token, host):
    """Set the next password for an account in PVWA."""
    response = requests.post(
        f"https://{host}/PasswordVault/API/Accounts/{account_id}/SetNextPassword",
        json={"ChangeEntireGroup": False, "NewCredentials": value},
        headers={"Authorization": token},
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("cyberark", "PUT", response.status_code)


# Conjur

def _conjur_token(auth):
    host = auth["host"]
    account = auth["account"]
    login = urllib.parse.quote(auth["login"], safe="")
    response = requests.post(
        f"https://{host}/authn/{account}/{login}/authenticate",
        data=auth["api_key"],
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("conjur", "auth", response.status_code)
    return base64.b64encode(response.content).decode("utf-8")


def conjur_get(secret_name, auth):
    token = _conjur_token(auth)
    host = auth["host"]
    account = auth["account"]
    encoded = urllib.parse.quote(secret_name, safe="")
    response = requests.get(
        f"https://{host}/secrets/{account}/variable/{encoded}",
        headers={"Authorization": f'Token token="{token}"'},
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("conjur", "GET", response.status_code)
    return response.text


def conjur_put(secret_name, value, auth):
    token = _conjur_token(auth)
    host = auth["host"]
    account = auth["account"]
    encoded = urllib.parse.quote(secret_name, safe="")
    response = requests.post(
        f"https://{host}/secrets/{account}/variable/{encoded}",
        data=value,
        headers={"Authorization": f'Token token="{token}"'},
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise UpstreamError("conjur", "PUT", response.status_code)


# AWS Secrets Manager

def _aws_client(auth):
    region = auth["region"]
    role_arn = auth.get("role_arn")
    if role_arn:
        sts = boto3.client("sts", region_name=region)
        creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="aegis")["Credentials"]
        return boto3.client(
            "secretsmanager",
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.client("secretsmanager", region_name=region)


def aws_get(secret_name, auth):
    try:
        return _aws_client(auth).get_secret_value(SecretId=secret_name)["SecretString"]
    except ClientError as e:
        # botocore puts the operation and error code in the exception; the
        # response payload is not included in that string.
        raise UpstreamError("aws", "GET",
                            reason=e.response.get("Error", {}).get("Code")) from e


def aws_put(secret_name, value, auth):
    client = _aws_client(auth)
    try:
        client.put_secret_value(SecretId=secret_name, SecretString=value)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            try:
                client.create_secret(Name=secret_name, SecretString=value)
            except ClientError as ce:
                raise UpstreamError("aws", "create",
                                    reason=ce.response.get("Error", {}).get("Code")) from ce
        else:
            raise UpstreamError("aws", "PUT",
                                reason=e.response.get("Error", {}).get("Code")) from e
