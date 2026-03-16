import base64
import urllib.parse

import boto3
import requests
from botocore.exceptions import ClientError

TIMEOUT = 10  # seconds for all HTTP calls

## HashiCorp Vault

def vault_get(secret_name, auth):
    addr = auth.get("addr")
    token = auth.get("token")
    mount = auth.get("mount", "secret")
    url = f"{addr}/v1/{mount}/data/{secret_name}"
    response = requests.get(url, headers={"X-Vault-Token": token}, timeout=TIMEOUT)
    if not response.ok:
        raise ValueError(f"Vault GET failed [{response.status_code}]: {response.text}")
    return response.json()["data"]["data"]["value"]


def vault_put(secret_name, value, auth):
    addr = auth.get("addr")
    token = auth.get("token")
    mount = auth.get("mount", "secret")
    url = f"{addr}/v1/{mount}/data/{secret_name}"
    response = requests.post(url, json={"data": {"value": value}}, headers={"X-Vault-Token": token}, timeout=TIMEOUT)
    if not response.ok:
        raise ValueError(f"Vault PUT failed [{response.status_code}]: {response.text}")


# CyberArk — CCP retrieves svc account creds → PVWA Logon → PVWA operations

def cyberark_logon(auth):
    """
    Two-step logon:
      1. CCP: retrieve service account username + password stored in CyberArk.
      2. PVWA: exchange those credentials for a session token.
    auth keys: host, app_id, safe, svc_object
    Returns {"token": <pvwa_session_token>}
    """
    host = auth["host"]
    app_id = auth["app_id"]
    safe = auth["safe"]
    svc_object = auth["svc_object"]

    # Step 1: CCP — fetch stored service account credentials
    ccp = requests.get(
        f"https://{host}/AIMWebService/api/Accounts",
        params={"AppID": app_id, "Safe": safe, "Object": svc_object},
        timeout=TIMEOUT,
    )
    if not ccp.ok:
        raise ValueError(f"CyberArk CCP failed [{ccp.status_code}]: {ccp.text}")
    ccp_data = ccp.json()
    username = ccp_data.get("UserName")
    password = ccp_data.get("Content")
    if not username or not password:
        raise ValueError("CyberArk CCP: missing UserName or Content in response")

    # Step 2: PVWA — exchange credentials for a session token
    logon = requests.post(
        f"https://{host}/PasswordVault/API/Auth/CyberArk/Logon",
        json={"username": username, "password": password},
        timeout=TIMEOUT,
    )
    if not logon.ok:
        raise ValueError(f"CyberArk PVWA logon failed [{logon.status_code}]: {logon.text}")
    token = logon.json()  # PVWA returns a bare JSON string
    if not token:
        raise ValueError("CyberArk PVWA logon: empty token returned")
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
        raise ValueError(f"CyberArk find account failed [{response.status_code}]: {response.text}")
    accounts = response.json().get("value", [])
    if not accounts:
        raise ValueError(f"CyberArk: no account '{name}' on platform '{platform}' in safe '{safe}'")
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
        raise ValueError(f"CyberArk GET failed [{response.status_code}]: {response.text}")
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
        raise ValueError(f"CyberArk PUT failed [{response.status_code}]: {response.text}")


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
        raise ValueError(f"Conjur auth failed [{response.status_code}]: {response.text}")
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
        raise ValueError(f"Conjur GET failed [{response.status_code}]: {response.text}")
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
        raise ValueError(f"Conjur PUT failed [{response.status_code}]: {response.text}")


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
        raise ValueError(f"AWS GET failed: {e}")


def aws_put(secret_name, value, auth):
    client = _aws_client(auth)
    try:
        client.put_secret_value(SecretId=secret_name, SecretString=value)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            try:
                client.create_secret(Name=secret_name, SecretString=value)
            except ClientError as ce:
                raise ValueError(f"AWS create secret failed: {ce}")
        else:
            raise ValueError(f"AWS PUT failed: {e}")
