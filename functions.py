import requests
import os
import sys
import logging
import argparse


# Need to sus out vars
hashicorpHost = "stub"
cyberarkHost = "stub"


# ----- Logging ----- #

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("vaab.log")
file_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
)

# ----- Arg parse ----- #

parser = argparse.ArgumentParser(description='add, modify and delete upstream nodes')

parser.add_argument(
    'pam', choices=['hashicorp', 'cyberark', 'conjur'], help='Name of PAM Provider')

parser.add_argument(
    '-n', '--auth', required=True, type=map, help='authentication for PAM')

parser.add_argument(
    '-l', '--secrets', required=True, type=map, help='')

args = parser.parse_args()

# ----- Validator ----- #

# add map validation steps here for whenever initiated,

# should have a fucntion name and flag to be able to differentiate
# so, args action should follow -> script.py Update/Get {PAM}


# ----- API Functions ----- #

def getSecret():

    # Add args for Hashicorp


    if args.pam == "hashicorp":

        print("stub")

        url = f"http://{hashicorpHost}/v1/secret/data/{secretType}/{secretName}"

        auth = {
            "X-Vault-Token": "{VAULT_TOKEN}"
        }

         #headers = {
        
        # }

        response = requests.get(url=url, headers=headers, auth=auth)
        response.raise_for_status()


    # Add args for Conjur

    elif args.pam == "conjur":
    
        print("stub")


    # Add args for CyberArk

    elif args.pam == "cyberark":

        url = f"http://{cyberarkHost}/read?filename={file}"

        headers = {
            "Content-Type": "application/json", 
            "Authorisation": "stub"
            }

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()

        if rc == 200:
            content = data["content"]
            print(f"Status: {rc}")
            print(f"\n[{file}]")
            print(f"Content:\n{content}\n")
            logger.info(f"Successfully read - {file} - {rc}")

        else:
            print("\n")
            logger.warning(f"Unable to read file - {rc} - {data.get('detail')}")

        return secret
    
    else:
        raise RuntimeError(f"{args.pam} is not a valid provider")

def writeSecret():