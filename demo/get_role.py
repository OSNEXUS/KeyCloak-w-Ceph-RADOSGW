from pickle import FALSE
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import json
import sys
import requests
import hashlib
import base64
from requests.auth import HTTPBasicAuth
from os.path import exists
from subprocess import run, PIPE

import jwt
from jwt.algorithms import RSAAlgorithm

from cryptography import x509
from cryptography.hazmat.primitives import serialization

S3_ACCESS_ROLE_NAME = "S3Access"

if len(sys.argv) not in (4, 5):
    print("Usage: list_roles.py <role_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']")
    sys.exit(1)


role_name = sys.argv[1]
# IAM client args
s3_compatable_endpoint = sys.argv[2]
iam_client_id = sys.argv[3]
iam_client_password = sys.argv[4]

# If region is provided, use it, otherwise default to an empty string
region = sys.argv[5] if len(sys.argv) == 4 else ''

args = {
    "S3 compatable Endpoint": s3_compatable_endpoint,
    "IAM Client ID": iam_client_id,
    "IAM Client Password": iam_client_password,
    "Region": region,
}

#iam client TESTER
print(f"Creating IAM client... access {iam_client_id} endpoint {s3_compatable_endpoint}")
iam_client = boto3.client('iam',
    aws_access_key_id=iam_client_id,
    aws_secret_access_key=iam_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name=region
)

# verify creation of new role.
print("getting role s3access...")
try:
    get_response = iam_client.get_role(RoleName=role_name)
    print("Successfully got role "+role_name+"...")
    print(json.dumps(get_response, indent=4, default=str))
except Exception as e:
    print(e)
