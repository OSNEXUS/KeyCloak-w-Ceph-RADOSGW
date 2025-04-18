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

if len(sys.argv) not in (5, 6):
    print("Usage: create_oidc_provider_role.py <role_name> <policy_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']")
    sys.exit(1)

role_name = sys.argv[1]
policy_name = sys.argv[2]
# IAM client args
s3_compatable_endpoint = sys.argv[3]
iam_client_id = sys.argv[4]
iam_client_password = sys.argv[5]

# If region is provided, use it, otherwise default to an empty string
region = sys.argv[6] if len(sys.argv) == 5 else ''

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

# this policy will allow s3access role to perform s3 operations
role_policy = '''{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}}'''

# Add new policy Policy-1
print("Adding policy document to role "+role_name+" with policy "+policy_name+"...")
try:
    response = iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=role_policy
    )
    print("Successfully added policy document.")
except Exception as e:
    print(e)
