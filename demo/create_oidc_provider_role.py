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

if len(sys.argv) not in (5, 6):
    print("Usage: create_oidc_provider_role.py <role_name> <oidc_app_endpoint> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']")
    sys.exit(1)

role_name = sys.argv[1]
oidc_app_endpoint = sys.argv[2]
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

oidc_path = oidc_app_endpoint.split("://", 1)[-1]
role_response = {}
# You can Verify role creation from the CLI using:
# radosgw-admin role list
print("create_role() sts:AssumeRoleWithWebIdentity create_role for RoleName "+role_name+". OIDC path is "+oidc_path+".")
try:
    policy_document = '''{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam:::oidc-provider/'''+oidc_path+'''"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringEquals":{"'''+oidc_path+''':app_id":"account"}}}]}'''
    role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path='/',
        RoleName=role_name,
    )
    print("Successfully Created Role "+role_name+"")
except Exception as e:
    print(e)
