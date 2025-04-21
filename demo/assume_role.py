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

if len(sys.argv) not in (11, 12):
    print("Usage: assume_role.py <operation: create|delete> <role_name> <bucket_name> <oidc_token_endpoint> <oidc_client_id> <oidc_client_secret> <access_token_scope> <s3_compatible_endpoint> <sts_client_id> <sts_client_password> [region='']")
    sys.exit(1)

operation = sys.argv[1]
if operation not in ['create', 'delete']:
    print("Error: <operation> must be either 'create' or 'delete'")
    sys.exit(1)

role_arn = sys.argv[2]
bucket_name = sys.argv[3]
oidc_token_endpoint = sys.argv[4]
oidc_client_id = sys.argv[5]
oidc_client_secret = sys.argv[6]
access_token_scope = sys.argv[7]
# IAM client args
s3_compatable_endpoint = sys.argv[8]
sts_client_id = sys.argv[9]
sts_client_password = sys.argv[10]

# If region is provided, use it, otherwise default to an empty string
region = sys.argv[11] if len(sys.argv) == 12 else ''

args = {
    "Operation": operation,
    "Role Arn": role_arn,
    "Bucket name": bucket_name,
    "OIDC Token Endpoint": oidc_token_endpoint,
    "OIDC Client": oidc_client_id,
    "OIDC Client Secret": oidc_client_secret,
    "ACCESS_TOKEN_SCOPE": access_token_scope,
    "S3 compatable Endpoint": s3_compatable_endpoint,
    "STS Client ID": sts_client_id,
    "STS Client Password": sts_client_password,
    "Region": region,
    
}

# create an sts client to consume access token via ceph rgw
print(f"Creating STS client... access {sts_client_id} endpoint {s3_compatable_endpoint} region {region}")
sts_client = boto3.client('sts',
    aws_access_key_id=sts_client_id,
    aws_secret_access_key=sts_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name=region,
)

# build access token request
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    "scope": access_token_scope,
    "grant_type": "client_credentials",
    "client_id": oidc_client_id,
    "client_secret": oidc_client_secret
    
}

# request access token from oidc token endpoint
print("Getting access token at URL '"+oidc_token_endpoint+"' for client '"+oidc_client_id+"'")
try:
    response = requests.post(oidc_token_endpoint, headers=headers, data=data, verify=False)  # `verify=False` for `-k` in curl
    response.raise_for_status()  # Raise an exception for HTTP errors
    #print(json.dumps(response.json(), indent=4))       # `jq .` equivalent for JSON output
    access_token = response.json().get('access_token')
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
    exit()
print(access_token)


header, payload, signature = access_token.split(".")
# Parse JSON
decoded_token_header = base64.urlsafe_b64decode(header + "==").decode("utf-8")
token_header_json = json.loads(decoded_token_header)

print("sts client is calling assume_role_with_web_identity() role arn: '"+role_arn+"'...")
try:
    response = sts_client.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName='ceph-test-session',
        DurationSeconds=3600,
        WebIdentityToken=access_token
    )
    print("sts_client_id successfully assumed role with eweb identify")
except sts_client.exceptions.MalformedPolicyDocumentException as e:
    print(f"Malformed Policy: {e}")
    exit()
except sts_client.exceptions.PackedPolicyTooLargeException as e:
    print(f"Packed Policy Too Large: {e}")
    exit()
except sts_client.exceptions.IDPRejectedClaimException as e:
    print(f"IDP Rejected Claim: {e}")
    exit()
except sts_client.exceptions.IDPCommunicationErrorException as e:
    print(f"IDP Communication Error: {e}")
    exit()
except sts_client.exceptions.InvalidIdentityTokenException as e:
    print(f"Invalid Identity Token: {e}")
    exit()
except sts_client.exceptions.ExpiredTokenException as e:
    print(f"Expired Token: {e}")
    exit()
except sts_client.exceptions.RegionDisabledException as e:
    print(f"Region Disabled: {e}")
    exit()
except ClientError as e:
    print(f"Client Error: {e}")
    exit()
except BotoCoreError as e:
    print(f"BotoCore Error: {e}")
    exit()
except Exception as e:
    print(f"Unexpected Error: {e}")
    exit()

print(f"PRINTING REGION {region}")
#Set up the S3 client using the new credentials
s3Compatclient = boto3.client('s3',
    aws_access_key_id = response['Credentials']['AccessKeyId'],
    aws_secret_access_key = response['Credentials']['SecretAccessKey'],
    aws_session_token = response['Credentials']['SessionToken'],
    endpoint_url=s3_compatable_endpoint,
    region_name=region,
)

print(f"{operation.capitalize()}ing bucket using the S3 client...")
try:
    if operation == 'create':
        s3bucket = s3Compatclient.create_bucket(Bucket=bucket_name)
        print(s3bucket)
        resp = s3Compatclient.list_buckets()
        print(resp)
        print(f"Successfully created bucket on endpoint '{s3_compatable_endpoint}'.")
    
    elif operation == 'delete':
        s3Compatclient.delete_bucket(Bucket=bucket_name)
        print(f"Successfully deleted bucket '{bucket_name}' from endpoint '{s3_compatable_endpoint}'.")
    
except Exception as e:
    print(f"An exception was thrown while attempting to {operation} the bucket.")
    print(e)
    exit()
