#!/usr/bin/python3
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



THUMBPRINT_FILE = "thumbprints.txt"
S3_ACCESS_ROLE_NAME = "S3Access"
ROLE_POLICY_NAME = "Policy1"

def get_jwks_uri(oidc_config_endpoint):
    """Retrieve the JWKS URI from the OpenID configuration."""
    try:
        response = requests.get(oidc_config_endpoint, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
        response.raise_for_status()
        return response.json().get("jwks_uri")
    except (requests.RequestException, ValueError) as e:
        print(f"Error: Could not retrieve 'jwks_uri'. {e}")
        exit(1)

def get_certificates(jwks_uri):
    """Retrieve all x5c certificate values from the JWKS URI."""
    try:
        response = requests.get(jwks_uri, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
        response.raise_for_status()
        keys = response.json().get("keys", [])

        # Extract only the x5c certificate values from each key
        return [cert for key in keys if "x5c" in key for cert in key["x5c"]]

    except (requests.RequestException, ValueError) as e:
        print(f"Error: Could not retrieve certificates. {e}")
        exit(1)

def make_certificate(x5c_value):
    """Convert the x5c value into a PEM formatted certificate."""
    return f"-----BEGIN CERTIFICATE-----\n{x5c_value}\n-----END CERTIFICATE-----"

def generate_thumbprint_sha1(cert_b64):
    """Generate a SHA-256 thumbprint from a base64-encoded certificate."""
    try:
        cert_der = make_certificate(cert_b64)
        print(f"generated cert was \n{cert_der}")
        cert_der = base64.b64decode(cert_b64, validate=True)  # Ensures proper base64 format
    except base64.binascii.Error as e:
        print(f"Error decoding base64 certificate: {e}")
        return None  # Return None instead of crashing

    sha1_fingerprint = hashlib.sha1(cert_der).hexdigest().upper()
    return sha1_fingerprint


def base64url_decode(data):
    """Decode base64url-encoded data."""
    data += '=' * (-len(data) % 4)  # Fix padding
    return base64.urlsafe_b64decode(data)

def save_thumbprints(certs):
    """Save certificate thumbprints to a file."""
    if not certs:
        print("Error: No certificates found.")
        exit(1)

    print("\nAssembling Certificates....")

    with open(THUMBPRINT_FILE, "w") as f:
        for index, cert_b64 in enumerate(certs, start=1):
            print(f"Generating thumbprint for certificate {index}....")
            thumbprint = generate_thumbprint_sha1(cert_b64)
            f.write(f"{thumbprint}\n")

    print(f"Thumbprints saved to {THUMBPRINT_FILE}")

def validate_args(bucket_name,s3_compatable_endpoint,oidc_app_endpoint,oidc_token_endpoint,oidc_config_endpoint,region,iam_client_id,iam_client_password,access_token_scope,sts_client_id,sts_client_password,oidc_client_id,oidc_client_secret):
    # do some arg validation
    print("\nArguments Provided:")
    print(f"bucket_name: {bucket_name}")
    print(f"s3_compatable_endpoint: {s3_compatable_endpoint}")
    print(f"oidc_app_endpoint: {oidc_app_endpoint}")
    print(f"oidc_token_endpoint: {oidc_token_endpoint}")
    print(f"oidc_config_endpoint: {oidc_config_endpoint}")
    print(f"region: {region}")
    print(f"iam_client_id: {iam_client_id}")
    print(f"iam_client_password: {iam_client_password}")
    print(f"access_token_scope: {access_token_scope}")
    print(f"sts_client_id: {sts_client_id}")
    print(f"sts_client_password: {sts_client_password}")
    print(f"oidc_client_id: {oidc_client_id}")
    print(f"oidc_client_secret: {oidc_client_secret}")
    return

if len(sys.argv) != 15:
    print("Usage: create-oidc-and-bucket.py <operation: create|delete> <bucket_name> <s3_compatible_endpoint> <oidc_app_endpoint> <oidc_token_endpoint> <oidc_config_endpoint> <region> " +
          "<iam_client_id> <iam_client_password> <access_token_scope> <sts_client_id> <sts_client_password> <oidc_client_id> <oidc_client_secret>")
    sys.exit(1)

operation = sys.argv[1]
if operation not in ['create', 'delete']:
    print("Error: <operation> must be either 'create' or 'delete'")
    sys.exit(1)

bucket_name = sys.argv[2]
s3_compatable_endpoint = sys.argv[3]
oidc_app_endpoint = sys.argv[4]
oidc_token_endpoint = sys.argv[5]
oidc_config_endpoint = sys.argv[6]
region = sys.argv[7]
iam_client_id = sys.argv[8]
iam_client_password = sys.argv[9]
access_token_scope = sys.argv[10]
sts_client_id = sys.argv[11]
sts_client_password = sys.argv[12]
oidc_client_id = sys.argv[13]
oidc_client_secret = sys.argv[14]

args = {
    "Operation": operation,
    "Bucket Name": bucket_name,
    "S3 compatable Endpoint": s3_compatable_endpoint,
    "OIDC App Endpoint": oidc_app_endpoint,
    "OIDC Token Endpoint": oidc_token_endpoint,
    "OIDC Config Endpoint": oidc_config_endpoint,
    "Region": region,
    "IAM Client ID": iam_client_id,
    "IAM Client Password": iam_client_password,
    "ACCESS_TOKEN_SCOPE": access_token_scope,
    "STS Client ID": sts_client_id,
    "STS Client Password": sts_client_password,
    "OIDC Client": oidc_client_id,
    "OIDC Client Secret": oidc_client_secret,
}

validate_args(bucket_name,s3_compatable_endpoint,oidc_app_endpoint,oidc_token_endpoint,oidc_config_endpoint,region,iam_client_id,iam_client_password,access_token_scope,sts_client_id,sts_client_password,oidc_client_id,oidc_client_secret)


#iam client TESTER
print("Creating IAM client...")
iam_client = boto3.client('iam',
    aws_access_key_id=iam_client_id,
    aws_secret_access_key=iam_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name=''
)

# create an sts client to consume access token via ceph rgw
sts_client = boto3.client('sts',
    aws_access_key_id=sts_client_id,
    aws_secret_access_key=sts_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name='',
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

# DEBUG - uncomment below to print decoded token header and payload
# decoded_token_payload = base64.urlsafe_b64decode(payload + "==").decode("utf-8")
# token_payload_json = json.loads(decoded_token_payload)
# print(json.dumps(token_header_json, indent=4))
# print(json.dumps(token_payload_json, indent=4))

# save the key id for later use
token_kid=token_header_json["kid"]

oidcArn=''
#list the existing ODIC
try:
    oidc_response = iam_client.list_open_id_connect_providers()
    print("Successfully listed open id connect provider...")
    # print(json.dumps(oidc_response, indent=4))
    oidcArn = oidc_response['OpenIDConnectProviderList'][0]['Arn']
except Exception as e:
    print("An exception was thrown while listing oidc providers...")
    print(e)

#delete the existing ODIC if it exists
try:
    print("Deleting OIDC provider arn: '"+oidcArn+"'.")
    oidc_response = iam_client.delete_open_id_connect_provider(
        OpenIDConnectProviderArn=oidcArn,
    )
    # print(json.dumps(oidc_response, indent=4))
    print("Successfully deleted open id connect provider...")
except Exception as e:
    print("An exception was thrown while deleting oidc provider for odic path '"+oidc_app_endpoint+"' ...")
    print(e)

# You can Verify creation from the CLI using:
# aws --endpoint=http://x.x.x.x:7480/ iam list-open-id-connect-providers --region=""
# aws --endpoint=http://x.x.x.x:7480/ iam get-open-id-connect-provider --open-id-connect-provider-arn="arn:aws:iam:::oidc-provider/y.y.y.y:8080/auth/realms/quickstart" --region=""
print("create_open_id_connect_provider() OpenIDConnectProvider Url: "+oidc_app_endpoint+" key cloak client: "+oidc_client_id)

# use the wellknown config endpoint to get the JSON web key uri
jwks_uri = get_jwks_uri(oidc_config_endpoint)
if not jwks_uri:
    print("Error: Could not retrieve 'jwks_uri'.")
    exit(1)

# generate certs for each of the web keys avaiable
print(f"\nProcessing URI: {jwks_uri}")
certs = get_certificates(jwks_uri)

# generate a thumbprint file
save_thumbprints(certs)

with open(THUMBPRINT_FILE, "r") as file:
    ThumbprintListIn = [line.strip() for line in file if line.strip()]
print(ThumbprintListIn)

# create open id connect provider using the acquired thumbprints for your oidc client id
try:
    oidc_response = iam_client.create_open_id_connect_provider(
        Url=oidc_app_endpoint,
        ClientIDList=[
            oidc_client_id
        ],
        ThumbprintList=ThumbprintListIn
    )
    print("Successfully created open id connect provider...")
except Exception as e:
    print(e)

#list providers
try:
    oidc_list_response = iam_client.list_open_id_connect_providers()
    print("Listing oidc providers...\n")
    print(oidc_list_response)
except Exception as e:
    print(e)

# delete existing role policy, if it already exists.
print("delete_role_policy() Policy name '"+ROLE_POLICY_NAME+"'.")
try:
    role_response = iam_client.delete_role_policy(
        RoleName=S3_ACCESS_ROLE_NAME,
        PolicyName=ROLE_POLICY_NAME
    )
    print("Successfully Deleted Policy "+ROLE_POLICY_NAME+" for role "+S3_ACCESS_ROLE_NAME+".")
except Exception as e:
    print(e)

# delete the role if it already exists
print("\ndelete_role() RoleName '"+S3_ACCESS_ROLE_NAME+"'.")
try:
    role_response = iam_client.delete_role(
        RoleName=S3_ACCESS_ROLE_NAME
    )
    print("Successfully Deleted Role "+S3_ACCESS_ROLE_NAME+"")
except Exception as e:
    print(e)

oidc_path = oidc_app_endpoint.split("://", 1)[-1]
role_response = {}
# You can Verify role creation from the CLI using:
# radosgw-admin role list
print("create_role() sts:AssumeRoleWithWebIdentity create_role for RoleName "+S3_ACCESS_ROLE_NAME+". OIDC path is "+oidc_path+".")
try:
    policy_document = '''{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam:::oidc-provider/'''+oidc_path+'''"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringEquals":{"'''+oidc_path+''':app_id":"account"}}}]}'''
    role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path='/',
        RoleName=S3_ACCESS_ROLE_NAME,
    )
    print("Successfully Created Role "+S3_ACCESS_ROLE_NAME+"")
except Exception as e:
    print(e)

# this policy will allow s3access role to perform s3 operations
role_policy = '''{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}}'''

# Add new policy Policy-1
print("Adding policy document to role "+S3_ACCESS_ROLE_NAME+"...")
try:
    response = iam_client.put_role_policy(
        RoleName=S3_ACCESS_ROLE_NAME,
        PolicyName=ROLE_POLICY_NAME,
        PolicyDocument=role_policy
    )
    print("Successfully added policy document.")
except Exception as e:
    print(e)

# verify creation of new role.
print("getting role s3access...")
try:
    get_response = iam_client.get_role(RoleName=S3_ACCESS_ROLE_NAME)
    print("Successfully got role "+S3_ACCESS_ROLE_NAME+"...")
    print(get_response)
except Exception as e:
    print(e)

# This is probably the most important API call. AssumeRoleWithWebIdentity allows us to consume the access token to get a session token to be
# you need to run this before the token expires default token expires
roleArn = get_response['Role']['Arn']
print("sts client is calling assume_role_with_web_identity() role arn: '"+roleArn+"'...")
try:
    response = sts_client.assume_role_with_web_identity(
        RoleArn=roleArn,
        RoleSessionName='ceph-test-session',
        DurationSeconds=3600,
        WebIdentityToken=access_token
    )
    print("TESTER1 successfully assumed role with eweb identify")
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