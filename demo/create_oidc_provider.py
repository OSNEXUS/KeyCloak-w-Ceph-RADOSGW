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

if len(sys.argv) not in (6, 7):
    print("Usage: create_oidc_provider.py <oidc_app_endpoint> <oidc_config_endpoint> <oidc_client_id> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']")
    sys.exit(1)

oidc_app_endpoint = sys.argv[1]
oidc_config_endpoint = sys.argv[2]
oidc_client_id = sys.argv[3]
# IAM client args
s3_compatable_endpoint = sys.argv[4]
iam_client_id = sys.argv[5]
iam_client_password = sys.argv[6]


# If region is provided, use it, otherwise default to an empty string
region = sys.argv[7] if len(sys.argv) == 6 else ''

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
print(f"Args: Url {oidc_app_endpoint}, client id {oidc_client_id}")
try:
    oidc_response = iam_client.create_open_id_connect_provider(
        Url=oidc_app_endpoint,
        ClientIDList=[
            oidc_client_id
        ],
        ThumbprintList=ThumbprintListIn
    )
    print(json.dumps(oidc_response, indent=4))
    print("Successfully created open id connect provider...")
except Exception as e:
    print(e)