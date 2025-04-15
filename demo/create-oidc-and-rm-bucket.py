#!/usr/bin/python3
from pickle import FALSE
import boto3
import json
import sys
import requests
import hashlib
import base64
from requests.auth import HTTPBasicAuth
from os.path import exists
from subprocess import run, PIPE

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
    """Retrieve all certificates from the JWKS URI."""
    try:
        response = requests.get(jwks_uri, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
        response.raise_for_status()
        keys = response.json().get("keys", [])
        return [cert for key in keys for cert in key.get("x5c", [])]
    except (requests.RequestException, ValueError) as e:
        print(f"Error: Could not retrieve certificates. {e}")
        exit(1)

def generate_thumbprint(cert_b64):
    """Generate a SHA-1 thumbprint from a base64-encoded certificate."""
    cert_der = base64.b64decode(cert_b64)
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
            thumbprint = generate_thumbprint(cert_b64)
            f.write(f"{thumbprint}\n")

    print(f"Thumbprints saved to {THUMBPRINT_FILE}")



if len(sys.argv) != 13:
    print("Usage: script.py <bucket_name> <s3_compatable_endpoint> <oidc_app_endpoint> <oidc_token_endpoint> <oidc_config_endpoint> <region> " +
          "<iam_client_id> <iam_client_password> <sts_client_id> <sts_client_password> <kc_client_id> <kc_client_secret>")
    sys.exit(1)

bucket_name = sys.argv[1]
s3_compatable_endpoint = sys.argv[2]
oidc_app_endpoint = sys.argv[3]
oidc_token_endpoint = sys.argv[4]
oidc_config_endpoint = sys.argv[5]
region = sys.argv[6]
iam_client_id = sys.argv[7]
iam_client_password = sys.argv[8]
sts_client_id = sys.argv[9]
sts_client_password = sys.argv[10]
kc_client_id = sys.argv[11]
kc_client_secret = sys.argv[12]

#args = {
#    "S3 Server": s3_server,
#    "Realm Name": realm_name,
#    "IAM Client ID": iam_client_id,
#    "IAM Client Password": iam_client_password,
#    "STS Client ID": sts_client_id,
#    "STS Client Password": sts_client_password,
#    "KC Server": kc_server,
#    "KC Client": kc_client_id,
#    "KC Client Secret": kc_client_secret,
#    "Thumbprint File": thumbprint_file,
#}

args = {
    "Bucket Name": bucket_name,
    "S3 compatable Endpoint": s3_compatable_endpoint,
    "OIDC App Endpoint": oidc_app_endpoint,
    "OIDC Token Endpoint": oidc_token_endpoint,
    "OIDC Config Endpoint": oidc_config_endpoint,
    "Region": region,
    "IAM Client ID": iam_client_id,
    "IAM Client Password": iam_client_password,
    "STS Client ID": sts_client_id,
    "STS Client Password": sts_client_password,
    "KC Client": kc_client_id,
    "KC Client Secret": kc_client_secret,
}

print("\nArguments Provided:")
for key, value in args.items():
    print(f"{key}: {value}")

# derive endpoints
# s3_endpoint = "http://"+s3_server
# kc_endpoint = "http://"+kc_server
# realm_path = kc_server+"/realms/"+realm_name
# realm_endpoint = kc_endpoint+"/realms/"+realm_name
# # http://10.0.26.98:8080/realms/ceph-kc/protocol/openid-connect/auth
# # http://10.0.26.98:8080/realms/ceph-kc/broker/keycloak-oidc/endpoint
# auth_endpoint = realm_endpoint+"/protocol/openid-connect/auth"
# token_endpoint = realm_endpoint+"/protocol/openid-connect/token"
# introspect_endpoint = realm_endpoint+"/protocol/openid-connect/token/introspect"

# do some arg validation

#iam client TESTER
print("Creating IAM client...")
iam_client = boto3.client('iam',
    aws_access_key_id=iam_client_id,
    aws_secret_access_key=iam_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name=''
)

oidcArn=''
#delete the existing ODIC if it exists
try:
    oidc_response = iam_client.list_open_id_connect_providers()
    print("Successfully listed open id connect provider...")
    print(json.dumps(oidc_response, indent=4))
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
    print(json.dumps(oidc_response, indent=4))
    print("Successfully deleted open id connect provider...")
except Exception as e:
    print("An exception was thrown while deleting oidc provider for odic path '"+oidc_app_endpoint+"' ...")
    print(e)

# You can Verify creation from the CLI using:
# aws --endpoint=http://10.0.26.140:7480/ iam list-open-id-connect-providers --region=""
# aws --endpoint=http://10.0.26.140:7480/ iam get-open-id-connect-provider --open-id-connect-provider-arn="arn:aws:iam:::oidc-provider/10.0.26.1:8080/auth/realms/quickstart" --region=""
print("create_open_id_connect_provider() OpenIDConnectProvider Url: "+oidc_app_endpoint+" key cloak client: "+kc_client_id)
jwks_uri = get_jwks_uri(oidc_config_endpoint)
if not jwks_uri:
    print("Error: Could not retrieve 'jwks_uri'.")
    exit(1)

print(f"\nProcessing URI: {jwks_uri}")
certs = get_certificates(jwks_uri)
save_thumbprints(certs)

#list providers
try:
    oidc_list_response = iam_client.list_open_id_connect_providers()
    print("Listing oidc providers...\n")
    print(oidc_list_response)
except Exception as e:
    print(e)

print("\ndelete_role() RoleName 'S3Access'.")
try:
    role_response = iam_client.delete_role(
        RoleName='S3Access'
    )
    print("Successfully Deleted Role 'S3Access'")
except Exception as e:
    print(e)

role_response = {}
# You can Verify role creation from the CLI using:
# radosgw-admin role list
print("create_role() sts:AssumeRoleWithWebIdentity create_role for RoleName 'S3Access'.")
try:
    policy_document = '''{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam:::oidc-provider/'''+oidc_app_endpoint+'''"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringEquals":{"'''+oidc_app_endpoint+''':app_id":"account"}}}]}'''
    role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path='/',
        RoleName='S3Access',
    )
    print("Successfully Created Role 'S3Access'")
except Exception as e:
    print(e)

print("getting role s3access...")
try:
    get_response = iam_client.get_role(RoleName="S3Access")
    print("Successfully got role S3Access...")
    print(get_response)
except Exception as e:
    print(e)

# this policy will allow s3access role to perform s3 operations
role_policy = '''{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}}'''

print("Adding policy document to role S3Access...")
try:
    response = iam_client.put_role_policy(
        RoleName='S3Access',
        PolicyName='Policy1',
        PolicyDocument=role_policy
    )
    print("Successfully added policy document.")
except Exception as e:
    print(e)


#create an sts client to generate an access
sts_client = boto3.client('sts',
    aws_access_key_id=sts_client_id,
    aws_secret_access_key=sts_client_password,
    endpoint_url=s3_compatable_endpoint,
    region_name='',
)



headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    "scope": "openid",
    "grant_type": "client_credentials",
    "client_id": kc_client_id,
    "client_secret": kc_client_secret
}

print("Getting access token at URL '"+oidc_token_endpoint+"' for client '"+kc_client_id+"'")
try:
    response = requests.post(oidc_token_endpoint, headers=headers, data=data, verify=False)  # `verify=False` for `-k` in curl
    response.raise_for_status()  # Raise an exception for HTTP errors
    # print(response.json())       # `jq .` equivalent for JSON output
    access_token = response.json().get('access_token')
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
    exit()

print(access_token)

# Data payload
data = {
    'token': access_token
}

# Pretty-print the response JSON
#try:
#    print("introspecting token using client id '"+kc_client_id+"' with secret '"+kc_client_secret+"' url '"+introspect_endpoint+"'")
#    # Perform the request with Basic Auth
#    response = requests.post(
#        introspect_endpoint,
#        auth=HTTPBasicAuth(kc_client_id, kc_client_secret),
#        data=data,
#        verify=False  # Equivalent to `-k` in curl (disables SSL verification)
#    )
#    response.raise_for_status()
#
#    print(json.dumps(response.json(), indent=4))
#except ValueError:
#    print(f"Failed to decode JSON. Response text: {response.text}")



# you need to run this before the token expires default token expires in 1 min
roleArn = get_response['Role']['Arn']
print("sts client is calling assume_role_with_web_identity() role arn: '"+roleArn+"'...")
# use key_cloak2.sh to get the access token
try:
    response = sts_client.assume_role_with_web_identity(
        RoleArn=roleArn,
        RoleSessionName='ceph-kc-test-session',
        DurationSeconds=3600,
        WebIdentityToken=access_token
    )
    print("TESTER1 successfully assumed role with eweb identify")
except Exception as e:
    print(e)
    exit()

#Set up the S3 client using the new credentials
s3client = boto3.client('s3',
    aws_access_key_id = response['Credentials']['AccessKeyId'],
    aws_secret_access_key = response['Credentials']['SecretAccessKey'],
    aws_session_token = response['Credentials']['SessionToken'],
    endpoint_url=s3_compatable_endpoint,
    region_name='us-west-1',
)

print("Deleting bucket using the s3 client...")
try:
    s3bucket = s3client.delete_bucket(Bucket=bucket_name)
    resp = s3client.list_buckets()
    print("Successfully deleted bucket to end point '"+s3_compatable_endpoint+"'.")
except Exception as e:
    print("An exception was thrown while deleting a bucket with assumed role by web identity.")
    print(e)
    exit()