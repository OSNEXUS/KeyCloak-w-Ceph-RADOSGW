#!/usr/bin/python3
from pickle import FALSE
import boto3
import json
import sys
from os.path import exists
from subprocess import run, PIPE

if len(sys.argv) != 2:
    print("Access token script argument is a required argument to run this Keycloak CEPH RGW demo.")
    exit(1)

# we need the fully qualified path
scriptLoc = sys.argv[1]
print("SCRIPT LOC: " + scriptLoc)
if exists(scriptLoc) == False:
    print("Access token script file location '" + scriptLoc + "', needed to run this Keycloak CEPH RGW demo, does not exist.")
    exit(1)

#TESTER
print("Creating IAM client...")
iam_client = boto3.client('iam',
    aws_access_key_id="TESTER",
    aws_secret_access_key="test123",
    endpoint_url="http://10.0.26.140:7480",
    region_name=''
)

try:
    oidc_response = iam_client.delete_open_id_connect_provider(
        OpenIDConnectProviderArn="arn:aws:iam:::oidc-provider/10.0.26.1:8080/auth/realms/demo",
    )
    print("Successfully deleted open id connect provider...")
except Exception as e:
    print(e)

# You can Verify creation from the CLI using:
# aws --endpoint=http://10.0.26.140:7480/ iam list-open-id-connect-providers --region=""
# aws --endpoint=http://10.0.26.140:7480/ iam get-open-id-connect-provider --open-id-connect-provider-arn="arn:aws:iam:::oidc-provider/10.0.26.1:8080/auth/realms/quickstart" --region=""
print("create_open_id_connect_provider() OpenIDConnectProvider Url: http://10.0.26.1:8080/auth/realms/demo ClientIDList: ceph-rgw-client ThumbprintList: E43DBA95FC202A9773F3F542F12CF2A831FC7A6F, CE0E06206F6F5670E2BC725BD1557D177B3708BF.")
try:
    oidc_response = iam_client.create_open_id_connect_provider(
        Url="http://10.0.26.1:8080/auth/realms/demo",
        ClientIDList=[
            "ceph-rgw-client"
        ],
        ThumbprintList=[
            "F6897B6EE3DEA29887BD01FDBCCDCFA784DC0CE2",
            "B7A47AA590693B1730800FFA12BAE130D3459757"
        ]
    )
    print("Successfully created open id connect provider...")
except Exception as e:
    print(e)
    exit()

try:
    list_response = iam_client.list_roles()
    print("Listing roles for client 'http://10.0.26.140:7480'\n")
    print(list_response)
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
    policy_document = '''{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam:::oidc-provider/10.0.26.1:8080/auth/realms/demo"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringEquals":{"10.0.26.1:8080/auth/realms/demo:app_id":"account"}}}]}'''
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
    exit()

#TESTER1
sts_client = boto3.client('sts',
    aws_access_key_id="TESTER1",
    aws_secret_access_key="test321",
    endpoint_url="http://10.0.26.140:7480",
    region_name='',
)


# https://stackoverflow.com/questions/13745648/running-bash-script-from-within-python

# we need to get a fresh access token to load into WebIdentityToken in the assume_role_with_web_identity() call
result = run([scriptLoc], stdout=PIPE)
# Example return output
#   b'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NzI1MzEsImlhd
#   CI6MTY0Nzk3MjIzMSwianRpIjoiNTA0ZTgzODItMWNhNC00NmVjLWEyZjctNGYxOGQwNGU0YzRhIiwiaXNzIjoiaHR0cDovLzEwLjAuMjYuMTo4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJh
#   dWQiOiJhY2NvdW50Iiwic3ViIjoiNTA3NTE4ZjAtZDYzNi00Y2Q3LWExMjgtYTFjZjZlYjE4MGFmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibXljbGllbnQiLCJhY3IiOiIxIiwicmVhbG1
#   fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWRlbW8iXX0sInJlc291cmNlX2FjY2VzcyI6eyJteWNsaWVudC
#   I6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19f
#   Swic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SG9zdCI6IjEwLjAuMjYuMTQwIiwiY2xpZW50SWQiOiJteWNsaWVudCIsInBy
#   ZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1teWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4wLjI2LjE0MCJ9.eEuL9JXNk2OUNwQWV012FO3B6WKHN2vzBO-avo5VlI
#   iYe3BXXWmkxTXeS2_7lBDFlWEEkRY5K2C6vX7nJ3PceGAxDeUt9mO8jIblCiq1Pwg7IFr6Tn804o_8J_wZ94uC617ohGFWpxap07Wcdz9TtkYwUl3DDi8tvR254KrjgGRH-65riBJ-ufkch
#   CYKjMIM_kZb1Ci_Vc9-xQef9jEsVNmUBd-ZKWFpnaYmWsm73-d2bz4_XLyGkcq6z6LRK8hWaz9jyt7ESQmRfRa3VyYua8bO6eBsqF7n1e4ZPQNgxS-bWQzdzg0QH7JX5K1c7ZUj_9q4Fp9t
#   5ggeOgpjFI0kxw\n'
access_token = str(result.stdout).strip("b'")
access_token = access_token.strip("\\n")

#you need to run this before the token expires default token expires in 1 min
print("TESTER1 is calling assume_role_with_web_identity()...")
#use key_cloak2.sh to get the access token
try:
    response = sts_client.assume_role_with_web_identity(
        RoleArn=get_response['Role']['Arn'],
        RoleSessionName='Bob',
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
    endpoint_url="http://10.0.26.140:7480",
    region_name='',
)

print("Creating bucket using the s3 client...")
try:
    bucket_name = 'my-bucket'
    s3bucket = s3client.create_bucket(Bucket=bucket_name)
    resp = s3client.list_buckets()
    print("Successfully created bucket to end point 'http://10.0.26.140:7480'.")
except Exception as e:
    print(e)
    exit()