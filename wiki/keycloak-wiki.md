=OUTWARD=
== Setup Steps ==
Keycloak is a Third party authentication and OpenID Connect provider that can be integrated with Ceph RADOS Gateway to provide access control for Ceph Object Storage. Once you have configured CephRGW to communicate with the Keycloak server, users will be able to use 'Access Tokens' from the Keycloak server to provide authentication VIA the CephRGW STS service. Access Tokens from Keycloak have timeout periods and are useful to provide temporary access to bucket resources in the Ceph object storage pool.
=== Dependencies ===
* Docker - server
* Python3 & boto3 (pip3 install) - client
* Ceph RADOS Gateway - client
* OpenSSL - client

=== Keycloak Server ===
1. You will need to make sure that docker is installed and that you have downloaded the latest image of the Keycloak docker container (see [https://www.keycloak.org/getting-started/getting-started-docker Keycloak docker guide]). Run key cloak server docker image. <br>
 docker run -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin quay.io/keycloak/keycloak:15.0.2
2. Login to the [http://localhost:8080 admin terminal] (you can replace 'localhost' with the IP of the desired host if accessing remotely) via web browser as admin/admin and create a new realm 'demo' <br>
3. Create a new client 'ceph-rgw-client'. Use the following Settings: <br>
[[File:WikiKeyCloakCephRgw-client-settings.JPG]] <br>
4. Go to the the 'Credentials' tab and record the client secret to be used to acquire access tokens. <br>
[[File:WikiKeyCloakCephRgw-credentials-secret.JPG]] <br>
5. We are going to need a few scripts to acquire access tokens and inspect them:
 #!/bin/bash
 KC_REALM=<realm name>
 KC_CLIENT=<client name>
 KC_CLIENT_SECRET=<client secret>
 KC_SERVER=localhost:8080
 KC_CONTEXT=auth
 
 # Request Tokens for credentials
 KC_RESPONSE=$( \
 curl -s -k -v -X POST \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "scope=openid" \
 -d "grant_type=client_credentials" \
 -d "client_id=$KC_CLIENT" \
 -d "client_secret=$KC_CLIENT_SECRET" \
 "http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token" 2>/dev/null\
 | jq .
 )
 
 KC_ACCESS_TOKEN=$(echo $KC_RESPONSE| jq -r .access_token)
 #echo $KC_RESPONSE | jq .     # uncomment this line to print whole response.
 echo $KC_ACCESS_TOKEN
 
 # Example response :
 #{
 #  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NjY4MjMsImlhdCI6MTY0Nzk2NjUyMywianRpIjoiNmU2NTNhNDctNmJlOS00NDlkLThkNmItN2NmNWUzMmYxYzc0IiwiaXNzIjoiaHR0cDovLzEwLjAuMjYuMTo4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNTA3NTE4ZjAtZDYzNi00Y2Q3LWExMjgtYTFjZjZlYjE4MGFmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibXljbGllbnQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWRlbW8iXX0sInJlc291cmNlX2FjY2VzcyI6eyJteWNsaWVudCI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SG9zdCI6IjEwLjAuMjYuMTQwIiwiY2xpZW50SWQiOiJteWNsaWVudCIsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1teWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4wLjI2LjE0MCJ9.N5uOlBPKd2KZ3bQAwpbhYxDzeK-AVmvytPcHEsRktKANE7xgtCxPzagneTh5nzcEFpsyTGKIJVFTIgs7DvNepnfw1UPn0khatEChNQ_B_HJF9-2WV-b8PdOEmxACLXlcKfV4N0dWfOytcbIqInfdQGdHD_z1TwPDTdb3iALcccTiaOLWHSNKZkLFNM-Tj7B2HCI6SyUtOFLtfOXutJd4vlhAc0vkRimLyb2zQyzLSIEUg4vCEk7vNeiTkqfMpEumnc62jnoMm5wjaA6SjQ9JOvDySvv_sGtq-cbTWG4tkJ0ASOQqQ8kKHXYN5WGICDf46o834CQjzozukD0V6DD_zQ",
 #  "expires_in": 300,
 #  "refresh_expires_in": 0,
 #  "token_type": "Bearer",
 #  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NjY4MjMsImlhdCI6MTY0Nzk2NjUyMywiYXV0aF90aW1lIjowLCJqdGkiOiJkZjUyMzQwMS05NDkxLTQwZTctOWQzMC1hNDgxMzlmNDkzMzIiLCJpc3MiOiJodHRwOi8vMTAuMC4yNi4xOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsImF1ZCI6Im15Y2xpZW50Iiwic3ViIjoiNTA3NTE4ZjAtZDYzNi00Y2Q3LWExMjgtYTFjZjZlYjE4MGFmIiwidHlwIjoiSUQiLCJhenAiOiJteWNsaWVudCIsImF0X2hhc2giOiIxU1FBMFlpUUQxbXFtQmV4aEU0VWNnIiwiYWNyIjoiMSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SG9zdCI6IjEwLjAuMjYuMTQwIiwiY2xpZW50SWQiOiJteWNsaWVudCIsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1teWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4wLjI2LjE0MCJ9.I-tBqSvoP2lvP5ngUyfw7-0iBoZywl8x0i_XrrPI3Pony-cmuqmzgSTfmAtHCli7CKrbyw96xPPaina9S8DhmQxaZ7MGVderhs-WKq3h7FEQNXNY8sJcvolywSi9N7F1U_XtsUsn9BIy6J-3CJtK2VteRf6VSrvjXM7OJUKPE6eCjtxpL6GUJ7Kb7w9NhX6lNZMcDhXCri8qukjdn7wPuE_uP_UZFznzQYrZP738tilbRzOOGj0L1kTVy4lJeuakxyNINQsexWIgnHSw_O3sqBsCbvbrKbFJN4usYbxXVrAZXT1DWMZz4YI68kxtLQbsDpW2LaQMtW1R6f1IjyX-pA",
 #  "not-before-policy": 0,
 #  "scope": "openid email profile"
 #}
The script above will provide a service account 'access_token'. To do this, service accounts must be enabled on the KeyCloak server. You can also create users on the KeyCloak server and use those credentials to generate account access_tokens:
 #!/bin/bash
 KC_REALM=<realm name>
 KC_USERNAME=<username>
 KC_PASSWORD=<password>
 KC_CLIENT=<client name>
 KC_CLIENT_SECRET=<client secret>
 KC_SERVER=localhost:8080
 KC_CONTEXT=auth
 
 # Request Tokens for credentials
 KC_RESPONSE=$( \
 curl -k -v -X POST \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "scope=openid" \
 -d "grant_type=password" \
 -d "client_id=$KC_CLIENT" \
 -d "client_secret=$KC_CLIENT_SECRET" \
 -d "username=$KC_USERNAME" \
 -d "password=$KC_PASSWORD" \
 "http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token" 2>/dev/null\
 | jq .
 )
 
 echo
 #echo "Full token response:"
 #echo $KC_RESPONSE | jq .
 
 KC_ACCESS_TOKEN=$(echo $KC_RESPONSE| jq -r .access_token)
 echo "[access token]"
 echo $KC_ACCESS_TOKEN
 
 KC_ID_TOKEN=$(echo $KC_RESPONSE| jq -r .id_token)
 echo "[id token]"
 echo $KC_ID_TOKEN
 
 #{
 #  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NjczMzEsImlhdCI6MTY0Nzk2NzAzMSwianRpIjoiMzc0NjhjMmEtZDI2Ny00OWY5LTg2ZTUtYzFkYjEwNDRhMmM1IiwiaXNzIjoiaHR0cDovLzEwLjAuMjYuMTo4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiYzAyNzkxMDMtMDE5MC00NGMzLThlOGEtYjNhZjc5MDNiZjU3IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibXljbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiNWJmM2I1ODAtMDExZS00NDkyLWJhY2MtNDYyOGUwNWE4MGI4IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiZGVmYXVsdC1yb2xlcy1kZW1vIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsInNpZCI6IjViZjNiNTgwLTAxMWUtNDQ5Mi1iYWNjLTQ2MjhlMDVhODBiOCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdGVyIn0.H-BJ6M1omXUyu7ypQnuLoUkcr1r6kgo_z58dbLWr-HilHrMKiRuX8NeSjiftxquTySFw8uEwFmVwKpaIct1mJH2m37uOfSIZYDzDP0YD5WJEHkZ_5l89qogkCDFAvPQave5KYC5ml3M5xRmaKc4o9ojpPRisfBRW8sKHnM0zBRuP1nNyCGmLCuwmlBvzTwcogD2txVtuBU56X3XBKn9WxwTb_8rLOr2FvtPClcO5DPrb1jL3NXpmdN_O15cOJT7ZRo0o8HSRFy9l9aTkiqlIyS7_OYtT90MQ1Libyyiwv8k7V9wkLxTp7HqFwxvjUoOGz-pfegpxnzgCOGMi3Nf09w",
 #  "expires_in": 300,
 #  "refresh_expires_in": 1800,
 #  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxODdiYzdiNS0xZWNiLTQ1NTAtYjM1Zi0zOWFkZWEyMjk1MzMifQ.eyJleHAiOjE2NDc5Njg4MzEsImlhdCI6MTY0Nzk2NzAzMSwianRpIjoiN2NkMDU5ZjktNGRkYi00ZTFkLWIxYTktOTMwMjkxY2E3ODcyIiwiaXNzIjoiaHR0cDovLzEwLjAuMjYuMTo4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJhdWQiOiJodHRwOi8vMTAuMC4yNi4xOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsInN1YiI6ImMwMjc5MTAzLTAxOTAtNDRjMy04ZThhLWIzYWY3OTAzYmY1NyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJteWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiI1YmYzYjU4MC0wMTFlLTQ0OTItYmFjYy00NjI4ZTA1YTgwYjgiLCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNWJmM2I1ODAtMDExZS00NDkyLWJhY2MtNDYyOGUwNWE4MGI4In0.yjg6GE1T2xB5eb6WEzJql3-Gr4Hcleka5MOkfc2NmvU",
 #  "token_type": "Bearer",
 #  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NjczMzEsImlhdCI6MTY0Nzk2NzAzMSwiYXV0aF90aW1lIjowLCJqdGkiOiJmMDNkM2I5Zi1lOTNhLTQ4YzItYjU0Mi1kYzk3ZTE1M2M0OTgiLCJpc3MiOiJodHRwOi8vMTAuMC4yNi4xOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsImF1ZCI6Im15Y2xpZW50Iiwic3ViIjoiYzAyNzkxMDMtMDE5MC00NGMzLThlOGEtYjNhZjc5MDNiZjU3IiwidHlwIjoiSUQiLCJhenAiOiJteWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiI1YmYzYjU4MC0wMTFlLTQ0OTItYmFjYy00NjI4ZTA1YTgwYjgiLCJhdF9oYXNoIjoiU0FRU0JscjNRbDZZb3o5a3dxWEdDdyIsImFjciI6IjEiLCJzaWQiOiI1YmYzYjU4MC0wMTFlLTQ0OTItYmFjYy00NjI4ZTA1YTgwYjgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RlciJ9.dKaM09dYfEqnZ7CRRiz0ITZKR39OMIX1_QW2-XqYGGj_XLwClIQDYqCQzdsuhWDT60uQx1RSqJicZV8jnkCVZUB_AVjWXBjil4fITv1QXw8wOS7H48gG6HdkiVNxA3nBiBCGIbpiOR9iWyj_KBpwQd5bNaMNz1gtXW7t8MvkvS1iH8PI9iEAOT-PegJ8cfLdGPvLMfgDnAso6Me5Iq-uqHuZBtRsTMv5sydUqWHvn_7tF0YHtjA0aAmXWvOYGamBtTVAfMUAms8M8B749334KYXSPag_mGlKFsxcAeHN_UAJWCd375gSjfMdZxEZPsuYOmfHk4JiTWHZPeBM7tcyIQ",
 #  "not-before-policy": 0,
 #  "session_state": "5bf3b580-011e-4492-bacc-4628e05a80b8",
 #  "scope": "openid email profile"
 #}
You can inspect the access token using the introspection URL for the KeyCloak server:
 #!/bin/bash
 KC_REALM=demo
 KC_CLIENT=<client name>
 KC_CLIENT_SECRET=<client secret>
 KC_SERVER=localhost:8080
 KC_CONTEXT=auth
 KC_ACCESS_TOKEN=<access_token value>
 
 # using access token to verify against the introspection URL
 curl -k -v \
 -X POST \
 -u "$KC_CLIENT:$KC_CLIENT_SECRET" \
 -d "token=$KC_ACCESS_TOKEN" \
 "http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token/introspect" 2>/dev/null \
 | jq .
 
 #{
 #  "exp": 1647968025,
 #  "iat": 1647967725,
 #  "jti": "24737160-89ec-4eed-be21-76784c434abd",
 #  "iss": "http://10.0.26.1:8080/auth/realms/demo",
 #  "aud": "account",
 #  "sub": "507518f0-d636-4cd7-a128-a1cf6eb180af",
 #  "typ": "Bearer",
 #  "azp": "myclient",
 #  "preferred_username": "service-account-myclient",
 #  "email_verified": false,
 #  "acr": "1",
 #  "realm_access": {
 #    "roles": [
 #      "offline_access",
 #      "uma_authorization",
 #      "default-roles-demo"
 #    ]
 #  },
 #  "resource_access": {
 #    "myclient": {
 #      "roles": [
 #        "uma_protection"
 #      ]
 #    },
 #    "account": {
 #      "roles": [
 #        "manage-account",
 #        "manage-account-links",
 #        "view-profile"
 #      ]
 #    }
 #  },
 #  "scope": "openid email profile",
 #  "clientHost": "10.0.26.140",
 #  "clientId": "myclient",
 #  "clientAddress": "10.0.26.140",
 #  "client_id": "myclient",
 #  "username": "service-account-myclient",
 #  "active": true
 #}
6. Configure OpenIDConnect provider on realm in the 'Identity Providers' section. Select 'KeyCloak OpenID Connect': <br>
[[File:WikiKeyCloakCephRgw-oidc-provider.JPG]] <br>
Once you are able to get the access token and configured the OIDC provider, you have successfully set up your KeyCloak server.

=== Ceph RADOSGW ===

1. Configure Ceph Object storage pool and 1 RADOS Gateway on cluster manager node (ceph_*_radosgw.pem can be found int the /etc/ceph directory). <br>

2. Enable sts in gateway config (i.e. /etc/ceph/ceph.conf) Below is a sample configuration, add these lines:
 [client.radosgw.gateway_name]
 rgw sts key = abcdefghijklmnop 
 rgw s3 auth use sts = true
RGW STS uses a 128 bit key (16 characters) to encrypt/decrypt tokens. It is suggested that you use a stronger key than the one provided in this example. <br>

3. Create a 'TESTER' Ceph Bucket User and take down the secret and access key:
 radosgw-admin --uid TESTER --display-name "testuser" --access_key TESTER --secret test123 user create
 radosgw-admin caps add --uid="TESTER" --caps="oidc-provider=*"
 radosgw-admin caps add --uid="TESTER" --caps="roles=*"

We will also create another user 'TESTER1' to "AssumeRoleWithWebIdentity" as the STS client:
 radosgw-admin --uid TESTER1 --display-name "testuser1" --access_key TESTER1 --secret test321 user create
 radosgw-admin caps add --uid="TESTER1" --caps="roles=*"

4. configure "aws configure" using the credentials created above, so we can verify oidc provider arns using the aws CLI:
 root@terminal# aws configure
 AWS Access Key ID [None]: TESTER
 AWS Secret Access Key [None]: test123
 Default region name [None]:
 Default output format [None]: json

5. We can now use the AWS boto3 python library to create an OIDC provider, add some 'IAM' roles and policies, AssumeRoleWithIdentity using the RGW STS APIs, and make some s3 calls to RGW API:
 import boto3
 
 iam_client = boto3.client('iam',
 aws_access_key_id=<access_key of TESTER>,
 aws_secret_access_key=<secret_key of TESTER>,
 endpoint_url=<rgw-endpoint>,
 region_name=''
 )
 
 oidc_response = iam_client.create_open_id_connect_provider(
     Url="http://localhost:8080/auth/realms/<realm name>",  #<------ Realm endpoint
     ClientIDList=[
         <client name>
     ],
     ThumbprintList=[
         <Thumbprint of the IDP>
  ]
 )
 
 policy_document = ''''''{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam:::oidc-provider/localhost:8080/auth/realms/demo"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringEquals":{"localhost:8080/auth/realms/demo:app_id":"account"}}}]}''''''
 role_response = iam_client.create_role(
 AssumeRolePolicyDocument=policy_document,
 Path='/',
 RoleName='S3Access',
 )
 
 role_policy = ''''''{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}}''''''
 
 response = iam_client.put_role_policy(
     RoleName='S3Access',
     PolicyName='Policy1',
     PolicyDocument=role_policy
 )
 
 sts_client = boto3.client('sts',
 aws_access_key_id=<access_key of TESTER1>,
 aws_secret_access_key=<secret_key of TESTER1>,
 endpoint_url=<rgw-endpoint>,
 region_name='',
 )
 
 response = sts_client.assume_role_with_web_identity(
 RoleArn=role_response['Role']['Arn'],
 RoleSessionName='Bob',
 DurationSeconds=3600,
 WebIdentityToken=<Web Token> #<---- you can modify this script to fetch a new web token each time it is ran
 )
 
 s3client = boto3.client('s3',
 aws_access_key_id = response['Credentials']['AccessKeyId'],
 aws_secret_access_key = response['Credentials']['SecretAccessKey'],
 aws_session_token = response['Credentials']['SessionToken'],
 endpoint_url=<S3 URL>,
 region_name='',)
 
 bucket_name = 'my-bucket'
 s3bucket = s3client.create_bucket(Bucket=bucket_name)
 resp = s3client.list_buckets()

During testing, this python3 code could be put in a try-except block as failed operations will throw. Make sure that the 'policy_document' conditional permission 'app_id':'<aud>' where the 'aud' value comes from inspecting the access_token (see scripts in [http://devwiki.osnexus.net/index.php?title=CephRGW_w/_Keycloak#Keycloak_Server KeyCloak set up]). <br>

7. To fill in this script you will need to get the cert thumbprint from the KeyCloak server. You can do so by running this bash script:
 #!/bin/bash
 
 # Returns configured URLs for the requested realm
 curl -k -v \
      -X GET \
      -H "Content-Type: application/x-www-form-urlencoded" \
      "http://10.0.26.1:8080/auth/realms/demo/.well-known/openid-configuration" 2>/dev/null \
    | jq . | grep -i jwks_uri
 
 # Use the 'jwks_uri' value from the response to get the certificate of the IDP (Below)
 
 echo
 echo
 # Get the 'x5c' from this response to turn into an IDP-cert
 KEY1_RESPONSE=$(curl -k -v \
      -X GET \
      -H "Content-Type: application/x-www-form-urlencoded" \
      "http://10.0.26.1:8080/auth/realms/demo/protocol/openid-connect/certs" 2>/dev/null \
      | jq -r .keys[0].x5c)
 
 KEY2_RESPONSE=$(curl -k -v \
      -X GET \
      -H "Content-Type: application/x-www-form-urlencoded" \
      "http://10.0.26.1:8080/auth/realms/demo/protocol/openid-connect/certs" 2>/dev/null \
      | jq -r .keys[1].x5c)
 
 echo
 echo "Assembling Certificates...."
 
 # Assemble Cert1
 echo '-----BEGIN CERTIFICATE-----' > certificate1.crt
 echo $(echo $KEY1_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate1.crt
 echo '-----END CERTIFICATE-----' >> certificate1.crt
 echo $(cat certificate1.crt)
 
 # Assemble Cert2
 echo '-----BEGIN CERTIFICATE-----' > certificate2.crt
 echo $(echo $KEY2_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate2.crt
 echo '-----END CERTIFICATE-----' >> certificate2.crt
 echo $(cat certificate2.crt)
 
 echo
 echo "Generating thumbprints...."
 # Create Thumbprint for both certs
 PRETHUMBPRINT1=$(openssl x509 -in certificate1.crt -fingerprint -noout)
 PRETHUMBPRINT2=$(openssl x509 -in certificate2.crt -fingerprint -noout)
 
 PRETHUMBPRINT1=$(echo $PRETHUMBPRINT1 | awk '{ print substr($0, 18) }')
 PRETHUMBPRINT2=$(echo $PRETHUMBPRINT2 | awk '{ print substr($0, 18) }')
 
 echo "${PRETHUMBPRINT1//:}"
 echo "${PRETHUMBPRINT2//:}"
 
 #clean up the temp files
 rm certificate1.crt
 rm certificate2.crt
 
 #[
 #  {
 #    "kid": "SkDALfA6N9sz2SRmxLUMPqhu0xdk6DpEW4PEV-L2tmA",
 #    "kty": "RSA",
 #    "alg": "RS256",
 #    "use": "sig",
 #    "n": "govdBOQ0T8Z1P3OxnlMASAPObpqRN3CLFxwhaokhplxWL20imwVlgLQXu41DpqJQ8U0cM8LxQ7NgYV-E1uJ_o_tq9loEBJqA2grIqVhfrk9fUF1iiVvxpn-gsHpFuW0_BGMzbFVwhKCuybJATAXwf6KxBxKswcP8y4mRw20uRxKX9iiWWOaNvRtVQsu6BN395HwdOIkE2408OdepDWHzPIUneS8-bzPTMgeoLxwV9tTNY6fkWhIdBNHJWGjdK2tyUfzICP7KK919zKqGpLP-f76uIq4GuxUsEwyF0FqrCjq_zD7q0c9iXOgVCIZO23mVl0HGi6wzX6ohNZS_pldGbw",
 #    "e": "AQAB",
 #    "x5c": [
 #      "MIIClzCCAX8CBgF/dQ18xjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARkZW1vMB4XDTIyMDMxMDE4MTYzMloXDTMyMDMxMDE4MTgxMlowDzENMAsGA1UEAwwEZGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIKL3QTkNE/GdT9zsZ5TAEgDzm6akTdwixccIWqJIaZcVi9tIpsFZYC0F7uNQ6aiUPFNHDPC8UOzYGFfhNbif6P7avZaBASagNoKyKlYX65PX1BdYolb8aZ/oLB6RbltPwRjM2xVcISgrsmyQEwF8H+isQcSrMHD/MuJkcNtLkcSl/Yolljmjb0bVULLugTd/eR8HTiJBNuNPDnXqQ1h8zyFJ3kvPm8z0zIHqC8cFfbUzWOn5FoSHQTRyVho3StrclH8yAj+yivdfcyqhqSz/n++riKuBrsVLBMMhdBaqwo6v8w+6tHPYlzoFQiGTtt5lZdBxousM1+qITWUv6ZXRm8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKvrr/pT7JD/EHZWsiig6ciSed733FB/KHEtQbkWIp/ch45gsGVHHqGq911vk/26A8i6PFypWDsuoM0ocYwMDu0oZPX7f28jeEZC4bJNt4GNe13LMXGXaDcE+PvHgN3nR5u/PV1rT+8c+moCtEdC1uQJeVFYZMgz1DvUUZjhQBer0PXIUz4F8k3wCxl/WZGLen67iqnvJpTjXDJ7SHDXvQJ+BPrk6jTwMgY8Wm/ZO/rq063nOOWCLM781vMmR5eEtUsPjBXJrTVbvyymZL6n5govT/16fZu5Ht2ssZUFpa7hmj0MPU0ZgC2+46iltCpNIMsWlNyYBBp3mIKaUb6NB3g=="
 #    ],
 #    "x5t": "5D26lfwgKpdz8_VC8SzyqDH8em8",
 #    "x5t#S256": "cxJdnE1jTyBQ3GV3EyB44tjUtw8hwMna1RS7nz3KcYM"
 #  },
 #  {
 #    "kid": "LA2gYGbGTRP6LoDrOYSJrsKHk_dxNRxYyohN_4rzNGQ",
 #    "kty": "RSA",
 #    "alg": "RS256",
 #    "use": "enc", <----- encryption cert usage?
 #    "n": "jqDe1GRCScyfx9FqcriI3YiPNS1VNpQVAEPocBpY31vhXwty4L-2HxMCBpNJTNxzHoLhqvZmxfDQ8XogEklIjaCBXmhcHxpTS8HwN7HrhRqxoH52TwCNec8BimMUPwgn-oVSvhP5eRoCbZYZocMR-Y8n562dI3wfMt7ajwd8G-hNSxUOfF756PJlwZTDlGBUOfIUHJezhSONF817eKYEBmMAUhUZZIw2AMJlwZxezvd4V_cB9QSeNq2GT3FQVeYY3qJV0Fj3UUK7YWlk3bgYdrraZyouVP6y558rBXqo57-PjZobQQrnl0gJMe2OPl3-FSccqy5VppoLCzHIxxfrOQ",
 #    "e": "AQAB",
 #    "x5c": [
 #      "MIIClzCCAX8CBgF/dQ190DANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARkZW1vMB4XDTIyMDMxMDE4MTYzMloXDTMyMDMxMDE4MTgxMlowDzENMAsGA1UEAwwEZGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI6g3tRkQknMn8fRanK4iN2IjzUtVTaUFQBD6HAaWN9b4V8LcuC/th8TAgaTSUzccx6C4ar2ZsXw0PF6IBJJSI2ggV5oXB8aU0vB8Dex64UasaB+dk8AjXnPAYpjFD8IJ/qFUr4T+XkaAm2WGaHDEfmPJ+etnSN8HzLe2o8HfBvoTUsVDnxe+ejyZcGUw5RgVDnyFByXs4UjjRfNe3imBAZjAFIVGWSMNgDCZcGcXs73eFf3AfUEnjathk9xUFXmGN6iVdBY91FCu2FpZN24GHa62mcqLlT+suefKwV6qOe/j42aG0EK55dICTHtjj5d/hUnHKsuVaaaCwsxyMcX6zkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAahRWXkRqoapA3IJTPbwqFp97HbaDxu/NdrNwQwEWOVZB2Dw1PvQoFsX3a8sTIFORt7VJNacJ9kPmQhZO7AWpdSIuaLlMR9MD3ifDFGxxL3B4SJX/sKywPWwZn3KkK6KV1Scm+oPkbumKBdsBV15zFJltxiMdLGksNx+h7ZnU9uw7tBz6HcAIB3pY22hCaGO/5/qM7o8KHtu3tDlKmrgQ0m3B3ChWPekjQf9GknRksTAV92meoGv9Rw5HXyFbCW0ZXs1d5tN+gb8YA1StErJD1cY+7sqWxsar1aIrBr8O7zR6qFzsznJVeHbfS92khpWtpBU0YEvo/Rr3A1WIGQkCqA=="
 #    ],
 #    "x5t": "zg4GIG9vVnDivHJb0VV9F3s3CL8",
 #    "x5t#S256": "aJjXaMeHMJ9mfyYR05Qg79R4r3J4keHp5GIwt-34zzs"
 #  }
 #]
 
8. Once you have filled in the test script, run it. You should successfully create 'my-bucket' in your ceph object storage.
9. Verify the creation of the open-id-connect-provider using the aws CLI:
 aws --endpoint=<rgw-endpoint> iam list-open-id-connect-providers --region=""
 aws --endpoint=<rgw-endpoint> iam get-open-id-connect-provider --open-id-connect-provider-arn="arn:aws:iam:::oidc-provider/10.0.26.1:8080/auth/realms/demo" --region=""
 aws --endpoint=<rgw-endpoint> iam list-roles --region=""
