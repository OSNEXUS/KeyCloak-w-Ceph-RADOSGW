# KeyCloak-w-Ceph-RADOSGW
This repo contains a demo application 'test.py' that utilizes the Amazon boto3 python library to create a Ceph Object Storage bucket. In the 'scripts' directory, there are utility scripts that can get various access tokens from the key cloak server which are utilized by the 'test.py' script for identity authentication.

- get_access_token.sh : Gets access token for client app 'ceph-rgw-client'. 
	Usage: get_access_token.sh <realm> <client> <client_secret> <server> [access_token_file]
- get_user_access_token.sh : Gets access token and ID token for client-user using credentials. 
	Usage: get_user_access_token.sh <realm> <client> <client_secret> <server> <kc_username> <kc_password> [access_token_file]
- introspect_token.sh : Examine the access token using the KeyCloak introspection URL.
	Usage: get_introspection.sh <realm> <client> <client_secret> <server> [access_token_file]
- key_cloak4.sh : Generates OIDC thumbprints
- key_cloak5.sh : Fetches access token, then examine the access token using the KeyCloak introspection URL.

QuantaStor KeyCloak Integration Guide https://wiki.osnexus.com/index.php?title=KeyCloak_Integration

