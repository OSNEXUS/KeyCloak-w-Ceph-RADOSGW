# KeyCloak-w-Ceph-RADOSGW
This repo contains a demo application 'test.py' that utilizes the Amazon boto3 python library to create a Ceph Object Storage bucket. In the 'scripts' directory, there are utility scripts that can get various access tokens from the key cloak server which are utilized by the 'test.py' script for identity authentication.

- key_cloak.sh : Gets access token for client app 'ceph-rgw-client'.
- key_cloak2.sh : Gets access token and ID token for client-user using credentials.
- key_cloak3.sh : Examine the access token using the KeyCloak introspection URL. (hardcoded access token)
- key_cloak4.sh : Generates OIDC thumbprints
- key_cloak5.sh : Fetches access token, then examine the access token using the KeyCloak introspection URL.

QuantaStor KeyCloak Integration Guide https://wiki.osnexus.com/index.php?title=KeyCloak_Integration

