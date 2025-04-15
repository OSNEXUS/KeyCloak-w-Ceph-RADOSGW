# KeyCloak with Ceph RADOSGW

This repository contains a demo applications that utilizes the Amazon Boto3 Python library to create a Ceph Object Storage bucket. The `scripts` directory provides utility scripts to retrieve various access tokens from the Keycloak server, which are used by `create-oidc-and-bucket.py` & `create-oidc-and-rm-bucket.py for identity authentication.

## Scripts Overview

### `get_access_token.sh`
**Purpose:** Retrieves an access token for the provided client app credentials.\
**Usage:**

```bash
get_access_token.sh <grant_type: password|client_credentials> <token-end-point> <client> <client_secret> [scope,openid] [access_token_file]
```
- **grant_type** - The access token grant type desired password or client credentials. If password is selected user will be prompted for username and password.
- **token-end-point** - The token end point for your OIDC provider.
- **client** - Client ID of the OIDC client.
- **client\_secret** - Secret key for OIDC client.
- **[scope]** - (Optional) default value is openid. Some IDPs require that the scope be the ID of your target domain.
- **[access\_token\_file]** - (Optional) File location to write the access token. If omitted, the token prints to stdout.\
  **Example:**

```bash
./get_access_token.sh client_credentials https://key.cloak.com:8080/realms/realm-name/protocol/token kc-client-id xxxxxxxxxxxxxxxxxxxxxxxxxxx openid access.file
./get_access_token.sh password https://login.microsoftonline.com/tenant-uuid/oauth2/v2.0/token azure-client-uuid xxxxxxxxxxxxxxxxxxxxxxxxxxx azure-client-uuid/.default access.file
```

### `introspect_token.sh`
**Purpose:** Examines the access token using Keycloak's introspection URL.\
**Usage:**
```bash
introspect_token.sh <introspect-end-point> <client> <client_secret> <access_token_file>
```
- **introspect-end-point** - introspection endpoint, available for various IDPs like KeyCloak '''Note:''' Some identity providers do not have this API.
- **client** - Client ID of the OIDC client.
- **client\_secret** - Secret key for OIDC client.
- **[access\_token\_file]** - File containing the raw access token. This file can be generated using `get_access_token.sh`.\
  **Example:**
```bash
./introspect_token.sh http://key.cloak.com:8080/realms/ID-provider/protocol/openid-connect/token/introspect ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx access.file
```

### `get_thumbprints.sh`
**Purpose:** Generates an OIDC thumbprints file named `thumbprints.txt` in the current directory.\
**Usage:**
```bash
get_thumbprints.sh <oidc-config-endpoint>
```
- **oidc-config-endpoint** - URL to the well known configuration for OIDC.
  **Example:**
```bash
get_thumbprints.sh https://login.microsoftonline.com/tenant-uuid/v2.0/.well-known/openid-configuration
```


## User Creation for Demo Setup

Create two users via the RADOSGW endpoint for the demo setup:

**IAM Client User**

```bash
radosgw-admin --uid ODIC_PROVIDER --display-name "iam_user" --access_key ODIC_PROVIDER --secret test123 user create
radosgw-admin caps add --uid="ODIC_PROVIDER" --caps="oidc-provider=*"
radosgw-admin caps add --uid="ODIC_PROVIDER" --caps="roles=*"
```

**STS Client User**

```bash
radosgw-admin --uid STS_CLIENT --display-name "sts_client_user" --access_key STS_CLIENT --secret test321 user create
radosgw-admin caps add --uid="STS_CLIENT" --caps="roles=*"
```

## Demo Scripts

### `oidc_bucket.py`

**Purpose:** Uses the OIDC/STS protocols to assume the `S3Access` role and create or delete a bucket with a given name. This python script is a culmination of the operations that are performed by the scripts in the `scripts` directory.\
**Usage:**
```bash
python3 oidc_bucket.py <operation: create|delete> <bucket_name> <s3_compatible_endpoint> <oidc_app_endpoint> <oidc_token_endpoint> <oidc_config_endpoint> <region> <iam_client_id> <iam_client_password> <access_token_scope> <sts_client_id> <sts_client_password> <kc_client_id> <kc_client_secret>
```
**Example:**

```bash
python3 oidc_bucket.py create test-bucket-1 http://x.x.x.x:7480 https://login.microsoftonline.com/tenant-uuid/v2.0 https://login.microsoftonline.com/tenant-uuid/oauth2/v2.0/token https://login.microsoftonline.com/tenant-uuid/v2.0/.well-known/openid-configuration us-west-1 ODIC_PROVIDER test123 client-uuid/.default STS_CLIENT test321 client-uuid client-secret
```
## Additional Resources

For more information, refer to the [QuantaStor Keycloak Integration Guide](https://wiki.osnexus.com/index.php?title=KeyCloak_Integration)

