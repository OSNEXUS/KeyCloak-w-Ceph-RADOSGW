# KeyCloak with Ceph RADOSGW

This repository contains a demo applications that utilizes the Amazon Boto3 Python library to create a Ceph Object Storage bucket. The `scripts` directory provides utility scripts to retrieve various access tokens from an OIDC provider server, which are used by Ceph RGW STS for identity authentication via the AssumeRoleWithWebIdentity API. AssumeRoleWithWebIdentity will return a session token which can be used by an s3 compatible module such as Pyhton's `boto3`. Examples of python applications can be found in the `demo` directory.

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
python3 oidc_bucket.py <operation: create|delete> <bucket_name> <s3_compatible_endpoint> <oidc_app_endpoint> <oidc_token_endpoint> <oidc_config_endpoint> <region> <iam_client_id> <iam_client_password> <access_token_scope> <sts_client_id> <sts_client_password> <oidc_client_id> <oidc_client_secret>
```
- **operation** - `create` or `delete` bucket.
- **bucket_name** - Name of the bucket to `create` or `delete`.
- **s3_compatible_endpoint** - S3 endpoint to perform operation on.
- **oidc_app_endpoint** - Base end point for identity provider domain
- **oidc_token_endpoint** - Token end point for identity provider
- **oidc_config_endpoint** - OIDC configuration end point for identity provider
- **region** - Target region for S3 compatable operation
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **access_token_scope** - Most identity providers need `openid` scope. Azure requires `<client-uuid>/.default`
- **sts_client_id** - STS client target user. S3 compatable user with caps to perform role operations. Will call AssumeRoleWithWebIdentity() API.
- **sts_client_password** - STS client password.
- **oidc_client_id** - OIDC client ID, you can usually figure this out through the admin portal of your OIDC.
- **oidc_client_secret** - OIDC client secret.
**Example:**

```bash
python3 oidc_bucket.py create test-bucket-1 http://x.x.x.x:7480 https://login.microsoftonline.com/tenant-uuid/v2.0 https://login.microsoftonline.com/tenant-uuid/oauth2/v2.0/token https://login.microsoftonline.com/tenant-uuid/v2.0/.well-known/openid-configuration us-west-1 ODIC_PROVIDER test123 client-uuid/.default STS_CLIENT test321 client-uuid client-secret
```

### `list_oidc_providers.py`

**Purpose:** List all of the OpenID Connect providers on the given S3 compatable end point. \
**Usage:**
```bash
python3 list_oidc_providers.py <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 list_oidc_providers.py http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `create_oidc_provider.py`

**Purpose:** Create OIDC provider with assumed policy document.\
**Usage:**
```bash
python3 create_oidc_provider.py <oidc_app_endpoint> <oidc_config_endpoint> <oidc_client_id> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **oidc_app_endpoint** - Base end point for identity provider domain
- **oidc_config_endpoint** - OIDC configuration end point for identity provider
- **oidc_client_id** - OIDC client ID, you can usually figure this out through the admin portal of your OIDC.
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 create_oidc_provider.py https://auth.keycloaktest.com:8443/realms/kc_id_broker https://auth.keycloaktest.com:8443/realms/kc_id_broker/.well-known/openid-configuration kc_idp http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `delete_oidc_provider.py`

**Purpose:** Delete OIDC provider by ARN identifier. \
**Usage:**
```bash
python3 delete_oidc_provider.py <oidc_arn> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **oidc_arn** - ARN for target OIDC provider
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 delete_oidc_provider.py "arn:aws:iam:::oidc-provider/auth.keycloaktest.com:8443/realms/kc_id_broker" http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `list_roles.py`

**Purpose:** Lists all roles at a given S3 compatable endpoint. \
**Usage:**
```bash
python3 list_roles.py <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 list_roles.py http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `get_role.py`

**Purpose:** Get metadata for role by role name. \
**Usage:**
```bash
python3 get_role.py <role_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Target role name.
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 get_role.py S3Access http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `create_oidc_provider_role.py`

**Purpose:** Create a new role for S3 access.\
**Usage:**
```bash
python3 create_oidc_provider_role.py <role_name> <oidc_app_endpoint> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Name to assign role. Recommend to name 'S3Access'.
- **oidc_app_endpoint** - Base end point for identity provider domain
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 create_oidc_provider_role.py S3Access https://auth.keycloaktest.com:8443/realms/kc_id_broker http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `delete_oidc_provider_role.py`

**Purpose:** Delete target role by name. \
**Usage:**
```bash
python3 delete_oidc_provider_role.py <role_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Name of role to delete.
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 delete_oidc_provider_role.py S3Access http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `list_role_policy.py`

**Purpose:** List policies for a given role. \
**Usage:**
```bash
python3 list_role_policy.py <role_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Target role by name.
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 list_role_policy.py S3Access http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `put_oidc_provider_role_policy.py`

**Purpose:** Add policy for OIDC role assumption on target role by name.\
**Usage:**
```bash
python3 put_oidc_provider_role_policy.py <role_name> <policy_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Target role by name.
- **policy_name** - Name to assign to policy document
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 put_oidc_provider_role_policy.py S3Access Policy1 http://10.0.26.10:7480 OIDC_PROVIDER test123
```

### `delete_role_policy.py`

**Purpose:** Delete a role policy from a given role. \
**Usage:**
```bash
python3 delete_role_policy.py <role_name> <policy_name> <s3_compatible_endpoint> <iam_client_id> <iam_client_password> [region='']
```
- **role_name** - Target role to delete.
- **policy_name** - Name of target policy.
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **iam_client_id** - IAM client target user. S3 compatable user with caps to modify oidc-providers
- **iam_client_password** - IAM client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 delete_role_policy.py S3Access Policy1 http://10.0.26.10:7480 OIDC_PROVIDER test123
```


### `assume_role.py`

**Purpose:** This script assumes a role by ARN, assuming then attempts to either create or delete a bucket with a given name\
**Usage:**
```bash
python3 assume_role.py <operation: create|delete> <role_arn> <bucket_name> <oidc_token_endpoint> <oidc_client_id> <oidc_client_secret> <access_token_scope> <s3_compatible_endpoint> <sts_client_id> <sts_client_password> [region='']
```
- **operation** - `create` or `delete` bucket.
- **role_arn** - Role to assume by ARN identifier.
- **bucket_name** - Target bucket name.
- **oidc_token_endpoint** - Token end point for identity provider
- **oidc_client_id** - OIDC client ID, you can usually figure this out through the admin portal of your OIDC.
- **oidc_client_secret** - OIDC client secret.
- **access_token_scope** - Most identity providers need `openid` scope. Azure requires `<client-uuid>/.default`
- **s3_compatable_endpoint** - S3 endpoint to perform operation on.
- **sts_client_id** - STS client target user. S3 compatable user with caps to modify roles and assume them
- **sts_client_password** - STS client password
- **[region]** - (Optional) Target region for S3 compatable operation. Defaults to ''.
**Example:**
```bash
python3 assume_role.py create arn:aws:iam:::role/S3Access test-bucket-1 https://auth.keycloaktest.com:8443/realms/kc_id_broker/protocol/openid-connect/token kc_idp Xb1ItVaK4Zg7DUDKKNE4DYXePK5anovW openid http://10.0.26.10:7480 STS_CLIENT test321 us-east-1
python3 assume_role.py delete arn:aws:iam:::role/S3Access test-bucket-1 https://auth.keycloaktest.com:8443/realms/kc_id_broker/protocol/openid-connect/token kc_idp Xb1ItVaK4Zg7DUDKKNE4DYXePK5anovW openid http://10.0.26.10:7480 STS_CLIENT test321 us-east-1
```

## Additional Resources

For more information, refer to the [QuantaStor Keycloak Integration Guide](https://wiki.osnexus.com/index.php?title=KeyCloak_Integration)


