# KeyCloak with Ceph RADOSGW

This repository contains a demo applications (`create-oidc-and-bucket.py` & `create-oidc-and-rm-bucket.py`) that utilizes the Amazon Boto3 Python library to create a Ceph Object Storage bucket. The `scripts` directory provides utility scripts to retrieve various access tokens from the Keycloak server, which are used by `create-oidc-and-bucket.py` & `create-oidc-and-rm-bucket.py for identity authentication.

## Scripts Overview

### `get_access_token.sh`

**Purpose:** Retrieves an access token for the provided client app credentials.\
**Usage:**

```bash
get_access_token.sh <realm> <client> <client_secret> <server> [access_token_file]
```

- **realm** - The configured realm for your OIDC client (default is 'master').
- **client** - Client ID of the OIDC client.
- **client\_secret** - Secret key for OIDC client.
- **server** - IP address and port number for the Keycloak server.
- **[access\_token\_file]** - (Optional) File location to write the access token. If omitted, the token prints to stdout.\
  **Example:**

```bash
./get_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
```

### `get_user_access_token.sh`

**Purpose:** Retrieves access and ID tokens for a client user using credentials.\
**Usage:**

```bash
get_user_access_token.sh <realm> <client> <client_secret> <server> <kc_username> <kc_password> [access_token_file]
```

- **kc\_username** - Valid Keycloak username.
- **kc\_password** - Keycloak user password.\
  **Example:**

```bash
./get_user_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 testuid1 test123 access.file
```

### `introspect_token.sh`

**Purpose:** Examines the access token using Keycloak's introspection URL.\
**Usage:**

```bash
introspect_token.sh <realm> <client> <client_secret> <server> [access_token_file]
```

- **[access\_token\_file]** - File containing the raw access token. This file can be generated using `get_access_token.sh`.\
  **Example:**

```bash
./introspect_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
```

### `get_thumbprints.sh`

**Purpose:** Generates an OIDC thumbprints file named `thumbprints.txt` in the current directory.\
**Usage:**

```bash
get_thumbprints.sh <realm> <client> <client_secret> <server>
```

**Example:**

```bash
./get_thumbprints.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080
```

## User Creation for Demo Setup

Create two users via the RADOSGW endpoint for the demo setup:

**IAM Client User**

```bash
radosgw-admin --uid TESTUID1 --display-name "iam_user" --access_key TESTUID1 --secret test123 user create
radosgw-admin caps add --uid="TESTUID1" --caps="oidc-provider=*"
radosgw-admin caps add --uid="TESTUID1" --caps="roles=*"
```

**STS Client User**

```bash
radosgw-admin --uid TESTUID2 --display-name "sts_client_user" --access_key TESTUID2 --secret test321 user create
radosgw-admin caps add --uid="TESTUID2" --caps="roles=*"
```

## Demo Scripts

### `create-oidc-and-bucket.py`

**Purpose:** Uses the OIDC/STS protocols to assume the `S3Access` role and create a bucket named `my-bucket`.\
**Usage:**

```bash
python3 create-oidc-and-bucket.py <s3-server> <realm-name> <region> <iam-client-id> <iam-client-password> <sts-client-id> <sts-client-password> <kc-server> <kc-client-id> <kc-client-secret> <thumbprint-file>
```

**Example:**

```bash
python3 create-oidc-and-bucket.py x.x.x.x:7480 ceph-kc us-west-1 TESTUID1 test123 TESTUID2 test321 y.y.y.y:8080 ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx thumbprints.txt
```

### `create-oidc-and-rm-bucket.py`

**Purpose:** Uses the OIDC/STS protocols to assume the `S3Access` role and delete a bucket named `my-bucket`.\
**Usage:**

```bash
python3 create-oidc-and-rm-bucket.py <s3-server> <realm-name> <region> <iam-client-id> <iam-client-password> <sts-client-id> <sts-client-password> <kc-server> <kc-client-id> <kc-client-secret> <thumbprint-file>
```

**Example:**

```bash
python3 create-oidc-and-rm-bucket.py x.x.x.x:7480 ceph-kc us-west-1 TESTUID1 test123 TESTUID2 test321 y.y.y.y:8080 ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx thumbprints.txt
```

## Additional Resources

For more information, refer to the [QuantaStor Keycloak Integration Guide](https://wiki.osnexus.com/index.php?title=KeyCloak_Integration)

