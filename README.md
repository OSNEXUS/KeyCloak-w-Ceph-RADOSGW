# KeyCloak-w-Ceph-RADOSGW
This repo contains a demo application 'test.py' that utilizes the Amazon boto3 python library to create a Ceph Object Storage bucket. In the 'scripts' directory, there are utility scripts that can get various access tokens from the key cloak server which are utilized by the 'test.py' script for identity authentication.

scripts:
- get_access_token.sh : Gets access token for the provided client app credentials. 
	Usage: get_access_token.sh <realm> <client> <client_secret> <server> [access_token_file]
		realm 				- The configured realm for your OIDC client. Keycloak default realm is 'master'
		client 				- Client ID of the OIDC client.
		client_secret 		- Secret key for OIDC client.
		server				- Ip-address:port-number for the Keycloak server that hosts the OIDC.
		[access_token_file]	- File location to write out the access token data. If not provided token will be printed to stdout.
	Example: ./get_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
- get_user_access_token.sh : Gets access token and ID token for client-user using credentials. 
	Usage: get_user_access_token.sh <realm> <client> <client_secret> <server> <kc_username> <kc_password> [access_token_file]
		realm 				- The configured realm for your OIDC client. Keycloak default realm is 'master'
		client 				- Client ID of the OIDC client.
		client_secret 		- Secret key for OIDC client.
		server				- Ip-address:port-number for the Keycloak server that hosts the OIDC.
		kc_username			- Valid Keycloak username.
		kc_password 		- Keycloak user password.
		[access_token_file]	- File location to write out the access token data. If not provided token will be printed to stdout.
	Example: ./get_user_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 testuid1 test123 access.file
- introspect_token.sh : Examine the access token using the KeyCloak introspection URL.
	Usage: get_introspection.sh <realm> <client> <client_secret> <server> [access_token_file]
		realm 				- The configured realm for your OIDC client. Keycloak default realm is 'master'
		client 				- Client ID of the OIDC client.
		client_secret 		- Secret key for OIDC client.
		server				- Ip-address:port-number for the Keycloak server that hosts the OIDC.
		[access_token_file]	- File location to file that contains the raw access token data. This file can be generated using the 'get_access_token.sh' script with the 'access_token_file' parameter.
	Example: ./introspect_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
- get_thumbprints.sh : Generates OIDC thumbprints file to the cwd named thumbprints.txt
	Usage: get_thumbprints.sh <realm> <client> <client_secret> <server>
		realm 				- The configured realm for your OIDC client. Keycloak default realm is 'master'
		client 				- Client ID of the OIDC client.
		client_secret 		- Secret key for OIDC client.
		server				- Ip-address:port-number for the Keycloak server that hosts the OIDC.
	Example: ./get_thumbprints.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080

To enable the demo scripts you must create 2 users through the radosgw endpoint. One user will be used as a ceph STS client and the other as an iam client user and will need to be able to have 'oidc-provider' caps. Both clients need 'Roles' caps. Use the following example to create these users:
 # create an iam client user
 radosgw-admin --uid TESTUID1 --display-name "iam_user" --access_key TESTUID1 --secret test123 user create
 radosgw-admin caps add --uid="TESTUID1" --caps="oidc-provider=*"
 radosgw-admin caps add --uid="TESTUID1" --caps="roles=*"
 
 # create an sts client user
 radosgw-admin --uid TESTUID2 --display-name "sts_client_user" --access_key TESTUID2 --secret test321 user create
 radosgw-admin caps add --uid="TESTUID2" --caps="roles=*"

Additionally, use the 'get_thumbprints.sh' script to generate a cert thumbprint file to be consumed by the demo scripts 'create-oidc-and-bucket.py' and 'create-oidc-and-rm-bucket.py'

For each of these demos a series of operations is performed. Both scripts create an OIDC provider for specified ceph object storage Rados Gateway endpoint using your iam client user. Iam client will create an 'S3Access' role to be used by an s3 client. Next, we get access credentials using the STS client via the OIDC access_token protocol. Access credentials will be used to create an s3 client to create and delete buckets. Each time the scripts are run, a new OIDC provider is created and new access token is generated. The OIDC provider does not need to be recreated each time, but for the sake of this demo, it seemed practical.

demo:
 - create-oidc-and-bucket.py : This script uses the OIDC/STS protocols to assume S3access role and creates a bucket named 'my-bucket'.
	Usage: create-oidc-and-bucket.py <s3-server> <realm-name> <region> <iam-client-id> <iam-client-password> <sts-client-id> <sts-client-password> <kc-server> <kc-client-id> <kc-client-secret> <thumbprint-file>
 - create-oidc-and-rm-bucket.py : This script uses the OIDC/STS protocols to assume S3access role and deletes a bucket named 'my-bucket'.
	Usage: create-oidc-and-rm-bucket.py <s3-server> <realm-name> <region> <iam-client-id> <iam-client-password> <sts-client-id> <sts-client-password> <kc-server> <kc-client-id> <kc-client-secret> <thumbprint-file>
		s3-server				- Ip-address:port-number of radosgw endpoint. 
		realm-name				- The configured realm for your OIDC client. Keycloak default realm is 'master'.
		region					- A valid s3 region for your radosgw e.g. us-west-1.
		iam-client-id			- Username of the user we IAM client user with oidc-provider caps (in this example 'TESTUID1').
		iam-client-password		- Password for IAM client user.
		sts-client-id			- Username of the STS client user (in this example TESTUID2).
		sts-client-password		- Password for STS client user.
		kc-server				- Ip-address:port-number for the Keycloak server that hosts the OIDC.
		kc-client-id			- Client ID of the OIDC client.
		kc-client-secret		- Secret key for OIDC client.
		thumbprint-file			- Thumbprints from the keycloak public certs. You can generate this file using the 'get_thumbprints.sh' script.
	Example:  python3 create-oidc-and-bucket.py x.x.x.x:7480 ceph-kc us-west-1 TESTUID1 test123 TESTUID2 test321 y.y.y.y:8080 ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx thumbprints.txt

QuantaStor KeyCloak Integration Guide https://wiki.osnexus.com/index.php?title=KeyCloak_Integration

--------------------------------------------------------------

# KeyCloak with Ceph RADOSGW

This repository contains a demo application (`test.py`) that utilizes the Amazon Boto3 Python library to create a Ceph Object Storage bucket. The `scripts` directory provides utility scripts to retrieve various access tokens from the Keycloak server, which are used by `test.py` for identity authentication.

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

