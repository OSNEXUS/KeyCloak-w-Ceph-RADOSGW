# KeyCloak with Ceph RADOSGW

This repository contains a demo applications (`create-oidc-and-bucket.py` & `create-oidc-and-rm-bucket.py`) that utilizes the Amazon Boto3 Python library to create a Ceph Object Storage bucket. The `scripts` directory provides utility scripts to retrieve various access tokens from the Keycloak server, which are used by `create-oidc-and-bucket.py` & `create-oidc-and-rm-bucket.py for identity authentication.

## Scripts Overview

TODO

### `get_access_token.sh`

### `introspect_token.sh`

### `get_thumbprints.sh`

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

TODO

### `create-oidc-and-bucket.py`

### `create-oidc-and-rm-bucket.py`


## Additional Resources

For more information, refer to the [QuantaStor Keycloak Integration Guide](https://wiki.osnexus.com/index.php?title=KeyCloak_Integration)

