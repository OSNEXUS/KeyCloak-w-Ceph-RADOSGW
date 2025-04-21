The demos contained in this directory were designed specifically for Keycloak OIDC specifications. More general usage scripts for OIDC providers can be found in the base of the demo directory.

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
