These are scripts that are more specifically designed to work with Keycloak OIDC. We found there was a need for a more general purpose OIDC script which can be found in the base scripts directory.

## Scripts Overview

### `kc_get_access_token.sh`

**Purpose:** Retrieves an access token for the provided client app credentials.\
**Usage:**

```bash
kc_get_access_token.sh <realm> <client> <client_secret> <server> [access_token_file]
```

- **realm** - The configured realm for your OIDC client (default is 'master').
- **client** - Client ID of the OIDC client.
- **client\_secret** - Secret key for OIDC client.
- **server** - IP address and port number for the Keycloak server.
- **[access\_token\_file]** - (Optional) File location to write the access token. If omitted, the token prints to stdout.\
  **Example:**

```bash
./kc_get_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
```

### `kc_get_user_access_token.sh`

**Purpose:** Retrieves access and ID tokens for a client user using credentials.\
**Usage:**

```bash
kc_get_user_access_token.sh <realm> <client> <client_secret> <server> <kc_username> <kc_password> [access_token_file]
```

- **kc\_username** - Valid Keycloak username.
- **kc\_password** - Keycloak user password.\
  **Example:**

```bash
./kc_get_user_access_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 testuid1 test123 access.file
```

### `kc_introspect_token.sh`

**Purpose:** Examines the access token using Keycloak's introspection URL.\
**Usage:**

```bash
kc_introspect_token.sh <realm> <client> <client_secret> <server> [access_token_file]
```

- **[access\_token\_file]** - File containing the raw access token. This file can be generated using `kc_get_access_token.sh`.\
  **Example:**

```bash
./kc_introspect_token.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080 access.file
```

### `kc_get_thumbprints.sh`

**Purpose:** Generates an OIDC thumbprints file named `thumbprints.txt` in the current directory.\
**Usage:**

```bash
kc_get_thumbprints.sh <realm> <client> <client_secret> <server>
```

**Example:**

```bash
./kc_get_thumbprints.sh ceph-kc ceph-kc-client xxxxxxxxxxxxxxxxxxxxxxxxxxx x.x.x.x:8080
```