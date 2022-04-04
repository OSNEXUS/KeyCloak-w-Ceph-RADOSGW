#!/bin/bash
KC_REALM=demo
KC_CLIENT=ceph-rgw-client
KC_CLIENT_SECRET=4ab75796-0a02-4456-8818-a6225605f9f4
KC_SERVER=10.0.26.1:8080
KC_CONTEXT=auth

# Request Tokens for credentials
KC_RESPONSE=$( \
curl -s -k -v -X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "scope=openid" \
-d "grant_type=client_credentials" \
-d "client_id=$KC_CLIENT" \
-d "client_secret=$KC_CLIENT_SECRET" \
"http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token" 2>/dev/null \
| jq .
)

# get access token to pass to introspection URL
KC_ACCESS_TOKEN=$(echo $KC_RESPONSE| jq -r .access_token)

# using access token to verify against the introspection URL
curl -k -v \
-X POST \
-u "$KC_CLIENT:$KC_CLIENT_SECRET" \
-d "token=$KC_ACCESS_TOKEN" \
"http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token/introspect" 2>/dev/null \
| jq .

#{
#  "exp": 1647967965,
#  "iat": 1647967665,
#  "jti": "ff582fd6-ab51-46cc-93da-d762fab4d61d",
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

