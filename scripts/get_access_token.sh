#!/bin/bash

# Check for required arguments
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <realm> <client> <client_secret> <server>"
    exit 1
fi

# Assign arguments to variables
KC_REALM="$1"
KC_CLIENT="$2"
KC_CLIENT_SECRET="$3"
KC_SERVER="$4"

# Request Tokens for credentials
KC_RESPONSE=$( \
curl -s -k -X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "scope=openid" \
-d "grant_type=client_credentials" \
-d "client_id=$KC_CLIENT" \
-d "client_secret=$KC_CLIENT_SECRET" \
"http://$KC_SERVER/realms/$KC_REALM/protocol/openid-connect/token" 2>/dev/null\
| jq .
)

KC_ACCESS_TOKEN=$(echo "$KC_RESPONSE" | jq -r .access_token)
#echo "$KC_RESPONSE" | jq .     # Uncomment this line to print whole response.
echo "$KC_ACCESS_TOKEN"
