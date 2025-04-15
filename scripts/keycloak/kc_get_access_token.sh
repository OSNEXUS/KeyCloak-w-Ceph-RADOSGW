#!/bin/bash

# Check for required arguments
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "Usage: $0 <realm> <client> <client_secret> <server> [access_token_file]"
    exit 1
fi

# Assign arguments to variables
KC_REALM="$1"
KC_CLIENT="$2"
KC_CLIENT_SECRET="$3"
KC_SERVER="$4"
KC_TOKEN_FILE="$5"

# Request Tokens for credentials
KC_RESPONSE=$( \
curl -s -k -X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "scope=openid" \
-d "grant_type=client_credentials" \
-d "client_id=$KC_CLIENT" \
-d "client_secret=$KC_CLIENT_SECRET" \
"http://$KC_SERVER/realms/$KC_REALM/protocol/openid-connect/token" 2>/dev/null\
| jq -r .access_token
)

# Handle token output
if [ -n "$KC_RESPONSE" ] && [ "$KC_RESPONSE" != "null" ]; then
    if [ -n "$KC_TOKEN_FILE" ]; then
        echo "$KC_RESPONSE" > "$KC_TOKEN_FILE"
        echo "Access token saved to $KC_TOKEN_FILE"
    else
        echo "$KC_RESPONSE"
    fi
else
    echo "Failed to retrieve access token." >&2
    exit 1
fi
