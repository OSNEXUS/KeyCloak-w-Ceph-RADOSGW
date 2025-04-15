#!/bin/bash

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
    echo "Usage: get_access_token_v2.sh <token-end-point> <client> <client_secret> [scope,openid] [access_token_file]"
    exit 1
fi

TOKEN_ENDPOINT="$1"
OIDC_CLIENT="$2"
OIDC_CLIENT_SECRET="$3"
SCOPE="${4:-openid}"
ACCESS_TOKEN_FILE="${5:-}"

# Request Tokens for credentials
ACCESS_TOKEN_RESPONSE=$( \
curl -s -k -X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "scope=$SCOPE" \
-d "grant_type=client_credentials" \
-d "client_id=$OIDC_CLIENT" \
-d "client_secret=$OIDC_CLIENT_SECRET" \
"$TOKEN_ENDPOINT" 2>/dev/null 
)
echo $ACCESS_TOKEN_RESPONSE | jq

# Handle token output
if [ -n "$ACCESS_TOKEN_RESPONSE" ] && [ "$ACCESS_TOKEN_RESPONSE" != "null" ]; then
    ACCESS_TOKEN=$(echo "$ACCESS_TOKEN_RESPONSE" | jq -r .access_token)
    if [ -n "$ACCESS_TOKEN_FILE" ]; then
        echo "$ACCESS_TOKEN" > "$ACCESS_TOKEN_FILE"
        echo "Access token saved to $ACCESS_TOKEN_FILE"
    else
        echo "$ACCESS_TOKEN"
    fi
else
    echo "Failed to retrieve access token." >&2
    exit 1
fi
