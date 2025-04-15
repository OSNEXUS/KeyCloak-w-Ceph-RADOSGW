#!/bin/bash

if [ "$#" -lt 4 ] || [ "$#" -gt 6 ]; then
    echo "Usage: get_access_token.sh <grant_type: password|client_credentials> <token-end-point> <client> <client_secret> [scope,openid] [access_token_file]"
    exit 1
fi

GRANT_TYPE="$1"
TOKEN_ENDPOINT="$2"
OIDC_CLIENT="$3"
OIDC_CLIENT_SECRET="$4"
SCOPE="${5:-openid}"
ACCESS_TOKEN_FILE="${6:-}"

# Validate grant_type
if [ "$GRANT_TYPE" != "password" ] && [ "$GRANT_TYPE" != "client_credentials" ]; then
    echo "Error: grant_type must be 'password' or 'client_credentials'"
    exit 1
fi

if [ "$GRANT_TYPE" = "client_credentials" ]; then
    ACCESS_TOKEN_RESPONSE=$(curl -s -k -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=$OIDC_CLIENT" \
        -d "client_secret=$OIDC_CLIENT_SECRET" \
        -d "scope=$SCOPE" \
        "$TOKEN_ENDPOINT")
elif [ "$GRANT_TYPE" = "password" ]; then
    # Prompt user for credentials
    read -p "Username: " KC_USERNAME
    read -s -p "Password: " KC_PASSWORD
    echo

    ACCESS_TOKEN_RESPONSE=$(curl -s -k -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=$OIDC_CLIENT" \
        -d "client_secret=$OIDC_CLIENT_SECRET" \
        -d "username=$KC_USERNAME" \
        -d "password=$KC_PASSWORD" \
        -d "scope=$SCOPE" \
        "$TOKEN_ENDPOINT")
fi

echo "$ACCESS_TOKEN_RESPONSE"

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
