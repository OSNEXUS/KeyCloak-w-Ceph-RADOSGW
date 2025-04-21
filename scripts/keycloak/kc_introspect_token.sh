#!/bin/bash

# Check for required arguments (minimum 4, maximum 5)
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "Usage: $0 <realm> <client> <client_secret> <server> [access_token_file]"
    exit 1
fi

# Assign arguments to variables
KC_REALM="$1"
KC_CLIENT="$2"
KC_CLIENT_SECRET="$3"
KC_SERVER="$4"
ACCESS_TOKEN_FILE="$5"

# Read access token from file if provided
if [ -n "$ACCESS_TOKEN_FILE" ]; then
    if [ -f "$ACCESS_TOKEN_FILE" ]; then
        KC_ACCESS_TOKEN=$(<"$ACCESS_TOKEN_FILE")
    else
        echo "Error: Access token file '$ACCESS_TOKEN_FILE' not found."
        exit 1
    fi
else
    echo "Error: Access token file must be provided as the fifth argument."
    exit 1
fi

# Using access token to verify against the introspection URL
curl -k -v \
-X POST \
-u "$KC_CLIENT:$KC_CLIENT_SECRET" \
-d "token=$KC_ACCESS_TOKEN" \
"http://$KC_SERVER/realms/$KC_REALM/protocol/openid-connect/token/introspect" 2>/dev/null \
| jq .
