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

# Extract 'jwks_uri' value from JSON response
JWKS_URI=$(curl -k -s \
     -X GET \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "http://$KC_SERVER/realms/$KC_REALM/.well-known/openid-configuration" \
     | jq -r '.jwks_uri')

# Check if JWKS_URI was found
if [ -z "$JWKS_URI" ]; then
    echo "Error: Could not retrieve 'jwks_uri'."
    exit 1
fi

echo "\nProcessing URI: $JWKS_URI"

# Retrieve all certificate keys
KEYS=$(curl -k -s \
     -X GET \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "$JWKS_URI" 2>/dev/null \
     | jq -r '.keys[].x5c[]')

if [ -z "$KEYS" ]; then
    echo "Error: No certificates found."
    exit 1
fi

echo "\nAssembling Certificates...."

# clear incase there is an old file
rm thumbprints.txt

# Process each certificate dynamically
INDEX=1
for KEY in $KEYS; do
    CERT_FILE="certificate$INDEX.crt"
    echo '-----BEGIN CERTIFICATE-----' > "$CERT_FILE"
    echo -E "$KEY" >> "$CERT_FILE"
    echo '-----END CERTIFICATE-----' >> "$CERT_FILE"
    echo "$(cat "$CERT_FILE")"

    echo "Generating thumbprint for certificate $INDEX...."
    PRETHUMBPRINT=$(openssl x509 -in "$CERT_FILE" -fingerprint -noout | awk '{ print substr($0, 18) }')

    echo "${PRETHUMBPRINT//:/}" >> thumbprints.txt

    # Clean up temp file
    rm "$CERT_FILE"

    ((INDEX++))
done
