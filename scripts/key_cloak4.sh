#!/bin/bash

# Returns configured URLs for the requested realm
curl -k -v \
     -X GET \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "http://10.0.26.1:8080/auth/realms/demo/.well-known/openid-configuration" 2>/dev/null \
   | jq . | grep -i jwks_uri

# Use the 'jwks_uri' value from the response to get the certificate of the IDP (Below)


echo
echo

# Get the 'x5c' from this response to turn into an IDP-cert
KEY1_RESPONSE=$(curl -k -v \
     -X GET \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "http://10.0.26.1:8080/auth/realms/demo/protocol/openid-connect/certs" 2>/dev/null \
     | jq -r .keys[0].x5c)

KEY2_RESPONSE=$(curl -k -v \
     -X GET \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "http://10.0.26.1:8080/auth/realms/demo/protocol/openid-connect/certs" 2>/dev/null \
     | jq -r .keys[1].x5c)


echo
echo "Assembling Certificates...."

# Assemble Cert1
echo '-----BEGIN CERTIFICATE-----' > certificate1.crt
echo $(echo $KEY1_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate1.crt
echo '-----END CERTIFICATE-----' >> certificate1.crt
echo $(cat certificate1.crt)

# Assemble Cert2
echo '-----BEGIN CERTIFICATE-----' > certificate2.crt
echo $(echo $KEY2_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate2.crt
echo '-----END CERTIFICATE-----' >> certificate2.crt
echo $(cat certificate2.crt)

echo
echo "Generating thumbprints...."
# Create Thumbprint for both certs
PRETHUMBPRINT1=$(openssl x509 -in certificate1.crt -fingerprint -noout)
PRETHUMBPRINT2=$(openssl x509 -in certificate2.crt -fingerprint -noout)

PRETHUMBPRINT1=$(echo $PRETHUMBPRINT1 | awk '{ print substr($0, 18) }')
PRETHUMBPRINT2=$(echo $PRETHUMBPRINT2 | awk '{ print substr($0, 18) }')

echo "${PRETHUMBPRINT1//:}"
echo "${PRETHUMBPRINT2//:}"

#clean up the temp files
rm certificate1.crt
rm certificate2.crt

#[
#  {
#    "kid": "SkDALfA6N9sz2SRmxLUMPqhu0xdk6DpEW4PEV-L2tmA",
#    "kty": "RSA",
#    "alg": "RS256",
#    "use": "sig",
#    "n": "govdBOQ0T8Z1P3OxnlMASAPObpqRN3CLFxwhaokhplxWL20imwVlgLQXu41DpqJQ8U0cM8LxQ7NgYV-E1uJ_o_tq9loEBJqA2grIqVhfrk9fUF1iiVvxpn-gsHpFuW0_BGMzbFVwhKCuybJATAXwf6KxBxKswcP8y4mRw20uRxKX9iiWWOaNvRtVQsu6BN395HwdOIkE2408OdepDWHzPIUneS8-bzPTMgeoLxwV9tTNY6fkWhIdBNHJWGjdK2tyUfzICP7KK919zKqGpLP-f76uIq4GuxUsEwyF0FqrCjq_zD7q0c9iXOgVCIZO23mVl0HGi6wzX6ohNZS_pldGbw",
#    "e": "AQAB",
#    "x5c": [
#      "MIIClzCCAX8CBgF/dQ18xjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARkZW1vMB4XDTIyMDMxMDE4MTYzMloXDTMyMDMxMDE4MTgxMlowDzENMAsGA1UEAwwEZGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIKL3QTkNE/GdT9zsZ5TAEgDzm6akTdwixccIWqJIaZcVi9tIpsFZYC0F7uNQ6aiUPFNHDPC8UOzYGFfhNbif6P7avZaBASagNoKyKlYX65PX1BdYolb8aZ/oLB6RbltPwRjM2xVcISgrsmyQEwF8H+isQcSrMHD/MuJkcNtLkcSl/Yolljmjb0bVULLugTd/eR8HTiJBNuNPDnXqQ1h8zyFJ3kvPm8z0zIHqC8cFfbUzWOn5FoSHQTRyVho3StrclH8yAj+yivdfcyqhqSz/n++riKuBrsVLBMMhdBaqwo6v8w+6tHPYlzoFQiGTtt5lZdBxousM1+qITWUv6ZXRm8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKvrr/pT7JD/EHZWsiig6ciSed733FB/KHEtQbkWIp/ch45gsGVHHqGq911vk/26A8i6PFypWDsuoM0ocYwMDu0oZPX7f28jeEZC4bJNt4GNe13LMXGXaDcE+PvHgN3nR5u/PV1rT+8c+moCtEdC1uQJeVFYZMgz1DvUUZjhQBer0PXIUz4F8k3wCxl/WZGLen67iqnvJpTjXDJ7SHDXvQJ+BPrk6jTwMgY8Wm/ZO/rq063nOOWCLM781vMmR5eEtUsPjBXJrTVbvyymZL6n5govT/16fZu5Ht2ssZUFpa7hmj0MPU0ZgC2+46iltCpNIMsWlNyYBBp3mIKaUb6NB3g=="
#    ],
#    "x5t": "5D26lfwgKpdz8_VC8SzyqDH8em8",
#    "x5t#S256": "cxJdnE1jTyBQ3GV3EyB44tjUtw8hwMna1RS7nz3KcYM"
#  },
#  {
#    "kid": "LA2gYGbGTRP6LoDrOYSJrsKHk_dxNRxYyohN_4rzNGQ",
#    "kty": "RSA",
#    "alg": "RS256",
#    "use": "enc", <----- encryption cert usage?
#    "n": "jqDe1GRCScyfx9FqcriI3YiPNS1VNpQVAEPocBpY31vhXwty4L-2HxMCBpNJTNxzHoLhqvZmxfDQ8XogEklIjaCBXmhcHxpTS8HwN7HrhRqxoH52TwCNec8BimMUPwgn-oVSvhP5eRoCbZYZocMR-Y8n562dI3wfMt7ajwd8G-hNSxUOfF756PJlwZTDlGBUOfIUHJezhSONF817eKYEBmMAUhUZZIw2AMJlwZxezvd4V_cB9QSeNq2GT3FQVeYY3qJV0Fj3UUK7YWlk3bgYdrraZyouVP6y558rBXqo57-PjZobQQrnl0gJMe2OPl3-FSccqy5VppoLCzHIxxfrOQ",
#    "e": "AQAB",
#    "x5c": [
#      "MIIClzCCAX8CBgF/dQ190DANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARkZW1vMB4XDTIyMDMxMDE4MTYzMloXDTMyMDMxMDE4MTgxMlowDzENMAsGA1UEAwwEZGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI6g3tRkQknMn8fRanK4iN2IjzUtVTaUFQBD6HAaWN9b4V8LcuC/th8TAgaTSUzccx6C4ar2ZsXw0PF6IBJJSI2ggV5oXB8aU0vB8Dex64UasaB+dk8AjXnPAYpjFD8IJ/qFUr4T+XkaAm2WGaHDEfmPJ+etnSN8HzLe2o8HfBvoTUsVDnxe+ejyZcGUw5RgVDnyFByXs4UjjRfNe3imBAZjAFIVGWSMNgDCZcGcXs73eFf3AfUEnjathk9xUFXmGN6iVdBY91FCu2FpZN24GHa62mcqLlT+suefKwV6qOe/j42aG0EK55dICTHtjj5d/hUnHKsuVaaaCwsxyMcX6zkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAahRWXkRqoapA3IJTPbwqFp97HbaDxu/NdrNwQwEWOVZB2Dw1PvQoFsX3a8sTIFORt7VJNacJ9kPmQhZO7AWpdSIuaLlMR9MD3ifDFGxxL3B4SJX/sKywPWwZn3KkK6KV1Scm+oPkbumKBdsBV15zFJltxiMdLGksNx+h7ZnU9uw7tBz6HcAIB3pY22hCaGO/5/qM7o8KHtu3tDlKmrgQ0m3B3ChWPekjQf9GknRksTAV92meoGv9Rw5HXyFbCW0ZXs1d5tN+gb8YA1StErJD1cY+7sqWxsar1aIrBr8O7zR6qFzsznJVeHbfS92khpWtpBU0YEvo/Rr3A1WIGQkCqA=="
#    ],
#    "x5t": "zg4GIG9vVnDivHJb0VV9F3s3CL8",
#    "x5t#S256": "aJjXaMeHMJ9mfyYR05Qg79R4r3J4keHp5GIwt-34zzs"
#  }
#]
