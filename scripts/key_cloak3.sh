#!/bin/bash
KC_REALM=demo
KC_CLIENT=ceph-rgw-client
KC_CLIENT_SECRET=4ab75796-0a02-4456-8818-a6225605f9f4
KC_SERVER=10.0.26.1:8080
KC_CONTEXT=auth
KC_ACCESS_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfUjk0bEtWRUZsam1Rc19WRGlST25XS0JnWXJnOEExTXZWb0w3WWhIS19jIn0.eyJleHAiOjE2NDc5NjgwMjUsImlhdCI6MTY0Nzk2NzcyNSwianRpIjoiMjQ3MzcxNjAtODllYy00ZWVkLWJlMjEtNzY3ODRjNDM0YWJkIiwiaXNzIjoiaHR0cDovLzEwLjAuMjYuMTo4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNTA3NTE4ZjAtZDYzNi00Y2Q3LWExMjgtYTFjZjZlYjE4MGFmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibXljbGllbnQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWRlbW8iXX0sInJlc291cmNlX2FjY2VzcyI6eyJteWNsaWVudCI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SG9zdCI6IjEwLjAuMjYuMTQwIiwiY2xpZW50SWQiOiJteWNsaWVudCIsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1teWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4wLjI2LjE0MCJ9.eq-tOULDXQmWh3iAx94b-REixxN1GBo_2yo1dAzVtaipQuvEsiEzLLIuHhoTcoPRmzOCw1z23U4qYlIoDGm-RGNbeU3z-DPkJsJy5myc0j7XkHUdX2jyGPeGgrd2jyxgqsB2_RWvlbFzLII56PSqgWdlqgzFRCuhbrUShEU6IGCVwxC7V6w6eOYCAAszqcLHth0SPsmuFZUicUeqgtp9w99frJC6xlIvNDohS8eXQb8ySFYQk7Cn5IOvRudh0zfJr_XF9gM8gLHU4az48rFSkc3yMLiDquc6wkrQ6iMRbd2ciwu2qWdRrALf-EjrpN30XCq20piUFWeYiIF8JhuuWQ

# using access token to verify against the introspection URL
curl -k -v \
-X POST \
-u "$KC_CLIENT:$KC_CLIENT_SECRET" \
-d "token=$KC_ACCESS_TOKEN" \
"http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/token/introspect" 2>/dev/null \
| jq .

#{
#  "exp": 1647968025,
#  "iat": 1647967725,
#  "jti": "24737160-89ec-4eed-be21-76784c434abd",
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

