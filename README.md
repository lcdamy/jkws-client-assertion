# SDID Netlify JWKS and Client Assertion Service

This project exposes two endpoints on Netlify:

```text
GET  /enrollment-creation-service/api/v1/requests/jwks
POST /client-assertion
```

Optional JWKS aliases are also enabled:

```text
GET /.well-known/jwks.json
GET /requests/jwks
```

## Important security note

The JWKS endpoint is safe to expose publicly because it returns only the public key.

The `/client-assertion` endpoint signs JWTs with your private key. Do not leave it open to the public. This implementation requires an `X-Assertion-Api-Key` header and the matching `ASSERTION_API_KEY` environment variable.

Do not commit `keys/private-*.pem` files to GitHub or Netlify.

## Required Netlify environment variables

Set these in Netlify Site settings → Environment variables.

```text
JWKS_KID=u5aw0txey983f0i97zh8hbhtqpahhael
JWKS_ALG=ES384
JWKS_USE=sig
CLIENT_ID=u5aw0txey983f0i97zh8hbhtqpahhael
TOKEN_ENDPOINT=https://auth.sdid.uat:8443/auth/oauth2/token
ASSERTION_EXPIRES_IN_SECONDS=300
ASSERTION_API_KEY=<long-random-secret>
JWKS_PRIVATE_KEY_PEM=<your-private-key-pem>
JWKS_PUBLIC_KEY_PEM=<your-public-key-pem>
```

When pasting PEM values into Netlify, use escaped newlines:

```text
-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
```

The code automatically converts `\n` into real newlines at runtime.

## Local setup

Install dependencies:

```bash
npm install
```

Create a local `.env` file from `.env.example`, then run:

```bash
npm run dev
```

Test JWKS locally:

```bash
curl "http://localhost:8888/enrollment-creation-service/api/v1/requests/jwks"
```

Create a client assertion locally:

```bash
curl -X POST "http://localhost:8888/client-assertion" \
  -H "Content-Type: application/json" \
  -H "X-Assertion-Api-Key: $ASSERTION_API_KEY" \
  -d '{
    "clientId": "u5aw0txey983f0i97zh8hbhtqpahhael",
    "audience": "https://auth.sdid.uat:8443/auth/oauth2/token",
    "expiresInSeconds": 300
  }'
```

## Netlify deployment

1. Create a new GitHub repository.
2. Push this project to the repository.
3. Create a new Netlify site from the repository.
4. Set all required environment variables in Netlify.
5. Deploy.

After deployment, your URLs will look like:

```text
https://<your-netlify-site>.netlify.app/enrollment-creation-service/api/v1/requests/jwks
https://<your-netlify-site>.netlify.app/client-assertion
```

## Token request example

```bash
CLIENT_ASSERTION=$(curl -s -X POST "https://<your-netlify-site>.netlify.app/client-assertion" \
  -H "Content-Type: application/json" \
  -H "X-Assertion-Api-Key: <ASSERTION_API_KEY>" \
  -d '{
    "clientId": "u5aw0txey983f0i97zh8hbhtqpahhael",
    "audience": "https://auth.sdid.uat:8443/auth/oauth2/token",
    "expiresInSeconds": 300
  }' | jq -r '.client_assertion')

curl -k -X POST "https://auth.sdid.uat:8443/auth/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=u5aw0txey983f0i97zh8hbhtqpahhael" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}"
```

Remember: the `audience` in the client assertion must match the token endpoint being called.
