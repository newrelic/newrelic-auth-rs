Example to retrieve a token using a private key and client_id.

It assumes that an identity already exists.

It requires a .env file with the following environment variables set:
```
PRIVATE_KEY_PATH=""
CLIENT_ID=""
TOKEN_URL="https://system-identity-oauth.service.newrelic.com/oauth2/token"
```

Run with:
```shell
cargo run --example retrieve-token
```
