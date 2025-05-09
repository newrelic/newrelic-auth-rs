Example to sign a JWT token using a local private key

It assumes that an identity already exists.

It requires a .env file with the following environment variables set:
```
PRIVATE_KEY_PATH=""
CLIENT_ID=""
```

Run with:
```shell
cargo run --example jwt-signer-local
```
