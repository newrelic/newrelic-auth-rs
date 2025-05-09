Example to sign a JWT token using Vault Transit. 

Based on https://github.com/alexadamm/jwt-vault-go 

It assumes that an identity already exists.

You can run a Vault instance in k8s using:
```shell
tilt up -f examples/jwt-signer-vault/vault-tilt/Tiltfile
```

It requires a .env file with the following environment variables set:
```
VAULT_TOKEN=""
TRANSIT_KEY_NAME=""
SYSTEM_IDENTITY_CLIENT_ID=""
VAULT_ADDRESS=""
```

Run with:
```shell
cargo run --example jwt-signer-vault
```
