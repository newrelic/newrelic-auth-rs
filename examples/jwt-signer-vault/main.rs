//! Example to sign a JWT token using Vault
use std::env;
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{TimeDelta, Utc};
use dotenvy::dotenv;
use http::Uri;
use jsonwebtoken::{Algorithm, Header};
use sha2::{Digest, Sha512};
use tracing::debug;
use vaultrs::api::transit::MarshalingAlgorithm;
use vaultrs::api::transit::requests::SignDataRequestBuilder;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::transit::data::sign;

use nr_auth::jwt::claims::Claims;

/// A signed JWT should live enough for the System Identity Service to consume it.
const DEFAULT_JWT_CLAIM_EXP: TimeDelta = TimeDelta::seconds(180);
/// The "aud" (audience) claim identifies the recipients that the JWT is intended for.
const DEFAULT_AUDIENCE: &str = "https://www.newrelic.com/";

/// Main function to sign a JWT token with Vault
/// It requires the following environment variables to be set:
///
/// VAULT_ADDRESS: Vault service address
/// VAULT_TOKEN: Token to access Vault
/// CLIENT_ID: Identity client_id
/// TRANSIT_KEY_NAME: Transit Private key name
///
/// # Errors
/// This function returns an error if:
/// - The `.env` file is missing or cannot be loaded.
/// - Required environment variables are not set.
/// - The JWT signing process fails.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set the current directory to the example's path
    let example_dir = Path::new("examples/jwt-signer-vault");
    env::set_current_dir(example_dir).expect("Failed to change directory");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    dotenv()
        .map_err(|_| ".env file not found. Copy .env.dist file to .env and fill the variables")?;

    let vault_addr = env::var("VAULT_ADDRESS")?;
    let token = env::var("VAULT_TOKEN")?;
    let key_name = env::var("TRANSIT_KEY_NAME")?;
    let client_id = env::var("SYSTEM_IDENTITY_CLIENT_ID")?;

    // Create a vault client
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_addr)
            .token(token)
            .build()
            .map_err(|e| format!("cannot build vault client settings {}", e))?,
    )
    .map_err(|e| format!("cannot build vault client {}", e))?;

    // Build claims
    let url = Uri::try_from(DEFAULT_AUDIENCE).expect("constant valid url value");
    let expires_at = Utc::now() + DEFAULT_JWT_CLAIM_EXP;
    let timestamp = expires_at
        .timestamp()
        .try_into()
        .map_err(|_| "converting token expiration time")?;
    let claims = Claims::new(client_id, url, timestamp);

    // Based on https://github.com/alexadamm/jwt-vault-go/blob/main/pkg/vault/vault.go#L245
    let encoded_header = base64_encode(serde_json::to_vec(&Header::new(Algorithm::RS512))?);
    let encoded_claims = base64_encode(serde_json::to_vec(&claims)?);
    let input = format!("{}.{}", encoded_header, encoded_claims);
    // Hash the input data
    let mut hasher = Sha512::new();
    hasher.update(input);
    let digest = hasher.finalize().as_slice().to_vec();
    let hashed_input = base64_encode(digest);
    debug!("hashed_input: {}", hashed_input);

    let response = sign(
        &client,
        "transit",
        key_name.as_str(),
        hashed_input.as_str(),
        Some(SignDataRequestBuilder::default().marshaling_algorithm(MarshalingAlgorithm::Jws)),
    )
    .await
    .map_err(|e| format!("cannot sign data {}", e))?;

    println!("{}", response.signature);

    Ok(())
}

fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    BASE64_STANDARD.encode(input)
}
