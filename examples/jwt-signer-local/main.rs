//! Example to sign a JWT token using a local private key
use std::env;
use std::path::{Path, PathBuf};

use chrono::{TimeDelta, Utc};
use dotenvy::dotenv;

use http::Uri;
use nr_auth::jwt::claims::Claims;
use nr_auth::jwt::signer::local::LocalPrivateKeySigner;
use nr_auth::jwt::signer::{JwtSigner, JwtSignerImpl};

/// A signed JWT should live enough for the System Identity Service to consume it.
const DEFAULT_JWT_CLAIM_EXP: TimeDelta = TimeDelta::seconds(180);
/// The "aud" (audience) claim identifies the recipients that the JWT is intended for.
const DEFAULT_AUDIENCE: &str = "https://www.newrelic.com/";

/// Main function to retrieve and print an access token.
/// It requires the following environment variables to be set:
///
/// PRIVATE_KEY_PATH: Absolute path to the private key associated with the identity
/// TOKEN_URL: Token verification URL
/// CLIENT_ID: Identity client_id
///
/// # Errors
/// This function returns an error if:
/// - The `.env` file is missing or cannot be loaded.
/// - Required environment variables are not set.
/// - Any of the components (e.g., signer, client, authenticator) fail to initialize.
/// - The token retrieval process fails.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set the current directory to the example's path
    let example_dir = Path::new("examples/jwt-signer-local");
    env::set_current_dir(example_dir).expect("Failed to change directory");

    dotenv()
        .map_err(|_| ".env file not found. Copy .env.dist file to .env and fill the variables")?;

    let private_key_path = env::var("PRIVATE_KEY_PATH")?;
    let client_id = env::var("CLIENT_ID")?;
    let url = Uri::try_from(DEFAULT_AUDIENCE).expect("constant valid url value");

    let signer = LocalPrivateKeySigner::try_from(PathBuf::from(private_key_path).as_path())?;
    let jwt_signer = JwtSignerImpl::Local(signer);

    let expires_at = Utc::now() + DEFAULT_JWT_CLAIM_EXP;

    let timestamp = expires_at
        .timestamp()
        .try_into()
        .map_err(|_| "converting token expiration time")?;

    let claims = Claims::new(client_id, url, timestamp);
    let signed_jwt = jwt_signer
        .sign(claims)
        .map_err(|e| format!("signing token failed: {}", e))?;

    println!("{}", signed_jwt.value());

    Ok(())
}
