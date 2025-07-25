//! Example to retrieve a token using the `newrelic-auth-rs` library.
//!
//! This example demonstrates how to:
//! - Use a LocalPrivateKeySigner to sign the JWT
//! - Configure and use a token retriever with caching.
//! - Retrieve and print an access token.
//!

use dotenvy::dotenv;
use http::Uri;
use nr_auth::TokenRetriever;
use nr_auth::authenticator::HttpAuthenticator;
use nr_auth::http::client::HttpClient;
use nr_auth::http::config::{HttpConfig, ProxyConfig};
use nr_auth::jwt::signer::JwtSignerImpl;
use nr_auth::jwt::signer::local::LocalPrivateKeySigner;
use nr_auth::parameters::DEFAULT_AUTHENTICATOR_TIMEOUT;
use nr_auth::token_retriever::TokenRetrieverWithCache;
use std::env;
use std::path::{Path, PathBuf};

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
    let example_dir = Path::new("examples/retrieve-token");
    env::set_current_dir(example_dir).expect("Failed to change directory");

    dotenv()
        .map_err(|_| ".env file not found. Copy .env.dist file to .env and fill the variables")?;

    let private_key_path = env::var("PRIVATE_KEY_PATH")?;
    let token_url = env::var("TOKEN_URL")?;
    let client_id = env::var("CLIENT_ID")?;

    let signer = LocalPrivateKeySigner::try_from(PathBuf::from(private_key_path).as_path())?;
    let jwt_signer = JwtSignerImpl::Local(signer);

    let http_config = HttpConfig::new(
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        ProxyConfig::default(),
    );
    let client = HttpClient::new(http_config)?;
    let authenticator = HttpAuthenticator::new(client, Uri::try_from(&token_url)?);

    let token_retriever =
        TokenRetrieverWithCache::new_with_jwt_signer(client_id, authenticator, jwt_signer);
    let token = token_retriever.retrieve()?;

    println!("{}", token.access_token());

    Ok(())
}
