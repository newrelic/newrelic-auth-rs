//! Full example to generate an L1 System Identity using the `newrelic-auth-rs` library.
mod client;

use client::HttpClient;
use dotenvy::dotenv;

use nr_auth::system_identity::client_input::{
    AuthMethod, ClientSecret, PrivateKeyPem, SystemIdentityCreationMetadata,
};
use nr_auth::system_identity::environment::SystemIdentityCreationEnvironment;
use nr_auth::system_identity::generator::L1SystemIdentityGenerator;
use nr_auth::system_identity::iam_client::http_iam_client::HttpIAMClient;
use nr_auth::system_identity::iam_client::http_token_retriever::HttpTokenRetriever;
use nr_auth::system_identity::output_platform::AuthOutputPlatform;

use std::path::{Path, PathBuf};
use std::{env, fs, io};

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
    let example_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(env!("CARGO_BIN_NAME"));
    env::set_current_dir(&example_dir).expect("Failed to change directory");

    dotenv().map_err(|e| {
        format!(".env file not found. Copy .env.dist file to .env and fill the variables: {e}")
    })?;

    let client_id = env::var("CLIENT_ID")?;
    let organization_id = env::var("ORGANIZATION_ID")?;
    // Has a client secret been set?
    let client_secret_auth_method = env::var("CLIENT_SECRET")
        .map(ClientSecret::from)
        .map(AuthMethod::ClientSecret);

    // Has a private key been set to a valid path?
    let private_key_auth_method = env::var("PRIVATE_KEY_PATH")
        .map_err(io::Error::other)
        .map(PathBuf::from)
        .and_then(|path| fs::read(&path))
        .map(PrivateKeyPem::from)
        .map(AuthMethod::PrivateKey);

    // Select one of the two and unwrap. Switch to change priority like this:
    // let auth_method = private_key_auth_method.or(client_secret_auth_method)?;
    let auth_method = client_secret_auth_method.or(private_key_auth_method)?;

    let environment = SystemIdentityCreationEnvironment::Staging;

    let system_identity_creation_metadata = SystemIdentityCreationMetadata {
        name: format!("example-{}", env!("CARGO_BIN_NAME")),
        organization_id,
        client_id,
        auth_method,
        environment,
        output_platform: AuthOutputPlatform::LocalPrivateKeyPath(PathBuf::from("private_key.pem")),
    };

    let http_client = HttpClient::new()?;
    let http_token_retriever =
        HttpTokenRetriever::new(http_client.clone(), &system_identity_creation_metadata)?;

    let iam_client = HttpIAMClient::new(
        http_client,
        http_token_retriever,
        system_identity_creation_metadata.to_owned(),
    );

    let system_identity_generator = L1SystemIdentityGenerator { iam_client };

    let result = system_identity_generator.generate()?;

    println!("System Identity created successfully: {result:?}");

    Ok(())
}
