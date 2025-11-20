//! Full example to generate an L1 System Identity using the `newrelic-auth-rs` library.
use dotenvy::dotenv;

use nr_auth::authenticator::HttpAuthenticator;
use nr_auth::jwt::signer::JwtSignerImpl;
use nr_auth::jwt::signer::local::LocalPrivateKeySigner;

use nr_auth::TokenRetriever;
use nr_auth::key::PrivateKeyPem;
use nr_auth::system_identity::generator::L1SystemIdentityGenerator;
use nr_auth::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
use nr_auth::system_identity::input_data::environment::NewRelicEnvironment;
use nr_auth::system_identity::input_data::output_platform::OutputPlatform;
use nr_auth::system_identity::input_data::{SystemIdentityCreationMetadata, SystemIdentityInput};
use nr_auth::token_retriever::TokenRetrieverWithCache;

use nr_auth::http::client::HttpClient;
use nr_auth::http::config::{HttpConfig, ProxyConfig};
use nr_auth::parameters::DEFAULT_AUTHENTICATOR_TIMEOUT;
use nr_auth::system_identity::iam_client::http::HttpIAMClient;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set the current directory to the example's path
    let example_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(env!("CARGO_BIN_NAME"));
    env::set_current_dir(&example_dir).expect("Failed to change directory");

    // Load environment variables from an .env file if present
    let _ = dotenv().inspect_err(|e| {
        println!(".env file not found. Copy .env.dist file to .env and fill the variables: {e}");
    });

    // Assert that required environment variables are set
    let Ok(client_id) = env::var("CLIENT_ID") else {
        panic!("Environment variable CLIENT_ID is not set.")
    };
    let Ok(organization_id) = env::var("ORGANIZATION_ID") else {
        panic!("Environment variable ORGANIZATION_ID is not set.")
    };
    let Ok(environment) = env::var("NR_ENVIRONMENT") else {
        panic!("Environment variable NR_ENVIRONMENT is not set.")
    };
    let Ok(environment) = NewRelicEnvironment::try_from(environment.as_str()) else {
        panic!("Invalid environment value: NR_ENVIRONMENT={environment}")
    };

    // Determine the authentication method to use depending on available environment variables
    // Has a client secret been set?
    let client_secret_auth_method = env::var("CLIENT_SECRET")
        .map_err(|e| {
            io::Error::other(format!(
                "Attempt to retrieve env var CLIENT_SECRET had error {e}"
            ))
        })
        .map(ClientSecret::from)
        .map(AuthMethod::ClientSecret)
        .inspect_err(|e| {
            println!("No client secret provided, falling back to other auth methods: {e}");
        });

    // Has a private key been passed as a valid path or PEM file content?
    let private_key_path_auth_method = env::var("PRIVATE_KEY_PATH")
        .map_err(|e| {
            io::Error::other(format!(
                "Attempt to retrieve env var PRIVATE_KEY_PATH had error {e}"
            ))
        })
        .map(PathBuf::from)
        .and_then(|path| fs::read(&path))
        .map(PrivateKeyPem::from)
        .map(AuthMethod::PrivateKey)
        .inspect_err(|e| {
            println!("No private key path provided, falling back to other auth methods: {e}");
        });
    let private_key_pem_auth_method = env::var("PRIVATE_KEY_PEM")
        .map_err(|e| {
            io::Error::other(format!(
                "Attempt to retrieve env var PRIVATE_KEY_PEM had error {e}"
            ))
        })
        .map(|s| s.as_bytes().to_vec())
        .map(PrivateKeyPem::from)
        .map(AuthMethod::PrivateKey);

    // Select one and unwrap. Switch to change priority like this:
    // let auth_method = private_key_auth_method.or(client_secret_auth_method)?;
    let auth_method = client_secret_auth_method
        .or(private_key_path_auth_method)
        .or(private_key_pem_auth_method)?;

    println!("Using auth method: {auth_method:?}");

    let key_path = env::current_dir()?;
    let output_platform = OutputPlatform::LocalPrivateKeyPath(key_path.to_owned());
    let http_config = HttpConfig::new(
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        ProxyConfig::default(),
    );
    let http_client = HttpClient::new(http_config)?;
    let http_authenticator =
        HttpAuthenticator::new(http_client.clone(), environment.token_renewal_endpoint());

    let token = match &auth_method {
        AuthMethod::ClientSecret(client_secret) => TokenRetrieverWithCache::new_with_secret(
            client_id.to_owned(),
            http_authenticator,
            client_secret.to_owned(),
        )
        .retrieve()?,
        AuthMethod::PrivateKey(private_key_pem) => {
            let jwt_signer =
                JwtSignerImpl::Local(LocalPrivateKeySigner::try_from(private_key_pem)?);
            TokenRetrieverWithCache::new_with_jwt_signer(
                client_id.to_owned(),
                http_authenticator,
                jwt_signer,
            )
            .retrieve()?
        }
    };

    let system_identity_creation_metadata = SystemIdentityCreationMetadata {
        system_identity_input: SystemIdentityInput {
            organization_id,
            client_id,
        },
        name: format!("test-{}", env!("CARGO_BIN_NAME")).into(),
        environment,
        output_platform,
    };

    let iam_client = HttpIAMClient::new(http_client, system_identity_creation_metadata.to_owned());

    let system_identity_generator = L1SystemIdentityGenerator { iam_client };

    let result = system_identity_generator.generate(&token)?;

    // Use `reveal` on the client secret to get the string value
    println!("System Identity created successfully: {result:?}");

    Ok(())
}
