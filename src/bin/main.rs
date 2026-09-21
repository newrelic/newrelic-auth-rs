use clap::Parser;
use nr_auth::audit;
use nr_auth::authenticator::HttpAuthenticator;
use nr_auth::commands::create::CreateCommand;
use nr_auth::commands::retrieve_token::RetrieveTokenCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::http::config::HttpConfig;
use nr_auth::parameters::{
    AuthenticationArgs, Commands, DEFAULT_AUTHENTICATOR_TIMEOUT, IdentityCreationCredential,
    IdentityType, IdentityTypeBootstrap, OutputTokenFormat, ProxyArgs, build_proxy_args,
    create_metadata_for_bootstrap_identity_creation, create_metadata_for_identity_creation,
    create_metadata_for_token_retrieve, extract_api_key_from_bootstrap,
    extract_identity_creation_credential, select_output_platform, select_output_platform_bootstrap,
};
use nr_auth::rate_limit::{LocalRateLimiter, RateLimitError};
use nr_auth::system_identity::iam_client::http::{HttpIAMClient, IAMAuthCredential};
use std::error::Error;

#[derive(Parser, Debug)]
#[command(name = "newrelic-auth-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Global proxy arguments
    #[command(flatten)]
    proxy_args: ProxyArgs,
}
fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let cli_command = Cli::parse();

    let http_client = init_http_client(cli_command.proxy_args)?;

    match cli_command.command {
        Commands::CreateIdentity { identity_type } => {
            handle_create_identity_command(http_client, identity_type)
        }
        Commands::CreateBootstrapIdentity { identity_type } => {
            handle_create_bootstrap_identity_command(http_client, identity_type)
        }
        Commands::Authenticate {
            auth_args,
            output_token_format,
        } => handle_authenticate_command(http_client, auth_args, output_token_format),
    }
}

fn handle_create_identity_command(
    http_client: HttpClient,
    identity_type: IdentityType,
) -> Result<(), Box<dyn Error>> {
    let credential = extract_identity_creation_credential(&identity_type)?;

    let iam_auth_credential = match credential {
        IdentityCreationCredential::BearerToken(token) => IAMAuthCredential::BearerToken(token),
        IdentityCreationCredential::ApiKey(api_key) => IAMAuthCredential::ApiKey(api_key),
    };

    let meta = create_metadata_for_identity_creation(&identity_type);
    let iam_client = &HttpIAMClient::new(http_client, meta);
    let create_command = CreateCommand::new(iam_client);

    let system_identity = match identity_type {
        IdentityType::Secret(_) => {
            create_command.create_l1_with_credential(&iam_auth_credential)?
        }
        IdentityType::Key(key_args) => {
            let output_platform = select_output_platform(key_args);
            create_command.create_l2_with_credential(&output_platform, &iam_auth_credential)?
        }
    };

    println!("{}", serde_json::to_string(&system_identity)?);
    Ok(())
}

fn handle_create_bootstrap_identity_command(
    http_client: HttpClient,
    identity_type: IdentityTypeBootstrap,
) -> Result<(), Box<dyn Error>> {
    let metadata = create_metadata_for_bootstrap_identity_creation(&identity_type);
    let auth_credential = IAMAuthCredential::ApiKey(extract_api_key_from_bootstrap(&identity_type));

    let iam_client = &HttpIAMClient::new(http_client, metadata);
    let create_command = CreateCommand::new(iam_client);

    let system_identity = match identity_type {
        IdentityTypeBootstrap::Secret(_) => {
            create_command.create_l1_with_credential(&auth_credential)?
        }
        IdentityTypeBootstrap::Key(key_args) => {
            let output_platform = select_output_platform_bootstrap(key_args);
            create_command.create_l2_with_credential(&output_platform, &auth_credential)?
        }
    };

    iam_client.add_identity_to_nr_control_group_by_id(&system_identity.id, &auth_credential)?;

    audit::log_bootstrap_identity_created(&system_identity);

    println!("{}", serde_json::to_string(&system_identity)?);
    Ok(())
}

fn handle_authenticate_command(
    http_client: HttpClient,
    auth_input_args: AuthenticationArgs,
    output_token_format: OutputTokenFormat,
) -> Result<(), Box<dyn Error>> {
    let max_tokens_per_hour = auth_input_args.max_tokens_per_hour();

    let meta =
        create_metadata_for_token_retrieve(auth_input_args).map_err(|e| format!("Error: {e}"))?;

    if let Some(limit) = max_tokens_per_hour {
        let limiter = LocalRateLimiter::new(LocalRateLimiter::default_state_dir());
        match limiter.check_and_record(&meta.client_id, limit) {
            Ok(()) => {}
            Err(RateLimitError::Exceeded { count, limit }) => {
                audit::log_rate_limited(&meta.client_id, count, limit);
                return Err(format!(
                    "Error: advisory rate limit exceeded ({count} token(s) already issued for \
                     this parent in the last hour, limit {limit}). This is a local, \
                     single-machine advisory limit, not a server-side one."
                )
                .into());
            }
            // The limiter's own local storage failed for an unrelated reason (e.g. disk
            // full, permissions). This is advisory tooling, not a security boundary, so a
            // storage failure here warns and proceeds rather than blocking a legitimate
            // authentication on a bookkeeping problem.
            Err(e) => {
                tracing::warn!(
                    parent_client_id = %meta.client_id,
                    error = %e,
                    "advisory rate limit check failed; proceeding without enforcing it for this call"
                );
            }
        }
    }

    let http_authenticator =
        HttpAuthenticator::new(http_client, meta.environment.token_renewal_endpoint());
    let retrieve_token_command = RetrieveTokenCommand::new(http_authenticator);
    let token = match retrieve_token_command.retrieve_token(&meta) {
        Ok(token) => {
            audit::log_token_issued(&meta.client_id, &meta.environment);
            token
        }
        Err(e) => {
            audit::log_token_issuance_failed(&meta.client_id, &meta.environment, &e.to_string());
            return Err(format!("Error: {e}").into());
        }
    };
    match output_token_format {
        OutputTokenFormat::PLAIN => {
            println!("{}", token.access_token());
            Ok(())
        }
        OutputTokenFormat::JSON => {
            let output = serde_json::to_string_pretty(&token)?;
            println!("{output}");
            Ok(())
        }
    }
}

fn init_http_client(proxy_args: ProxyArgs) -> Result<HttpClient, Box<dyn Error>> {
    let proxy_config = build_proxy_args(proxy_args)?;

    let http_config = HttpConfig::new(
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        DEFAULT_AUTHENTICATOR_TIMEOUT,
        proxy_config,
    );

    HttpClient::new(http_config).map_err(|e| format!("error creating HTTP client: {e}").into())
}
