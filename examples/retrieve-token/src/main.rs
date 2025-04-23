use dotenvy::dotenv;
use http_client::client::HttpClient;
use nr_auth::authenticator::HttpAuthenticator;
use nr_auth::jwt::signer::local::LocalPrivateKeySigner;
use nr_auth::jwt::signer::JwtSignerImpl;
use nr_auth::token_retriever::TokenRetrieverWithCache;
use nr_auth::TokenRetriever;
use std::env;
use std::path::PathBuf;
use url::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv()
        .map_err(|_| ".env file not found. Copy .env.dist file to .env and fill the variables")?;

    let private_key_path = env::var("PRIVATE_KEY_PATH")?;
    let token_url = env::var("TOKEN_URL")?;
    let client_id = env::var("CLIENT_ID")?;

    let signer = LocalPrivateKeySigner::try_from(PathBuf::from(private_key_path).as_path())?;
    let jwt_signer = JwtSignerImpl::Local(signer);

    let client = HttpClient::new()?;
    let authenticator = HttpAuthenticator::new(client, Url::parse(&token_url)?);

    let token_retriever = TokenRetrieverWithCache::new(client_id, jwt_signer, authenticator);
    let token = token_retriever.retrieve()?;

    println!("{}", token.access_token());

    Ok(())
}
