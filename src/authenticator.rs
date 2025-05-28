use core::fmt;

use http::header::CONTENT_TYPE;
use http::method::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::http_client::HttpClient;
use crate::{token::AccessToken, ClientID};

#[derive(Error, Debug)]
pub enum AuthenticateError {
    #[error("unable to serialize request: `{0}`")]
    SerializeError(String),
    #[error("unable to deserialize token: `{0}`")]
    DeserializeError(String),
    #[error("identity server error: Status code: `{0}`, Reason: `{1}`")]
    HttpResponseError(u16, String),
    #[error("http transport error: `{0}`")]
    HttpTransportError(String),
}

pub trait Authenticator {
    fn authenticate(&self, req: Request) -> Result<TokenRetrievalResponse, AuthenticateError>;
}

/// The Authenticator is responsible for obtaining a valid JWT token from System Identity Service.
pub struct HttpAuthenticator<C: HttpClient> {
    /// HTTP client
    http_client: C,
    /// System Identity Service URL
    url: Url,
}

impl<C: HttpClient> HttpAuthenticator<C> {
    pub fn new(http_client: C, uri: Uri) -> Self {
        Self { http_client, uri }
    }
}

impl<C: HttpClient> fmt::Debug for HttpAuthenticator<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAuthenticator")
            .field("http_client", &"impl HttpClient")
            .field("uri", &self.uri)
            .finish()
    }
}

impl<C: HttpClient> Authenticator for HttpAuthenticator<C> {
    /// Executes a POST request to Authentication Server with the `Request` as a body and returns a `Response`.
    fn authenticate(&self, req: Request) -> Result<TokenRetrievalResponse, AuthenticateError> {
        let serialized_req = serde_json::to_string(&req).map_err(|e| {
            AuthenticateError::SerializeError(format!("serializing request body: {e}"))
        })?;

        let req = http::Request::builder()
            .method(Method::POST.as_str())
            .uri(self.url.as_str())
            .header(CONTENT_TYPE, "application/json")
            .body(serialized_req.into_bytes())
            .map_err(|e| AuthenticateError::SerializeError(format!("building request: {e}")))?;

        let response = self
            .http_client
            .send(req)
            .map_err(|e| AuthenticateError::HttpTransportError(e.to_string()))?;

        let body: String = String::from_utf8(response.body().clone()).map_err(|e| {
            AuthenticateError::DeserializeError(format!("invalid utf8 response: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(AuthenticateError::HttpResponseError(
                response.status().as_u16(),
                body,
            ));
        }

        serde_json::from_str(body.as_str())
            .map_err(|e| AuthenticateError::DeserializeError(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    ClientCredentials,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientAssertionType {
    #[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
    JwtBearer,
}

type ClientAssertion = String;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub client_id: ClientID,
    pub grant_type: GrantType,
    pub client_assertion_type: ClientAssertionType,
    pub client_assertion: ClientAssertion,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
/// Basic response coming from the NR token retrieval endpoint
pub struct TokenRetrievalResponse {
    pub access_token: AccessToken,
    /// The lifetime in seconds of the access token
    pub expires_in: u64,
    pub token_type: String,
}

#[cfg(test)]
pub mod test {
    use assert_matches::assert_matches;
    use http::Method;
    use mockall::mock;
    use url::Url;

    use super::{
        ClientAssertion, ClientAssertionType, ClientID, GrantType, HttpAuthenticator, Request,
        TokenRetrievalResponse,
    };
    use crate::{
        authenticator::{AuthenticateError, Authenticator},
        http_client::{tests::MockHttpClient, HttpClientError},
    };

    mock! {
         pub AuthenticatorMock {}

        impl Authenticator for AuthenticatorMock
        {
            fn authenticate(&self, req: Request) -> Result<TokenRetrievalResponse, AuthenticateError>;
        }
    }

    #[test]
    fn test_authentication_succeed() {
        let (request, expected_response) = fake_request_response();

        let expected_body = serde_json::to_string(&request).unwrap().as_bytes().to_vec();

        let http_response = http::Response::builder()
            .status(200)
            .body(
                serde_json::to_string(&expected_response)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();

        let mut http_client = MockHttpClient::new();
        http_client
            .expect_send()
            .once()
            .withf(move |req| {
                req.method().eq(&Method::POST)
                    && req.uri().to_string().eq(TEST_URL)
                    && req.body().eq(&expected_body)
            })
            .returning(move |_| Ok(http_response.clone()));

        let authenticator = HttpAuthenticator::new(http_client, fake_url());

        let response = authenticator.authenticate(request).unwrap();

        assert_eq!(response, expected_response);
    }

    #[test]
    fn test_authentication_http_client_transport_error() {
        let (request, _) = fake_request_response();

        let mut http_client = MockHttpClient::new();
        http_client
            .expect_send()
            .once()
            .returning(move |_| Err(HttpClientError::TransportError("foo".to_string())));

        let authenticator = HttpAuthenticator::new(http_client, fake_url());

        let error = authenticator.authenticate(request).unwrap_err();

        assert!(error.to_string().to_ascii_lowercase().contains("foo"));
        assert_matches!(error, AuthenticateError::HttpTransportError(_));
    }

    #[test]
    fn test_authentication_deserialize_error() {
        let (request, _) = fake_request_response();

        let http_response = http::Response::builder()
            .status(200)
            .body("this body should fail to be deserialized as Response".into())
            .unwrap();

        let mut http_client = MockHttpClient::new();
        http_client
            .expect_send()
            .once()
            .returning(move |_| Ok(http_response.clone()));

        let authenticator = HttpAuthenticator::new(http_client, fake_url());

        let error = authenticator.authenticate(request).unwrap_err();

        assert_matches!(error, AuthenticateError::DeserializeError(_));
    }

    #[test]
    fn test_authentication_server_response_error() {
        let (request, _) = fake_request_response();

        let http_response = http::Response::builder().status(500).body(vec![]).unwrap();

        let mut http_client = MockHttpClient::new();
        http_client
            .expect_send()
            .once()
            .returning(move |_| Ok(http_response.clone()));

        let authenticator = HttpAuthenticator::new(http_client, fake_url());

        let error = authenticator.authenticate(request).unwrap_err();

        assert_matches!(error, AuthenticateError::HttpResponseError(500, _));
    }

    #[test]
    fn test_request_serialization_and_deserialization() {
        let request = Request {
            client_assertion: ClientAssertion::from("fake_assertion"),
            client_assertion_type: ClientAssertionType::JwtBearer,
            client_id: ClientID::from("fake_id"),
            grant_type: GrantType::ClientCredentials,
        };
        let serialized = r#"{"client_id":"fake_id","grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":"fake_assertion"}"#;

        assert_eq!(serde_json::to_string(&request).unwrap(), serialized);
        assert_eq!(request, serde_json::from_str(serialized).unwrap());
    }

    const TEST_URL: &str = "https://newrelic.com/v1/authorize";

    fn fake_url() -> Url {
        Url::parse(TEST_URL).unwrap()
    }

    fn fake_request_response() -> (Request, TokenRetrievalResponse) {
        (
            Request {
                client_id: ClientID::from("fake_id"),
                grant_type: GrantType::ClientCredentials,
                client_assertion_type: ClientAssertionType::JwtBearer,
                client_assertion: ClientAssertion::from("fake_assertion"),
            },
            TokenRetrievalResponse {
                access_token: "fake_token".to_string(),
                token_type: "fake_token_type".to_string(),
                expires_in: 10,
            },
        )
    }
}
