use crate::http_client::{HttpClient as OauthHttpClient, HttpClientError as OauthHttpClientError};
use crate::parameters::DEFAULT_AUTHENTICATOR_TIMEOUT;
use http::Response as HttpResponse;
use http::{Request, Response};
use reqwest::blocking::{Client, Response as BlockingResponse};
use reqwest::tls::TlsInfo;

#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
}
impl HttpClient {
    pub fn new() -> Result<Self, HttpBuildError> {
        let builder = Client::builder()
            .use_rustls_tls()
            .tls_built_in_native_certs(true)
            .timeout(DEFAULT_AUTHENTICATOR_TIMEOUT)
            .connect_timeout(DEFAULT_AUTHENTICATOR_TIMEOUT);

        let client = builder
            .build()
            .map_err(|err| HttpBuildError::ClientBuilder(err.to_string()))?;

        Ok(Self { client })
    }

    fn send(&self, request: Request<Vec<u8>>) -> Result<HttpResponse<Vec<u8>>, HttpResponseError> {
        let req = self
            .client
            .request(request.method().into(), request.uri().to_string().as_str())
            .headers(request.headers().clone())
            .body(request.body().to_vec());

        let res = req
            .send()
            .map_err(|err| HttpResponseError::TransportError(err.to_string()))?;

        try_build_response(res)
    }
}

fn try_build_response(res: BlockingResponse) -> Result<HttpResponse<Vec<u8>>, HttpResponseError> {
    let status = res.status();
    let version = res.version();

    let tls_info = res.extensions().get::<TlsInfo>().cloned();

    let body: Vec<u8> = res
        .bytes()
        .map_err(|err| HttpResponseError::ReadingResponse(err.to_string()))?
        .into();

    let response_builder = http::Response::builder().status(status).version(version);

    let response_builder = if let Some(tls_info) = tls_info {
        response_builder.extension(tls_info)
    } else {
        response_builder
    };

    let response = response_builder
        .body(body)
        .map_err(|err| HttpResponseError::BuildingResponse(err.to_string()))?;

    Ok(response)
}

impl OauthHttpClient for HttpClient {
    fn send(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, OauthHttpClientError> {
        let response = self.send(req)?;

        Ok(response)
    }
}

impl From<HttpResponseError> for OauthHttpClientError {
    fn from(err: HttpResponseError) -> Self {
        match err {
            HttpResponseError::TransportError(msg) => OauthHttpClientError::TransportError(msg),
            HttpResponseError::BuildingResponse(msg) | HttpResponseError::ReadingResponse(msg) => {
                OauthHttpClientError::InvalidResponse(msg)
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HttpBuildError {
    #[error("could not build the http client: {0}")]
    ClientBuilder(String),
}

#[derive(thiserror::Error, Debug)]
enum HttpResponseError {
    #[error("could read response body: {0}")]
    ReadingResponse(String),
    #[error("could build response: {0}")]
    BuildingResponse(String),
    #[error("http transport error: `{0}`")]
    TransportError(String),
}
