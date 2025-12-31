use crate::http::config::HttpConfig;
use crate::http_client::{HttpClient as OauthHttpClient, HttpClientError as OauthHttpClientError};
use http::Request;
use http::{Response as HttpResponse, Response};
use reqwest::blocking::{Client, Response as BlockingResponse};
use reqwest::tls::TlsInfo;
use reqwest::{Certificate, Proxy};
use std::{
    fmt::Display,
    path::{Path, PathBuf},
};
use tracing::{debug, warn};

const CERT_EXTENSION: &str = "pem";
#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
}
impl HttpClient {
    pub fn new(http_config: HttpConfig) -> Result<Self, HttpBuildError> {
        let mut builder = Client::builder()
            .timeout(http_config.timeout)
            .connect_timeout(http_config.conn_timeout);

        let proxy_config = http_config.proxy;
        let proxy_url = proxy_config.url_as_string();
        if !proxy_url.is_empty() {
            let proxy = Proxy::all(proxy_url).map_err(|err| {
                HttpBuildError::ClientBuilder(format!("invalid proxy url: {err}"))
            })?;
            builder = builder.proxy(proxy);
            for cert in
                certs_from_paths(proxy_config.ca_bundle_file(), proxy_config.ca_bundle_dir())?
            {
                builder = builder.add_root_certificate(cert)
            }
        }

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

        debug!("Request body: {:?}", req);

        let res = req
            .send()
            .map_err(|err| HttpResponseError::TransportError(err.to_string()))?;

        try_build_response(res)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HttpBuildError {
    #[error("could not build the http client: {0}")]
    ClientBuilder(String),
    #[error("could not load certificates from {path}: {err}")]
    CertificateError { path: String, err: String },
}

/// Tries to extract certificates from the provided `ca_bundle_file` and `ca_bundle_dir` paths.
fn certs_from_paths(
    ca_bundle_file: &Path,
    ca_bundle_dir: &Path,
) -> Result<Vec<Certificate>, HttpBuildError> {
    let mut certs = Vec::new();
    // Certs from bundle file
    certs.extend(certs_from_file(ca_bundle_file)?);
    // Certs from bundle dir
    for path in cert_paths_from_dir(ca_bundle_dir)? {
        certs.extend(certs_from_file(&path)?)
    }
    Ok(certs)
}

/// Returns all certs bundled in the file corresponding to the provided path.
fn certs_from_file(path: &Path) -> Result<Vec<Certificate>, HttpBuildError> {
    if path.as_os_str().is_empty() {
        return Ok(Vec::new());
    }
    let buf = std::fs::read(path).map_err(|err| certificate_error(path, err))?;
    let certs = Certificate::from_pem_bundle(&buf).map_err(|err| certificate_error(path, err))?;
    Ok(certs)
}

/// Returns all paths to be considered to load certificates under the provided directory path.
fn cert_paths_from_dir(dir_path: &Path) -> Result<Vec<PathBuf>, HttpBuildError> {
    if dir_path.as_os_str().is_empty() {
        return Ok(Vec::new());
    }
    let dir_entries =
        std::fs::read_dir(dir_path).map_err(|err| certificate_error(dir_path, err))?;
    // filter readable file with 'cert' extension
    let paths = dir_entries.inspect(|entry_res| if let Err(err) = entry_res {
        warn!(%err, directory=dir_path.to_string_lossy().to_string(), "Unreadable path when loading certificates from directory");
    }).flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == CERT_EXTENSION))
        .map(|entry| entry.path());
    Ok(paths.collect())
}

/// Helper to build a [HttpBuildError::CertificateError] more concisely.
fn certificate_error<E: Display>(path: &Path, err: E) -> HttpBuildError {
    HttpBuildError::CertificateError {
        path: path.to_string_lossy().into(),
        err: err.to_string(),
    }
}

fn try_build_response(res: BlockingResponse) -> Result<HttpResponse<Vec<u8>>, HttpResponseError> {
    let status = res.status();
    let version = res.version();

    debug!("Response status: {:?}", status);
    debug!("Response version: {:?}", version);

    let tls_info = res.extensions().get::<TlsInfo>().cloned();
    debug!("TLS info: {:?}", tls_info);

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

    debug!("Response successfully built");

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
enum HttpResponseError {
    #[error("could not read response body: {0}")]
    ReadingResponse(String),
    #[error("could not build response: {0}")]
    BuildingResponse(String),
    #[error("http transport error: `{0}`")]
    TransportError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::config::ProxyConfig;
    use crate::parameters::DEFAULT_AUTHENTICATOR_TIMEOUT;
    use assert_matches::assert_matches;
    use http::StatusCode;
    use httpmock::MockServer;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    const INVALID_TESTING_CERT: &str =
        "-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----";

    fn valid_testing_cert() -> String {
        let subject_alt_names = vec!["localhost".to_string()];
        let rcgen::CertifiedKey {
            cert,
            signing_key: _,
        } = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        cert.pem()
    }

    #[test]
    fn test_http_client_proxy() {
        // Target server simulating the real service
        let expected_response = "OK!";
        let target_server = MockServer::start();
        target_server.mock(|when, then| {
            when.any_request();
            then.status(200).body(expected_response);
        });
        // Proxy server will request the target server, allowing requests to that host only
        let proxy_server = MockServer::start();
        proxy_server.proxy(|rule| {
            rule.filter(|when| {
                when.host(target_server.host()).port(target_server.port());
            });
        });
        // Build a http client using the proxy configuration
        let http_config = HttpConfig::new(
            DEFAULT_AUTHENTICATOR_TIMEOUT,
            DEFAULT_AUTHENTICATOR_TIMEOUT,
            ProxyConfig::from_url(proxy_server.base_url()),
        );
        let agent = HttpClient::new(http_config)
            .unwrap_or_else(|e| panic!("Unexpected error building the client {e}"));
        let resp = agent
            .client
            .get(target_server.url("/path").as_str())
            .send()
            .unwrap_or_else(|e| panic!("Error performing request: {e}"));
        // Check responses from the target server
        assert_eq!(resp.status(), StatusCode::OK.as_u16());
        assert_eq!(resp.text().unwrap(), expected_response.to_string())
    }

    #[test]
    fn test_certs_from_paths_no_certificates() {
        let ca_bundle_file = PathBuf::default();
        let ca_bundle_dir = PathBuf::default();
        let certificates = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap();
        assert_eq!(certificates.len(), 0);
    }

    #[test]
    fn test_certs_from_paths_non_existing_certificate_path() {
        let ca_bundle_file = PathBuf::from("non-existing.pem");
        let ca_bundle_dir = PathBuf::default();
        let err = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap_err();
        assert_matches!(err, HttpBuildError::CertificateError { .. });

        let ca_bundle_file = PathBuf::default();
        let ca_bundle_dir = PathBuf::from("non-existing-dir.pem");
        let err = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap_err();
        assert_matches!(err, HttpBuildError::CertificateError { .. });
    }

    #[test]
    fn test_certs_from_paths_invalid_certificate_file() {
        let dir = tempdir().unwrap();
        let ca_bundle_file = dir.path().join("invalid_cert.pem");
        let mut file = File::create(&ca_bundle_file).unwrap();
        writeln!(file, "{INVALID_TESTING_CERT}").unwrap();

        let ca_bundle_dir = PathBuf::default();
        let err = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap_err();
        assert_matches!(err, HttpBuildError::CertificateError { .. });
    }

    #[test]
    fn test_certs_from_paths_valid_certificate_file() {
        let dir = tempdir().unwrap();
        let ca_bundle_file = dir.path().join("valid_cert.pem");
        let mut file = File::create(&ca_bundle_file).unwrap();
        writeln!(file, "{}", valid_testing_cert()).unwrap();

        let ca_bundle_dir = PathBuf::default();
        let certificates = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap();
        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn test_certs_from_paths_dir_poining_to_file() {
        let dir = tempdir().unwrap();
        let ca_bundle_dir = dir.path().join("valid_cert.pem");
        let mut file = File::create(&ca_bundle_dir).unwrap();
        writeln!(file, "{}", valid_testing_cert()).unwrap();

        let ca_bundle_file = PathBuf::default();
        let err = certs_from_paths(&ca_bundle_file, &ca_bundle_dir).unwrap_err();
        assert_matches!(err, HttpBuildError::CertificateError { .. });
    }

    #[test]
    fn test_certs_from_paths_valid_certificate_dir() {
        let dir = tempdir().unwrap();
        let ca_bundle_dir = dir.path();

        // Valid cert file
        let file_path = dir.path().join("valid_cert.pem");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{}", valid_testing_cert()).unwrap();
        // Empty cert file
        let file_path = dir.path().join("empty_cert.pem");
        let _ = File::create(&file_path).unwrap();
        // Unrelated file
        let file_path = dir.path().join("other-file.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "some content").unwrap();
        // Invalid cert in no cert-file
        let file_path = dir.path().join("invalid-cert.bk");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{INVALID_TESTING_CERT}").unwrap();

        let ca_bundle_file = PathBuf::default();
        let certificates = certs_from_paths(&ca_bundle_file, ca_bundle_dir).unwrap();
        assert_eq!(certificates.len(), 1);
    }
}
