use http::{Request, Response};

#[derive(thiserror::Error, Debug)]
pub enum HttpClientError {
    /// Represents an http transport crate error.
    #[error("HTTP Transport error: `{0}`")]
    TransportError(String),
    /// Unsuccessful HTTP response.
    #[error("Status code: `{0}` Canonical reason: `{1}`")]
    UnsuccessfulResponse(u16, String),
    /// Represents a decode error.
    #[error("error decoding: `{0}`")]
    DecoderError(String),
    /// Represents an encode error.
    #[error("error encoding `{0}`")]
    EncoderError(String),
    /// Represents a compression error.
    #[error("error compressing data: `{0}`")]
    CompressionError(String),
    /// Represents an unexpected response.
    #[error("invalid http response: `{0}`")]
    InvalidResponse(String),
}

/// A synchronous trait that defines the internal methods for HTTP clients.
pub trait HttpClient {
    /// A synchronous function sends a request. The method and url are defined inside the Request.
    fn send(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, HttpClientError>;
}

// Accept closures as HttpClient implementations
impl<F> HttpClient for F
where
    F: Fn(Request<Vec<u8>>) -> Result<Response<Vec<u8>>, HttpClientError>,
{
    fn send(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, HttpClientError> {
        self(req)
    }
}

#[cfg(test)]
pub(super) mod tests {

    use super::*;

    use mockall::{mock, predicate::*};

    // Create a mock for the HttpClient trait using the mock! macro
    mock! {
        pub HttpClient {}

        impl HttpClient for HttpClient {
            fn send(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, HttpClientError>;
        }
    }
}
