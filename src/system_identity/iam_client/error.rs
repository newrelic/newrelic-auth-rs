use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum IAMClientError {
    #[error("error creating system identity: `{0}`")]
    IAMClient(String),
    #[error("error computing the payload: `{0}`")]
    Encoder(String),
    #[error("error decoding the response payload: `{0}`")]
    Decoder(String),
    #[error("transport error: `{0}`")]
    Transport(String),
}
