use http::Uri;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT Claims supported by the service.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// Issuer. Client ID will be used here.
    pub(crate) iss: String,
    /// Subject (whom token refers to). Client ID will be used here.
    pub(crate) sub: String,
    /// Audience. Full URL to the token generation endpoint.
    pub(crate) aud: String,
    /// JWT ID. Must not be reused. Using UID.
    pub(crate) jti: Uuid,
    /// Expiration time (as UTC timestamp).
    pub(crate) exp: u64,
}

impl Clone for Claims {
    /// Clone the Claims instance. This implies a new UUID will be generated as its `jti`.
    fn clone(&self) -> Self {
        Self {
            iss: self.iss.clone(),
            sub: self.sub.clone(),
            aud: self.aud.clone(),
            jti: Uuid::now_v7(),
            exp: self.exp,
        }
    }
}

impl Claims {
    /// Create a new Claims instance
    pub fn new(client_id: String, aud: Uri, exp: u64) -> Self {
        Self {
            iss: client_id.clone(),
            sub: client_id,
            aud: aud.to_string(),
            jti: Uuid::now_v7(), // Non-reusable JWT ID
            exp,
        }
    }
}
