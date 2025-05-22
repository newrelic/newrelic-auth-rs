use base64::{engine::general_purpose, Engine};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    StatusCode, Uri,
};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use thiserror::Error;

use crate::{http_client::HttpClient, token::AccessToken};

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

pub trait IAMClient {
    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError>;
}

/// Implementation of the IAMClient trait for a generic HTTP client.
pub struct HttpIAMClient<'a, C: HttpClient> {
    http_client: &'a C,
    name: String,
    organization_id: String,
    system_identity_creation_uri: &'a Uri,
    // other required data? Like access token retriever or auth mechanism? key pair generator?
}

impl<'a, C: HttpClient> HttpIAMClient<'a, C> {
    pub fn new(
        http_client: &'a C,
        name: String,
        organization_id: String,
        system_identity_creation_uri: &'a Uri,
    ) -> Self {
        Self {
            http_client,
            name,
            organization_id,
            system_identity_creation_uri,
        }
    }

    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        let pub_key_b64 = general_purpose::STANDARD.encode(pub_key);
        let json_body_string = json!({
            "query": format!(
                "mutation {{ systemIdentityCreate(name: \"{}\", organizationId: \"{}\", publicKey: \"{}\") {{ clientId, name }} }}",
                self.name, self.organization_id, pub_key_b64
            ),
        });
        let json_body = serde_json::to_vec(&json_body_string)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to encode JSON: {e}")))?;

        let request = http::Request::builder()
            .uri(self.system_identity_creation_uri)
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(json_body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to build request: {e}")))?;

        let response = self
            .http_client
            .send(request)
            .map_err(|e| IAMClientError::Transport(format!("Failed to send HTTP request: {e}")))?;
        let body = response.body();
        match response.status() {
            StatusCode::OK => {
                let system_identity_response: SystemIdentityCreationResponseData =
                    serde_json::from_slice(body).map_err(|e| {
                        IAMClientError::Decoder(format!("Failed to decode JSON: {e}"))
                    })?;
                Ok(system_identity_response)
            }
            status => Err(IAMClientError::Transport(format!(
                "Unsuccessful HTTP response: {status}. Body: {}",
                String::from_utf8_lossy(body)
            ))),
        }
    }
}

impl<C: HttpClient> IAMClient for HttpIAMClient<'_, C> {
    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        self.create_system_identity(token, pub_key)
    }
}

/// Represents the response data from the System Identity service
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationResponseData {
    pub client_id: String,
    pub name: String,
}

/// Manual implementation of Deserialize to handle nested structure that comes as response
/// from the System Identity service.
// TODO do we need this data at all?
impl<'de> Deserialize<'de> for SystemIdentityCreationResponseData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /*
        The JSON output that we expect has this form:

        ```json
        {
          "data": {
            "systemIdentityCreate": {
              "clientId": "some-client-id",
              "name": "some-name"
            }
          }
        }
        ```

        So we create the appropriate intermediate structures to
        deserialize it and return only the actual data we need.
        */

        #[derive(Deserialize)]
        struct Root {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(rename = "systemIdentityCreate")]
            system_identity_create: Inner,
        }
        #[derive(Deserialize)]
        struct Inner {
            #[serde(rename = "clientId")]
            client_id: String,
            name: String,
        }

        let deserialized_data = Root::deserialize(deserializer)?;
        Ok(SystemIdentityCreationResponseData {
            client_id: deserialized_data.data.system_identity_create.client_id,
            name: deserialized_data.data.system_identity_create.name,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use mockall::mock;

    use super::*;

    mock! {
        pub IAMClient {}

        impl IAMClient for IAMClient {
            fn create_system_identity(
                &self,
                token: &AccessToken,
                pub_key: &[u8],
            ) -> Result<SystemIdentityCreationResponseData, IAMClientError>;
        }
    }
}
