use base64::{engine::general_purpose, Engine};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    StatusCode, Uri,
};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use thiserror::Error;

use crate::{
    http_client::{HttpClient, HttpClientError},
    token::AccessToken,
};

#[derive(Debug, Clone, Error)]
pub enum IAMClientError {
    #[error("error creating system identity: `{0}`")]
    IAMClientError(String),
}

pub trait IAMClient {
    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError>;
}

/// Implementation of the IAMClient trait for a generic HTTP client.
pub struct HttpIAMClientImpl<'a, C: HttpClient> {
    http_client: &'a C,
    name: String,
    organization_id: String,
    system_identity_creation_uri: &'a Uri,
    // other required data? Like access token retriever or auth mechanism? key pair generator?
}

impl<'a, C: HttpClient> HttpIAMClientImpl<'a, C> {
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

    fn system_identity_from_token(
        http_client: &C,
        name: &str,
        organization_id: &str,
        token: &str,    // type
        pub_key: &[u8], // type and provenance, other modes accepted?
        system_identity_creation_uri: &Uri,
    ) -> Result<SystemIdentityCreationResponseData, HttpClientError> {
        let pub_key_b64 = general_purpose::STANDARD.encode(pub_key);
        let json_body_string = json!({
            "query": format!(
                "mutation {{ systemIdentityCreate(name: \"{}\", organizationId: \"{}\", publicKey: \"{}\") {{ clientId, name }} }}",
                name, organization_id, pub_key_b64
            ),
        });
        let json_body = serde_json::to_vec(&json_body_string)
            .map_err(|e| HttpClientError::EncoderError(format!("Failed to encode JSON: {e}")))?;

        let request = http::Request::builder()
            .uri(system_identity_creation_uri)
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(json_body)
            .map_err(|e| HttpClientError::EncoderError(format!("Failed to build request: {e}")))?;

        let response = http_client.send(request)?;
        let body = response.body();
        match response.status() {
            StatusCode::OK => {
                let system_identity_response: SystemIdentityCreationResponseData =
                    serde_json::from_slice(body).map_err(|e| {
                        HttpClientError::DecoderError(format!("Failed to decode JSON: {e}"))
                    })?;
                Ok(system_identity_response)
            }
            status => Err(HttpClientError::UnsuccessfulResponse(
                status.as_u16(),
                String::from_utf8_lossy(body).to_string(),
            )),
        }
    }
}

impl<C: HttpClient> IAMClient for HttpIAMClientImpl<'_, C> {
    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        Self::system_identity_from_token(
            self.http_client,
            self.name.as_str(),
            self.organization_id.as_str(),
            token,
            pub_key,
            self.system_identity_creation_uri,
        )
        .map_err(|e| IAMClientError::IAMClientError(e.to_string()))
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
