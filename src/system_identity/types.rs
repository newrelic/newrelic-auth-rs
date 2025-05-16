use serde::{Deserialize, Deserializer, Serialize};

/// Represents the input data required to request an L1 access token from the System Identity OAuth service.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct L1TokenRequestInputData {
    pub client_id: String,
    pub client_secret: String,
}

/// Represents an appropriate response from the System Identity OAuth service
/// when requesting an access token.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct L1AccessTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

/// Represents the input data required to create a System Identity.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationInputData {
    pub name: String,
    pub organization_id: String,
    pub b64_public_key: String,
}

/// Represents the response data from the System Identity service
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationResponseData {
    pub client_id: String,
    pub name: String,
}

// Manual implementation of Deserialize to handle nested structure that comes as response
// from the System Identity service.
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
