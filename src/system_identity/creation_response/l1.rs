use serde::{Deserialize, Deserializer};

use crate::system_identity::{SystemIdentity, SystemIdentityType};

use super::common_nerdgraph_response;

/// Represents the response data from the L1 System Identity service
#[derive(Debug, Clone, PartialEq)]
pub struct L1SystemIdentityCreationResponseData {
    client_id: String,
    name: String,
    id: Option<String>, // What's this field actually?
    client_secret: String,
}

impl From<L1SystemIdentityCreationResponseData> for SystemIdentity {
    fn from(response: L1SystemIdentityCreationResponseData) -> Self {
        Self {
            name: response.name,
            client_id: response.client_id,
            identity_type: SystemIdentityType::L1 {
                id: response.id.unwrap_or_default(),
                client_secret: response.client_secret,
            },
        }
    }
}

impl TryFrom<SystemIdentity> for L1SystemIdentityCreationResponseData {
    type Error = &'static str;

    fn try_from(value: SystemIdentity) -> Result<Self, Self::Error> {
        if let SystemIdentityType::L1 { id, client_secret } = value.identity_type {
            Ok(Self {
                client_id: value.client_id,
                name: value.name,
                id: if id.is_empty() { None } else { Some(id) },
                client_secret,
            })
        } else {
            Err("Cannot convert non-L1 SystemIdentity to L1SystemIdentityCreationResponseData")
        }
    }
}

impl<'de> Deserialize<'de> for L1SystemIdentityCreationResponseData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            client_id: String,
            name: String,
            id: Option<String>, // What's this field actually?
            client_secret: String,
        }
        let response = common_nerdgraph_response::<_, Response>(deserializer)?;

        Ok(Self {
            client_id: response.client_id,
            name: response.name,
            id: response.id,
            client_secret: response.client_secret,
        })
    }
}
