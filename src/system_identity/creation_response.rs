use serde::{Deserialize, Deserializer};

/// Represents the response data from the System Identity service
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationResponseData {
    pub client_id: String,
    pub name: String,
}

/// Manual implementation of Deserialize to handle nested structure that comes as response
/// from the System Identity service. This assumes we are deserializing from a specific JSON format.
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
