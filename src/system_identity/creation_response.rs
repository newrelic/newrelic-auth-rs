use serde::{Deserialize, Deserializer};

pub mod l1;
pub mod l2;

/// Manual implementation fragment of Deserialize to handle nested structure that comes as response
/// from the System Identity service. Both for L1 and L2 (hence the generic "end node", `T`).
///
/// This assumes we are deserializing from a specific JSON format.
fn common_nerdgraph_response<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    /*
    The JSON output that we expect has this form for the case of L2 SI creation:

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

    or for the case of L1:

    ```json
    {
      "data": {
        "systemIdentityCreate": {
          "clientId": "894d361a-20ec-493e-9ff8-046f32889a46",
          "clientSecret": "some secret",
          "id": "b9b884cc-868e-4050-856b-e2c41a172ec3",
          "name": "NR_Control_System_Identity"
        }
      }
    }
    ```

    So we create the appropriate intermediate structures to
    deserialize it and return only the actual data we need.
    */

    #[derive(Deserialize)]
    struct Root<T> {
        data: Data<T>,
    }
    #[derive(Deserialize)]
    struct Data<T> {
        #[serde(rename = "systemIdentityCreate")]
        system_identity_create: T,
    }

    let deserialized_data = Root::<T>::deserialize(deserializer)?
        .data
        .system_identity_create;

    Ok(deserialized_data)
}
