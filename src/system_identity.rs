pub mod creation_response;
pub mod generator;
pub mod identity_creator;
pub mod input_data;

/// System identity information. Final output of the System Identity creation process.
#[derive(Debug, Clone, Default)]
pub struct SystemIdentity {
    pub name: String,
    pub client_id: String,
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use mockall::Sequence;

    use crate::{
        key::creator::tests::MockCreator,
        system_identity::{
            creation_response::SystemIdentityCreationResponseData,
            generator::L2SystemIdentityGenerator, identity_creator::tests::MockL2IAMClient,
        },
    };

    #[test]
    fn create_system_identity_mocked() {
        let mut key_creator = MockCreator::new();
        let mut iam_client = MockL2IAMClient::new();
        let mut sequence = Sequence::new();

        key_creator
            .expect_create()
            .once()
            .in_sequence(&mut sequence)
            .returning(|| Ok(vec![1, 2, 3]));
        iam_client
            .expect_create_l2_system_identity()
            .once()
            .in_sequence(&mut sequence)
            .returning(|_| {
                Ok(SystemIdentityCreationResponseData {
                    client_id: "client-id".to_string(),
                    name: "test".to_string(),
                })
            });

        let system_identity_generator = L2SystemIdentityGenerator {
            key_creator,
            iam_client,
        };
        let result = system_identity_generator.generate();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.name, "test");
        assert_eq!(result.client_id, "client-id");
        assert_eq!(result.pub_key, vec![1, 2, 3]);
    }
}
