pub mod creation_response;
pub mod generator;
pub mod identity_creator;
pub mod input_data;

/// System identity information. Final output of the System Identity creation process.
#[derive(Debug, Clone)]
pub struct SystemIdentity {
    pub id: String,
    pub name: Option<String>,
    pub client_id: String,
    pub organization_id: String,
    pub identity_type: SystemIdentityType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SystemIdentityType {
    L1 {
        client_secret: ClientSecret,
        credential_expiration: String,
    },
    L2 {
        pub_key: Base64PublicKey,
    },
}

type ClientSecret = String; // For L1 System Identity. Type better? What are we doing with these?
type Base64PublicKey = String; // For L2 System Identity. Type better? What are we doing with these?

#[cfg(test)]
mod tests {
    use mockall::Sequence;

    use crate::{
        key::creator::tests::MockCreator,
        system_identity::{
            generator::L2SystemIdentityGenerator, identity_creator::tests::MockL2IAMClient,
            SystemIdentity,
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
                Ok(SystemIdentity {
                    client_id: "client-id".to_string(),
                    name: "test".to_string().into(),
                    identity_type: super::SystemIdentityType::L2 {
                        pub_key: String::from_utf8_lossy(&[1u8, 2u8, 3u8]).to_string(),
                    },
                    id: "id".to_string(),
                    organization_id: "org-id".to_string(),
                })
            });

        let system_identity_generator = L2SystemIdentityGenerator {
            key_creator,
            iam_client,
        };
        let result = system_identity_generator.generate();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.name, Some("test".to_string()));
        assert_eq!(result.client_id, "client-id");
        assert!(matches!(
            result.identity_type,
            super::SystemIdentityType::L2 { pub_key } if pub_key == String::from_utf8_lossy(&[1u8, 2u8, 3u8])
        ));
    }
}
