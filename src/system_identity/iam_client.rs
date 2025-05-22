use error::IAMClientError;
use response_data::SystemIdentityCreationResponseData;

mod error;
pub mod http_iam_client;
mod http_token_retriever;
mod l1_token_retriever;
pub mod response_data;

pub trait IAMClient {
    fn create_system_identity(
        &self,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError>;
}

// Accept closures as IAMClient implementations
impl<F> IAMClient for F
where
    F: Fn(&[u8]) -> Result<SystemIdentityCreationResponseData, IAMClientError>,
{
    fn create_system_identity(
        &self,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        self(pub_key)
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
                pub_key: &[u8]
            ) -> Result<SystemIdentityCreationResponseData, IAMClientError>;
        }
    }
}
