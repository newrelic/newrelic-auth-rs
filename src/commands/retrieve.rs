use crate::http_client::HttpClient;
use http::Error;

pub struct RetrieveCommand<C>
where
    C: HttpClient,
{
    http_client: C,
}

impl<C> RetrieveCommand<C>
where
    C: HttpClient,
{
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }

    pub fn retrieve(metadata: String) -> Result<(), Error> {
        Ok(())
    }
}
