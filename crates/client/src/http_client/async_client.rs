use anyhow::anyhow;
use esplora_client::Error;
use reqwest::{Client, Response};
use std::time::Duration;

const DEFAULT_MAX_RETRIES: usize = 6;
const BASE_BACKOFF_MILLIS: Duration = Duration::from_millis(256);
const RETRYABLE_ERROR_CODES: [u16; 3] = [
    429, // TOO_MANY_REQUESTS
    500, // INTERNAL_SERVER_ERROR
    503, // SERVICE_UNAVAILABLE
];

pub struct HttpAsyncClient {
    client: Client,
    max_retries: usize,
}

impl HttpAsyncClient {
    pub fn new(max_retries: Option<usize>) -> Self {
        Self { client: Client::new(), max_retries: max_retries.unwrap_or(DEFAULT_MAX_RETRIES) }
    }

    pub async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> anyhow::Result<T> {
        let response = self.get_with_retry(url).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await?;
            return Err(Error::HttpResponse { status, message }.into());
        }

        response.json::<T>().await.map_err(|e| anyhow!("failed to deserialize response:{e}"))
    }

    pub async fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<T>> {
        match self.get_response_json(url).await {
            Ok(res) => Ok(Some(res)),
            Err(e) => {
                if let Some(esplora_err) = e.downcast_ref::<Error>()
                    && let Error::HttpResponse { status: 404, .. } = esplora_err
                {
                    return Ok(None);
                }
                Err(e)
            }
        }
    }
    async fn get_with_retry(&self, url: &str) -> anyhow::Result<Response> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            match self.client.get(url).send().await? {
                resp if attempts < self.max_retries
                    && RETRYABLE_ERROR_CODES.contains(&resp.status().as_u16()) =>
                {
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }
}
