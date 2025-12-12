pub mod graph_query;
#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
}

impl GraphQueryClient {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }

    pub async fn execute_query(
        &self,
        subgraph_url: &str,
        query: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self
            .client
            .post(subgraph_url)
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await
            .map_err(|err| anyhow::format_err!("{err}"))?;
        Ok(response["data"].clone())
    }
}
