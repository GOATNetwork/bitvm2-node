pub mod graph_query;
#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
    subgraph_url: String,
}

impl GraphQueryClient {
    pub fn new(subgraph_url: String) -> Self {
        let client = reqwest::Client::new();
        Self { client, subgraph_url }
    }
    pub async fn execute_query(&self, query: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .client
            .post(&self.subgraph_url)
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(response["data"].clone())
    }
}
