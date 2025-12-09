pub mod graph_query;
#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
    subgraph_urls: Vec<String>,
}

impl GraphQueryClient {
    pub fn new(subgraph_urls: Vec<String>) -> Self {
        let client = reqwest::Client::new();
        Self { client, subgraph_urls }
    }
    pub async fn execute_query(&self, query: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut res = vec![];

        for subgraph_url in &self.subgraph_urls {
            let response = self
                .client
                .post(subgraph_url)
                .json(&serde_json::json!({
                    "query": query
                }))
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;
            res.push(response["data"].clone());
        }
        Ok(res)
    }
}
