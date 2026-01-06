use crate::graphs::graph_query::get_meta_data_query;

pub mod graph_query;
#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
}

impl Default for GraphQueryClient {
    fn default() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

impl GraphQueryClient {
    pub fn new() -> Self {
        Self::default()
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

    pub async fn get_sync_block_height(&self, subgraph_url: &str) -> anyhow::Result<Option<i64>> {
        let query_res = self.execute_query(subgraph_url, &get_meta_data_query()).await?;
        Ok(query_res["_meta"]["block"]["number"].clone().as_i64())
    }
}
