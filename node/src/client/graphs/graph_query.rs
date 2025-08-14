use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum GatewayEventEntity {
    #[strum(serialize = "initWithdraws")]
    InitWithdraws,
    #[strum(serialize = "cancelWithdraws")]
    CancelWithdraws,
    #[strum(serialize = "proceedWithdraws")]
    ProceedWithdraws,
    #[strum(serialize = "withdrawHappyPaths")]
    WithdrawHappyPaths,
    #[strum(serialize = "withdrawUnhappyPaths")]
    WithdrawUnhappyPaths,
    #[strum(serialize = "withdrawDisproveds")]
    WithdrawDisproveds,
}

impl GatewayEventEntity {
    pub fn add_single_query(
        &self,
        builder: QueryBuilder,
        block_range: Option<BlockRange>,
    ) -> QueryBuilder {
        let mut builder = builder;
        let tag = self.to_string();
        builder = builder.add_query(&tag);
        match self {
            GatewayEventEntity::InitWithdraws | GatewayEventEntity::CancelWithdraws => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
            GatewayEventEntity::ProceedWithdraws => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "kickoffTxid")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            GatewayEventEntity::WithdrawHappyPaths | GatewayEventEntity::WithdrawUnhappyPaths => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "operatorAddress")
                    .add_field(&tag, "rewardAmountSats")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            GatewayEventEntity::WithdrawDisproveds => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "challengerAddress")
                    .add_field(&tag, "disproverAddress")
                    .add_field(&tag, "challengerRewardAmountSats")
                    .add_field(&tag, "disproverRewardAmountSats")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
        }

        if let Some(range) = block_range {
            builder = builder
                .add_filter(&tag, "blockNumber_gte", &range.start_block.to_string())
                .add_filter(&tag, "blockNumber_lte", &range.end_block.to_string())
        }
        builder
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UserGraphWithdrawEvent {
    InitWithdraw(InitWithdrawEvent),
    CancelWithdraw(CancelWithdrawEvent),
}

impl UserGraphWithdrawEvent {
    pub fn get_block_number(&self) -> i64 {
        match self {
            UserGraphWithdrawEvent::InitWithdraw(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
            UserGraphWithdrawEvent::CancelWithdraw(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CancelWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProceedWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "kickoffTxid")]
    pub kickoff_txid: String,
}

/// WithdrawHappyPath or WithdrawUnhappyPath
#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawPathsEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "operatorAddress")]
    pub operator_addr: String,
    #[serde(rename = "rewardAmountSats")]
    pub reward_amount_sats: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawDisproved {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "challengerAddress")]
    pub challenger_addr: String,
    #[serde(rename = "challengerRewardAmountSats")]
    pub challenger_amount_sats: String,
    #[serde(rename = "disproverAddress")]
    pub disprover_addr: String,
    #[serde(rename = "disproverRewardAmountSats")]
    pub disprover_amount_sats: String,
}

#[derive(Debug, Clone)]
pub struct BlockRange {
    start_block: i64,
    end_block: i64,
}

impl BlockRange {
    pub fn new(start_block: i64, end_block: i64) -> Self {
        Self { start_block, end_block }
    }
}

#[derive(Debug)]
pub struct QueryBuilder {
    queries: Vec<SingleQuery>,
}
#[derive(Debug)]
struct SingleQuery {
    entity: String,
    fields: Vec<String>,
    filters: Vec<(String, String)>,
    order_by: Option<String>,
    order_direction: Option<String>,
    first: Option<usize>,
    skip: Option<usize>,
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl QueryBuilder {
    pub fn new() -> Self {
        Self { queries: Vec::new() }
    }

    pub fn add_query(mut self, entity: &str) -> Self {
        self.queries.push(SingleQuery {
            entity: entity.to_string(),
            fields: Vec::new(),
            filters: Vec::new(),
            order_by: None,
            order_direction: None,
            first: None,
            skip: None,
        });
        self
    }

    pub fn add_field(mut self, entity: &str, field: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.fields.push(field.to_string());
        }
        self
    }

    pub fn add_filter(mut self, entity: &str, field: &str, value: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.filters.push((field.to_string(), value.to_string()));
        }
        self
    }

    pub fn set_order_by(mut self, entity: &str, field: &str, direction: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.order_by = Some(field.to_string());
            query.order_direction = Some(direction.to_string());
        }
        self
    }

    pub fn set_pagination(mut self, entity: &str, first: usize, skip: Option<usize>) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.first = Some(first);
            query.skip = skip;
        }
        self
    }

    pub fn build(self) -> String {
        let mut query = String::from("query {");
        for q in self.queries {
            query.push_str(&format!("\n{}(", q.entity));
            // Add where clause if there are filters
            if !q.filters.is_empty() {
                query.push_str("where: {");
                for (field, value) in q.filters {
                    query.push_str(&format!("{field}: \"{value}\", "));
                }
                query.push_str("}, ");
            }
            // Add order by if specified
            if let (Some(order_by), Some(direction)) = (q.order_by, q.order_direction) {
                query.push_str(&format!("orderBy: {order_by}, orderDirection: {direction}, "));
            }
            // Add pagination if specified
            if let Some(first) = q.first {
                query.push_str(&format!("first: {first},"));
            }
            if let Some(skip) = q.skip {
                query.push_str(&format!("skip: {skip},"));
            }
            // Add fields
            query.push_str(") {");
            for field in q.fields {
                query.push_str(&format!("{field} "));
            }
            query.push_str(" }");
        }
        query.push_str("\n}");
        query
    }
}

pub fn get_gateway_events_query(
    event_entities: &[GatewayEventEntity],
    block_range: Option<BlockRange>,
) -> String {
    let mut query_builder = QueryBuilder::new();
    for entity in event_entities {
        query_builder = entity.add_single_query(query_builder, block_range.clone());
    }
    query_builder.build()
}
