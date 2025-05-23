use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum UserGraphWithdrawEvent {
    InitWithdraw(InitWithdrawEvent),
    CancelWithdraw(CancelWithdrawEvent),
}

pub const INIT_WITHDRAW_EVENT_ENTITY: &str = "initWithdraws";
pub const CANCEL_WITHDRAW_EVENT_ENTITY: &str = "cancelWithdraws";
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

#[derive(Debug)]
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
                    query.push_str(&format!("{field}: \"{value}\","));
                }
                query.push_str("},");
            }
            // Add order by if specified
            if let (Some(order_by), Some(direction)) = (q.order_by, q.order_direction) {
                query.push_str(&format!("orderBy: {order_by}, orderDirection: {direction},"));
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

pub fn get_user_withdraw_events_query(block_range: Option<BlockRange>) -> String {
    let mut query_builder = QueryBuilder::new()
        .add_query(INIT_WITHDRAW_EVENT_ENTITY)
        .add_query(CANCEL_WITHDRAW_EVENT_ENTITY);
    query_builder = query_builder
        .add_field(INIT_WITHDRAW_EVENT_ENTITY, "id")
        .add_field(INIT_WITHDRAW_EVENT_ENTITY, "instanceId")
        .add_field(INIT_WITHDRAW_EVENT_ENTITY, "graphId")
        .add_field(INIT_WITHDRAW_EVENT_ENTITY, "transactionHash")
        .add_field(INIT_WITHDRAW_EVENT_ENTITY, "blockNumber")
        .set_order_by(INIT_WITHDRAW_EVENT_ENTITY, "blockNumber", "asc");

    query_builder = query_builder
        .add_field(CANCEL_WITHDRAW_EVENT_ENTITY, "id")
        .add_field(CANCEL_WITHDRAW_EVENT_ENTITY, "instanceId")
        .add_field(CANCEL_WITHDRAW_EVENT_ENTITY, "graphId")
        .add_field(CANCEL_WITHDRAW_EVENT_ENTITY, "transactionHash")
        .add_field(CANCEL_WITHDRAW_EVENT_ENTITY, "blockNumber")
        .set_order_by(CANCEL_WITHDRAW_EVENT_ENTITY, "blockNumber", "asc");

    if let Some(range) = block_range {
        query_builder = query_builder
            .add_filter(
                INIT_WITHDRAW_EVENT_ENTITY,
                "blockNumber_gte",
                &range.start_block.to_string(),
            )
            .add_filter(INIT_WITHDRAW_EVENT_ENTITY, "blockNumber_lte", &range.end_block.to_string())
            .add_filter(
                CANCEL_WITHDRAW_EVENT_ENTITY,
                "blockNumber_gte",
                &range.start_block.to_string(),
            )
            .add_filter(
                CANCEL_WITHDRAW_EVENT_ENTITY,
                "blockNumber_lte",
                &range.end_block.to_string(),
            );
    }
    query_builder.build()
}
