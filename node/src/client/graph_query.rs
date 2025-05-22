use serde::{Deserialize, Serialize};

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
    #[serde(rename = "IntWithdrawTxHash")]
    pub int_withdraw_tx_hash: String,
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
    entity: String,
    fields: Vec<String>,
    filters: Vec<(String, String)>,
    order_by: Option<String>,
    order_direction: Option<String>,
    first: Option<usize>,
    skip: Option<usize>,
}

impl QueryBuilder {
    pub fn new(entity: &str) -> Self {
        Self {
            entity: entity.to_string(),
            fields: Vec::new(),
            filters: Vec::new(),
            order_by: None,
            order_direction: None,
            first: None,
            skip: None,
        }
    }

    pub fn add_field(mut self, field: &str) -> Self {
        self.fields.push(field.to_string());
        self
    }

    pub fn add_filter(mut self, field: &str, value: &str) -> Self {
        self.filters.push((field.to_string(), value.to_string()));
        self
    }

    pub fn set_order_by(mut self, field: &str, direction: &str) -> Self {
        self.order_by = Some(field.to_string());
        self.order_direction = Some(direction.to_string());
        self
    }

    pub fn set_pagination(mut self, first: usize, skip: Option<usize>) -> Self {
        self.first = Some(first);
        self.skip = skip;
        self
    }

    pub fn build(self) -> String {
        let mut query = format!(
            r#"query {{
            {}("#,
            self.entity
        );

        // Add where clause if there are filters
        if !self.filters.is_empty() {
            query.push_str("where: {");
            for (field, value) in self.filters {
                query.push_str(&format!("{field}: \"{value}\","));
            }
            query.push_str("},");
        }

        // Add order by if specified
        if let (Some(order_by), Some(direction)) = (self.order_by, self.order_direction) {
            query.push_str(&format!("orderBy: {order_by}, orderDirection: {direction},"));
        }

        // Add pagination if specified
        if let Some(first) = self.first {
            query.push_str(&format!("first: {first},"));
        }
        if let Some(skip) = self.skip {
            query.push_str(&format!("skip: {skip},",));
        }

        // Add fields
        query.push_str(") {");
        for field in self.fields {
            query.push_str(&format!("{field} "));
        }
        query.push_str("}}");

        query
    }
}

pub fn get_init_withdraw_events_query(block_range: Option<BlockRange>) -> String {
    let mut query_builder = QueryBuilder::new("initWithdrawEvent")
        .add_field("id")
        .add_field("IntWithdrawTxHash")
        .add_field("instanceId")
        .add_field("graphId")
        .add_field("transactionHash")
        .add_field("blockNumber")
        .set_order_by("blockNumber", "asc");
    query_builder = query_builder.set_pagination(5, None);

    if let Some(range) = block_range {
        query_builder = query_builder
            .add_filter("blockNumber_gte", &range.start_block.to_string())
            .add_filter("blockNumber_lte", &range.end_block.to_string());
    }
    query_builder.build()
}

pub fn get_cancel_withdraw_events_query(block_range: Option<BlockRange>) -> String {
    let mut query_builder = QueryBuilder::new("cancelWithdrawEvent")
        .add_field("id")
        .add_field("instanceId")
        .add_field("graphId")
        .add_field("transactionHash")
        .add_field("blockNumber")
        .set_order_by("blockNumber", "asc");
    query_builder = query_builder.set_pagination(5, None);

    if let Some(range) = block_range {
        query_builder = query_builder
            .add_filter("blockNumber_gte", &range.start_block.to_string())
            .add_filter("blockNumber_lte", &range.end_block.to_string());
    }
    query_builder.build()
}
