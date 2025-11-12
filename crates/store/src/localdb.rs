use crate::schema::NODE_STATUS_OFFLINE;
use crate::schema::NODE_STATUS_ONLINE;
use crate::utils::{QueryBuilder, QueryParam, create_place_holders};
use crate::{
    CommitChainProof, CommitInfo, GoatTxRecord, Graph, GraphBtcTxVoutMonitor, GraphRawData,
    HeaderChainProof, Instance, Message, MessageBroadcast, Node, NodesOverview, OperatorProof,
    PeginGraphProcessData, PeginInstanceProcessData, ProofInfo, ProofType, SerializableTxid,
    WatchContract, WatchtowerProof,
};

use indexmap::IndexMap;
use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::types::Uuid;
use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

fn get_current_timestamp_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn get_current_timestamp_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

#[derive(Clone, Debug)]
pub struct LocalDB {
    pub path: String,
    pub is_mem: bool,
    pub conn: SqlitePool,
}

#[derive(Debug)]
pub enum ConnectionHolder<'a> {
    Pooled(PoolConnection<Sqlite>),
    Direct(SqliteConnection),
    Transaction(Transaction<'a, Sqlite>),
}

#[derive(Debug)]
pub struct StorageProcessor<'a> {
    pub conn: ConnectionHolder<'a>,
    pub in_transaction: bool,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
impl LocalDB {
    pub async fn new(path: &str, is_mem: bool) -> LocalDB {
        if !Sqlite::database_exists(path).await.unwrap_or(false) {
            tracing::info!("Creating database {}", path);
            match Sqlite::create_database(path).await {
                Ok(_) => println!("Create db success"),
                Err(error) => panic!("error: {error}"),
            }
        } else {
            tracing::info!("Database already exists");
        }

        let conn = SqlitePool::connect(path).await.unwrap();
        Self { path: path.to_string(), is_mem, conn }
    }

    pub async fn migrate(&self) {
        match MIGRATOR.run(&self.conn).await {
            Ok(_) => tracing::info!("Migration success"),
            Err(error) => {
                panic!("error: {error:?}");
            }
        }
    }

    pub async fn acquire<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Pooled(self.conn.acquire().await?),
            in_transaction: false,
        })
    }
    pub async fn start_transaction<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Transaction(self.conn.begin().await?),
            in_transaction: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct InstanceQuery {
    pub is_bridge_in: bool,
    pub from_addr: Option<String>,
    pub statuses: Vec<String>,
    pub earliest_updated: Option<i64>,
    pub pegin_request_height_threshold: Option<i64>,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl InstanceQuery {
    pub fn with_is_bridge_in(mut self, is_bridge_in: bool) -> Self {
        self.is_bridge_in = is_bridge_in;
        self
    }

    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.statuses.push(status);
        self
    }

    pub fn with_statuses(mut self, statuses: Vec<String>) -> Self {
        self.statuses = statuses;
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_earliest_updated(mut self, earliest_updated: i64) -> Self {
        self.earliest_updated = Some(earliest_updated);
        self
    }

    pub fn with_pegin_request_height_threshold(mut self, threshold: i64) -> Self {
        self.pegin_request_height_threshold = Some(threshold);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);
        query_builder.and_where("is_bridge_in = ?", Some(QueryParam::Bool(self.is_bridge_in)));

        if let Some(from_addr) = &self.from_addr {
            query_builder.and_where("from_addr = ?", Some(QueryParam::Text(from_addr.clone())));
        }
        if !self.statuses.is_empty() {
            query_builder.and_where_in("status", &self.statuses, false);
        }
        if let Some(earliest_updated) = self.earliest_updated {
            query_builder.and_where("updated_at >= ?", Some(QueryParam::Int(earliest_updated)));
        }
        if let Some(pegin_request_height_threshold) = self.pegin_request_height_threshold {
            query_builder.and_where(
                "goat_tx_height < ?",
                Some(QueryParam::Int(pegin_request_height_threshold)),
            );
        }
        if let Some(order) = &self.order {
            query_builder.apply_order(order);
        }
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

/// Instance field update parameters
///
/// Provides a more elegant way to specify which instance fields to update
#[derive(Debug, Clone)]
pub struct InstanceUpdate {
    pub instance_id: Uuid,
    pub status: Option<String>,
    pub pegin_confirm_txid: Option<String>,
    pub btc_height: Option<i64>,
    pub committees_answers: Option<HashMap<String, Vec<u8>>>,
}

impl InstanceUpdate {
    /// Create new update parameters
    pub fn new(instance_id: Uuid) -> Self {
        Self {
            instance_id,
            status: None,
            pegin_confirm_txid: None,
            btc_height: None,
            committees_answers: None,
        }
    }

    /// Set status
    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    /// Set pegin confirmation information
    pub fn with_pegin_confirm(mut self, txid: String, _fee: i64) -> Self {
        self.pegin_confirm_txid = Some(txid);
        self
    }

    /// Set committees answers
    pub fn with_committees_answers(mut self, committees_answers: HashMap<String, Vec<u8>>) -> Self {
        self.committees_answers = Some(committees_answers);
        self
    }

    pub fn with_btc_height(mut self, timeout: i64) -> Self {
        self.btc_height = Some(timeout);
        self
    }
    /// Check if any fields need to be updated
    pub fn has_updates(&self) -> bool {
        self.status.is_some()
            || self.pegin_confirm_txid.is_some()
            || self.committees_answers.is_some()
            || self.btc_height.is_some()
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::update(base_sql);
        // Set field
        if let Some(ref status) = self.status {
            query_builder.set_field("status", QueryParam::Text(status.clone()));
        }

        if let Some(ref txid) = self.pegin_confirm_txid {
            query_builder.set_field("pegin_confirm_txid", QueryParam::Text(txid.clone()));
        }

        if let Some(pegin_prepare_height) = self.btc_height {
            query_builder.set_field("btc_height", QueryParam::Int(pegin_prepare_height));
        }

        // Add update time
        let current_time = get_current_timestamp_secs();
        query_builder.set_field("updated_at", QueryParam::Int(current_time));

        // Add WHERE clause
        query_builder.and_where(
            "hex(instance_id) = ? COLLATE NOCASE ",
            Some(QueryParam::Text(hex::encode(self.instance_id))),
        );

        query_builder
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphQuery {
    pub statuses: Vec<String>,
    pub operator_pubkey: Option<String>,
    pub kickoff_index: Option<i64>,
    pub from_addr: Option<String>,
    pub graph_id: Option<String>,
    pub pegin_txid: Option<SerializableTxid>,
    pub raw_conditions: Vec<String>,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl GraphQuery {
    pub fn with_status(mut self, status: String) -> Self {
        self.statuses.push(status);
        self
    }

    pub fn with_statuses(mut self, statuses: Vec<String>) -> Self {
        self.statuses = statuses;
        self
    }
    pub fn with_raw_condition(mut self, raw_condition: String) -> Self {
        self.raw_conditions.push(raw_condition);
        self
    }

    pub fn with_raw_conditions(mut self, raw_conditions: Vec<String>) -> Self {
        self.raw_conditions = raw_conditions;
        self
    }

    pub fn with_operator_pubkey(mut self, operator_pubkey: String) -> Self {
        self.operator_pubkey = Some(operator_pubkey);
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    pub fn with_graph_id(mut self, graph_id: String) -> Self {
        self.graph_id = Some(graph_id);
        self
    }

    pub fn with_pegin_txid(mut self, pegin_txid: SerializableTxid) -> Self {
        self.pegin_txid = Some(pegin_txid);
        self
    }

    pub fn with_kickoff_index(mut self, kickoff_index: i64) -> Self {
        self.kickoff_index = Some(kickoff_index);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);
        // Add WHERE conditions
        if !self.statuses.is_empty() {
            query_builder.and_where_in("status", &self.statuses, false);
        }

        if let Some(from_addr) = &self.from_addr {
            query_builder.and_where("from_addr = ?", Some(QueryParam::Text(from_addr.clone())));
        }

        if let Some(operator) = &self.operator_pubkey {
            query_builder
                .and_where("operator_pubkey = ?", Some(QueryParam::Text(operator.clone())));
        }

        if let Some(kickoff_index) = self.kickoff_index {
            query_builder.and_where("kickoff_index = ?", Some(QueryParam::Int(kickoff_index)));
        }

        if let Some(pegin_txid) = &self.pegin_txid {
            query_builder
                .and_where("pegin_txid = ?", Some(QueryParam::BTCTxid(pegin_txid.clone())));
        }

        if let Some(graph_id) = &self.graph_id {
            query_builder.and_where(
                "hex(graph_id) = ? COLLATE NOCASE",
                Some(QueryParam::Text(graph_id.clone())),
            );
        }
        for raw_condition in &self.raw_conditions {
            query_builder.add_raw_condition(raw_condition);
        }
        if let Some(order) = &self.order {
            query_builder.apply_order(order)
        }
        // Add pagination
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

#[derive(Clone, Debug)]
pub struct GraphUpdate {
    pub graph_id: Uuid,
    pub status: Option<String>,
    pub sub_status: Option<String>,
    pub ipfs_base_url: Option<String>,
    pub challenge_txid: Option<SerializableTxid>,
    pub disprove_txid: Option<SerializableTxid>,
    pub bridge_out_start_at: Option<i64>,
    pub init_withdraw_tx_hash: Option<String>,
}

impl GraphUpdate {
    /// Create new update parameters
    pub fn new(graph_id: Uuid) -> Self {
        Self {
            graph_id,
            status: None,
            sub_status: None,
            ipfs_base_url: None,
            challenge_txid: None,
            disprove_txid: None,
            bridge_out_start_at: None,
            init_withdraw_tx_hash: None,
        }
    }

    /// Set status
    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }
    /// Set sub_status
    pub fn with_sub_status(mut self, sub_status: String) -> Self {
        self.sub_status = Some(sub_status);
        self
    }

    /// Set IPFS base URL
    pub fn with_ipfs_base_url(mut self, ipfs_base_url: String) -> Self {
        self.ipfs_base_url = Some(ipfs_base_url);
        self
    }

    /// Set challenge transaction ID
    pub fn with_challenge_txid(mut self, challenge_txid: SerializableTxid) -> Self {
        self.challenge_txid = Some(challenge_txid);
        self
    }

    /// Set disprove transaction ID
    pub fn with_disprove_txid(mut self, disprove_txid: SerializableTxid) -> Self {
        self.disprove_txid = Some(disprove_txid);
        self
    }

    /// Set bridge out start time
    pub fn with_bridge_out_start_at(mut self, bridge_out_start_at: i64) -> Self {
        self.bridge_out_start_at = Some(bridge_out_start_at);
        self
    }

    /// Set init withdraw transaction ID
    pub fn with_init_withdraw_tx_hash(mut self, init_withdraw_tx_hash: String) -> Self {
        self.init_withdraw_tx_hash = Some(init_withdraw_tx_hash);
        self
    }

    /// Check if any fields need to be updated
    pub fn has_updates(&self) -> bool {
        self.status.is_some()
            || self.sub_status.is_some()
            || self.ipfs_base_url.is_some()
            || self.challenge_txid.is_some()
            || self.bridge_out_start_at.is_some()
            || self.init_withdraw_tx_hash.is_some()
            || self.disprove_txid.is_some()
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::update(base_sql);
        // Add SET fields
        if let Some(ref status) = self.status {
            query_builder.set_field("status", QueryParam::Text(status.clone()));
        }
        if let Some(ref sub_status) = self.sub_status {
            query_builder.set_field("sub_status", QueryParam::Text(sub_status.clone()));
        }
        if let Some(ref ipfs_base_url) = self.ipfs_base_url {
            query_builder.set_field("graph_ipfs_base_url", QueryParam::Text(ipfs_base_url.clone()));
        }
        if let Some(ref challenge_txid) = self.challenge_txid {
            query_builder.set_field("challenge_txid", QueryParam::BTCTxid(challenge_txid.clone()));
        }
        if let Some(ref disprove_txid) = self.disprove_txid {
            query_builder.set_field("disprove_txid", QueryParam::BTCTxid(disprove_txid.clone()));
        }
        if let Some(bridge_out_start_at) = self.bridge_out_start_at {
            query_builder.set_field("bridge_out_start_at", QueryParam::Int(bridge_out_start_at));
        }
        if let Some(ref init_withdraw_tx_hash) = self.init_withdraw_tx_hash {
            if init_withdraw_tx_hash.is_empty() {
                // Set NULL value
                query_builder.set_field_null("init_withdraw_tx_hash");
            } else {
                query_builder.set_field(
                    "init_withdraw_tx_hash",
                    QueryParam::Text(init_withdraw_tx_hash.clone()),
                );
            }
        }
        // Add update time
        let current_time = get_current_timestamp_secs();
        query_builder.set_field("updated_at", QueryParam::Int(current_time));

        // Add WHERE clause
        query_builder.and_where(
            "hex(graph_id) = ? COLLATE NOCASE",
            Some(QueryParam::Text(hex::encode(self.graph_id))),
        );

        query_builder
    }
}

#[derive(Clone, Debug, Default)]
pub struct NodeQuery {
    pub actor: Option<String>,
    pub goat_addr: Option<String>,
    pub time_threshold: i64,
    pub status_expect: Option<String>,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}
impl NodeQuery {
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_goat_addr(mut self, goat_addr: String) -> Self {
        self.goat_addr = Some(goat_addr);
        self
    }

    pub fn with_time_threshold(mut self, time_threshold: i64) -> Self {
        self.time_threshold = time_threshold;
        self
    }

    pub fn with_status_expect(mut self, status_expect: String) -> Self {
        self.status_expect = Some(status_expect);
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);

        // Add WHERE conditions
        if let Some(actor) = &self.actor {
            query_builder.and_where("actor = ?", Some(QueryParam::Text(actor.clone())));
        }

        if let Some(goat_addr) = &self.goat_addr {
            query_builder.and_where("goat_addr = ?", Some(QueryParam::Text(goat_addr.clone())));
        }
        if let Some(status_expect) = &self.status_expect {
            match status_expect.as_str() {
                NODE_STATUS_ONLINE => {
                    query_builder
                        .and_where("updated_at > ?", Some(QueryParam::Int(self.time_threshold)));
                }
                NODE_STATUS_OFFLINE => {
                    query_builder
                        .and_where("updated_at <= ?", Some(QueryParam::Int(self.time_threshold)));
                }
                _ => {}
            }
        }

        if let Some(order) = &self.order {
            query_builder.apply_order(order)
        }

        // Add pagination
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

impl<'a> StorageProcessor<'a> {
    pub fn conn(&mut self) -> &mut SqliteConnection {
        match &mut self.conn {
            ConnectionHolder::Pooled(conn) => conn,
            ConnectionHolder::Direct(conn) => conn,
            ConnectionHolder::Transaction(conn) => conn,
        }
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        if let ConnectionHolder::Transaction(transaction) = self.conn {
            transaction.commit().await?;
            Ok(())
        } else {
            panic!(
                "StorageProcessor::commit can only be invoked after calling StorageProcessor::begin_transaction"
            );
        }
    }

    /// Insert or update an instance
    ///
    /// Performs an INSERT OR REPLACE operation on the instance table.
    /// If an instance with the same instance_id exists, it will be updated.
    /// If no instance exists, a new one will be created.
    ///
    /// Parameters:
    /// - instance: The complete instance data to insert or update
    ///
    /// Returns:
    /// - Ok(true) if the operation affected at least one row
    /// - Ok(false) if no rows were affected
    /// - Err if the operation failed
    pub async fn upsert_instance(&mut self, instance: &Instance) -> anyhow::Result<bool> {
        let committees_answers_json = serde_json::to_string(&instance.committees_answers)?;
        let res = sqlx::query!(
            "INSERT OR
            REPLACE INTO instance (instance_id, is_bridge_in,  network, from_addr, to_addr, amount, fees, input_utxos, status, goat_tx_hash, goat_tx_height,
                        user_xonly_pubkey, user_change_addr, user_refund_addr, btc_txid, pegin_confirm_txid, pegin_cancel_txid, committees_answers,
                       pegin_data_tx_hash, btc_height, parameters, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            instance.instance_id,
            instance.is_bridge_in,
            instance.network,
            instance.from_addr,
            instance.to_addr,
            instance.amount,
            instance.fees,
            instance.input_utxos,
            instance.status,
            instance.goat_tx_hash,
            instance.goat_tx_height,
            instance.user_xonly_pubkey,
            instance.user_change_addr,
            instance.user_refund_addr,
            instance.btc_txid,
            instance.pegin_confirm_txid,
            instance.pegin_cancel_txid,
            committees_answers_json,
            instance.pegin_data_tx_hash,
            instance.btc_height,
            instance.parameters,
            instance.created_at,
            instance.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Find a single instance by its ID
    ///
    /// Retrieves an instance from the database using its unique instance_id.
    ///
    /// Parameters:
    /// - instance_id: The UUID of the instance to find
    ///
    /// Returns:
    /// - Ok(Some(instance)) if the instance was found
    /// - Ok(None) if no instance with the given ID exists
    /// - Err if the query failed
    pub async fn find_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<Option<Instance>> {
        let row = sqlx::query_as::<_, Instance>("SELECT * FROM instance WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_optional(self.conn())
            .await?;
        Ok(row)
    }

    /// Find multiple instances with filtering and pagination
    ///
    /// Retrieves instances from the database with optional filtering criteria
    /// and pagination support. Uses QueryBuilder for dynamic query construction.
    ///
    /// Parameters:
    /// - params: InstanceQuery containing all filter criteria and pagination options
    ///
    /// Returns:
    /// - Ok((instances, total_count)) where instances is a vector of matching instances
    ///   and total_count is the total number of instances matching the criteria
    /// - Err if the query failed
    pub async fn find_instances(
        &mut self,
        params: InstanceQuery,
    ) -> anyhow::Result<(Vec<Instance>, i64)> {
        let mut count_params = params.clone();
        (count_params.order, count_params.offset) = (None, None);
        let instances_query_builder = params.get_query_builder("SELECT * FROM instance");
        let count_query_builder =
            count_params.get_query_builder("SELECT count(*) as total_instances FROM instance");
        // Execute data query
        let sql = instances_query_builder.get_sql();
        let mut data_query = sqlx::query_as::<_, Instance>(&sql);
        data_query = instances_query_builder.query_as(data_query);
        // Execute count query
        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);
        Ok((
            data_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_instances"),
        ))
    }
    /// Get network type by instance ID
    ///
    /// Retrieves the network type (e.g., "mainnet", "testnet") for a specific instance.
    ///
    /// Parameters:
    /// - instance_id: The UUID of the instance
    ///
    /// Returns:
    /// - Ok(network_string) if the instance was found
    /// - Ok("") if no instance with the given ID exists
    /// - Err if the query failed
    pub async fn get_network_by_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<String> {
        if let Some(raw) =
            sqlx::query!(r#"SELECT network FROM instance WHERE instance_id = ?"#, instance_id)
                .fetch_optional(self.conn())
                .await?
        {
            Ok(raw.network)
        } else {
            Ok("".to_string())
        }
    }

    /// Update expired instances status
    ///
    /// Updates the status of instances that have expired based on a time threshold.
    /// This is typically used for cleanup operations to mark old instances as expired.
    ///
    /// Parameters:
    /// - current_status: The current status to match for instances to be updated
    /// - expired_status: The new status to set for expired instances
    /// - time_threshold: Timestamp threshold - instances updated before this time will be marked as expired
    ///
    /// Returns:
    /// - Ok(affected_rows) number of instances that were updated
    /// - Err if the update operation failed
    pub async fn update_expired_instance(
        &mut self,
        current_status: &str,
        expired_status: &str,
        time_threshold: i64,
    ) -> anyhow::Result<u64> {
        let row = sqlx::query!(
            r#"UPDATE instance SET status = ? WHERE status = ? AND updated_at < ?"#,
            expired_status,
            current_status,
            time_threshold
        )
        .execute(self.conn())
        .await?;
        Ok(row.rows_affected())
    }

    /// Update instance status
    ///
    /// A concise method specifically for updating instance status
    pub async fn update_instance_status(
        &mut self,
        instance_id: &Uuid,
        new_status: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query!(
            "UPDATE instance SET status = ?, updated_at = ? WHERE instance_id = ?",
            new_status,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update instance pegin confirmation information
    ///
    /// Method specifically for updating pegin confirmation transaction ID and fee
    pub async fn update_instance_pegin_confirm(
        &mut self,
        instance_id: &Uuid,
        pegin_confirm_txid: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query!(
            "UPDATE instance SET pegin_confirm_txid = ?, updated_at = ? WHERE instance_id = ?",
            pegin_confirm_txid,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update instance pegin data transaction ID
    ///
    /// Method specifically for updating pegin data transaction ID
    pub async fn update_instance_pegin_data_txid(
        &mut self,
        instance_id: &Uuid,
        pegin_data_tx_hash: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query!(
            "UPDATE instance SET pegin_data_tx_hash = ?, updated_at = ? WHERE instance_id = ?",
            pegin_data_tx_hash,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update instance fields using builder pattern
    ///
    /// This is the most elegant update method, using the InstanceUpdate builder pattern
    /// Provides type safety and clear API
    pub async fn update_instance(&mut self, params: &InstanceUpdate) -> anyhow::Result<bool> {
        if !params.has_updates() {
            return Ok(false);
        }
        let query_builder = params.get_query_builder("instance");
        // Get SQL and parameters
        let update_sql = query_builder.get_sql();
        // Execute query
        let mut query = sqlx::query(&update_sql);
        query = query_builder.query(query);
        let result = query.execute(self.conn()).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_instances_status_batch(
        &mut self,
        status: &str,
        ids: &[Uuid],
    ) -> anyhow::Result<()> {
        let current_time = get_current_timestamp_secs();
        let query_str = format!(
            "UPDATE instance \
            SET status = \'{status}\',
                updated_at = {current_time}
            WHERE hex(instance_id)
                 COLLATE NOCASE IN ({})",
            create_place_holders(ids)
        );
        let mut update_query = sqlx::query(&query_str);
        for id in ids {
            update_query = update_query.bind(hex::encode(id));
        }
        update_query.execute(self.conn()).await?;
        Ok(())
    }

    /// Add or update a single committee answer for an instance
    ///
    /// This method allows adding or updating a single committee's answer
    /// without needing to provide the entire committees_answers HashMap.
    pub async fn update_instance_committee_answer(
        &mut self,
        instance_id: &Uuid,
        committee_addr: &str,
        pubkey: Vec<u8>,
    ) -> anyhow::Result<bool> {
        // First, get the current committees_answers
        let current_instance = self.find_instance(instance_id).await?;
        if current_instance.is_none() {
            return Ok(false);
        }

        let mut committees_answers = current_instance.unwrap().committees_answers;
        committees_answers
            .entry(committee_addr.to_string())
            .and_modify(|existing| {
                *existing = pubkey.clone();
            })
            .or_insert_with(|| pubkey);
        self.update_instance_committees_answers_map(instance_id, &committees_answers).await
    }

    /// Remove a committee answer from an instance
    ///
    /// This method removes a specific committee's answer from the committees_answers HashMap.
    pub async fn remove_instance_committee_answer(
        &mut self,
        instance_id: &Uuid,
        committee: &str,
    ) -> anyhow::Result<bool> {
        // First, get the current committees_answers
        let current_instance = self.find_instance(instance_id).await?;
        if current_instance.is_none() {
            return Ok(false);
        }
        let mut committees_answers = current_instance.unwrap().committees_answers;
        // Remove the committee answer
        committees_answers.shift_remove(committee);
        // Update the instance with the new committees_answers
        self.update_instance_committees_answers_map(instance_id, &committees_answers).await
    }

    /// Get committees answers for an instance
    ///
    /// Returns the committees_answers HashMap for a specific instance.
    pub async fn get_instance_committees_answers(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<IndexMap<String, Vec<u8>>>> {
        let current_instance = self.find_instance(instance_id).await?;
        if let Some(instance) = current_instance {
            Ok(Some(instance.committees_answers))
        } else {
            Ok(None)
        }
    }

    /// Update instance committees answers with HashMap (convenience method)
    ///
    /// This is a convenience method that accepts a HashMap directly.
    /// Internally converts it to arrays and calls the main update method.
    pub async fn update_instance_committees_answers_map(
        &mut self,
        instance_id: &Uuid,
        committees_answers: &IndexMap<String, Vec<u8>>,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let committees_answers_json = serde_json::to_string(&committees_answers)?;

        let res = sqlx::query!(
            "UPDATE instance SET committees_answers = ?, updated_at = ? WHERE instance_id = ?",
            committees_answers_json,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;

        Ok(res.rows_affected() > 0)
    }

    pub async fn update_instance_parameters(
        &mut self,
        instance_id: &Uuid,
        parameters: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE instance SET parameters = ?,  updated_at = ? WHERE instance_id = ?",
            parameters,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_instance_parameters_by_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<String>> {
        let res =
            sqlx::query!("SELECT parameters FROM instance WHERE instance_id = ?", instance_id)
                .fetch_optional(self.conn())
                .await?;
        Ok(res.and_then(|record| record.parameters))
    }

    /// Insert or update a graph
    ///
    /// Performs an INSERT OR REPLACE operation on the graph table.
    /// If a graph with the same graph_id exists, it will be updated.
    /// If no graph exists, a new one will be created.
    ///
    /// Parameters:
    /// - graph: The complete graph data to insert or update
    ///
    /// Returns:
    /// - Ok(affected_rows) number of rows affected by the operation
    /// - Err if the operation failed
    pub async fn upsert_graph(&mut self, graph: Graph) -> anyhow::Result<u64> {
        let nack_txids_json = serde_json::to_string(&graph.nack_txids)?;
        let watchtower_challenge_timeout_txids_json =
            serde_json::to_string(&graph.watchtower_challenge_timeout_txids)?;
        let assert_commit_timeout_txids_json =
            serde_json::to_string(&graph.assert_commit_timeout_txids)?;
        let res = sqlx::query!(
            "INSERT OR
             REPLACE INTO graph (graph_id, instance_id, kickoff_index, from_addr, to_addr, graph_ipfs_base_url, amount, challenge_amount,
                    status, sub_status, operator_pubkey, cur_prekickoff_txid, next_prekickoff, force_skip_kickoff_txid,
                    quick_challenge_txid, challenge_incomplete_kickoff_txid, pegin_txid, kickoff_txid, take1_txid,
                    challenge_txid, take2_txid, disprove_txid,  watchtower_challenge_init_txid, watchtower_challenge_timeout_txids, nack_txids,
                    blockhash_commit_timeout_txid, assert_init_txid, assert_commit_timeout_txids, init_withdraw_tx_hash,
                    bridge_out_start_at, zkm_version,created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            graph.graph_id,
            graph.instance_id,
            graph.kickoff_index,
            graph.from_addr,
            graph.to_addr,
            graph.graph_ipfs_base_url,
            graph.amount,
            graph.challenge_amount,
            graph.status,
            graph.sub_status,
            graph.operator_pubkey,
            graph.cur_prekickoff_txid,
            graph.next_prekickoff,
            graph.force_skip_kickoff_txid,
            graph.quick_challenge_txid,
            graph.challenge_incomplete_kickoff_txid,
            graph.pegin_txid,
            graph.kickoff_txid,
            graph.take1_txid,
            graph.challenge_txid,
            graph.take2_txid,
            graph.disprove_txid,
            graph.watchtower_challenge_init_txid,
            watchtower_challenge_timeout_txids_json,
            nack_txids_json,
            graph.blockhash_commit_timeout_txid,
            graph.assert_init_txid,
            assert_commit_timeout_txids_json,
            graph.init_withdraw_tx_hash,
            graph.bridge_out_start_at,
            graph.zkm_version,
            graph.created_at,
            graph.updated_at,
        ).execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_graph_fields(&mut self, params: GraphUpdate) -> anyhow::Result<()> {
        let query_builder = params.get_query_builder("graph");
        let update_sql = query_builder.get_sql();
        let query = sqlx::query(&update_sql);
        let query = query_builder.query(query);
        let _ = query.execute(self.conn()).await?;
        Ok(())
    }

    pub async fn find_graph(&mut self, graph_id: &Uuid) -> anyhow::Result<Option<Graph>> {
        let row = sqlx::query_as::<_, Graph>(
            "SELECT *
             FROM graph
             WHERE graph_id = ?",
        )
        .bind(graph_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn get_graph_operator(&mut self, graph_id: &Uuid) -> anyhow::Result<Option<String>> {
        #[derive(sqlx::FromRow)]
        struct OperatorRow {
            operator_pubkey: String,
        }
        if let Some(operator_raw) = sqlx::query_as!(
            OperatorRow,
            "SELECT  operator_pubkey  FROM graph WHERE  graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?
        {
            Ok(Some(operator_raw.operator_pubkey))
        } else {
            Ok(None)
        }
    }

    pub async fn find_graphs(&mut self, params: GraphQuery) -> anyhow::Result<(Vec<Graph>, i64)> {
        // Build base query
        let mut count_params = params.clone();
        (count_params.offset, count_params.limit) = (None, None);
        let query_builder = params.get_query_builder(
            "SELECT graph_id,
                    instance_id,
                    kickoff_index,
                    from_addr,
                    to_addr,
                    graph_ipfs_base_url,
                    amount,
                    challenge_amount,
                    status,
                    sub_status,
                    operator_pubkey,
                    cur_prekickoff_txid,
                    next_prekickoff,
                    force_skip_kickoff_txid,
                    quick_challenge_txid,
                    challenge_incomplete_kickoff_txid,
                    pegin_txid,
                    kickoff_txid,
                    take1_txid,
                    challenge_txid,
                    take2_txid,
                    disprove_txid,
                    watchtower_challenge_init_txid,
                    watchtower_challenge_timeout_txids,
                    nack_txids,
                    blockhash_commit_timeout_txid,
                    assert_init_txid,
                    assert_commit_timeout_txids,
                    init_withdraw_tx_hash,
                    bridge_out_start_at,
                    zkm_version,
                    CASE
                        WHEN bridge_out_start_at > 0
                        THEN bridge_out_start_at
                        ELSE created_at
                    END AS created_at,
                    updated_at
             FROM graph",
        );

        let count_query_builder =
            count_params.get_query_builder("SELECT count(graph_id) as total_graphs FROM graph");
        let sql = query_builder.get_sql();
        let mut graphs_query = sqlx::query_as::<_, Graph>(&sql);
        graphs_query = query_builder.query_as(graphs_query);
        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);

        Ok((
            graphs_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_graphs"),
        ))
    }

    pub async fn find_graphs_by_status_group_by_operator(
        &mut self,
        status: &str,
    ) -> anyhow::Result<Vec<Graph>> {
        let row = sqlx::query_as::<_, Graph>(
            "SELECT * 
             FROM graph
             WHERE status = ? ORDER BY  operator_pubkey,  kickoff_index",
        )
        .bind(status)
        .fetch_all(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn get_graphs_by_instance_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as::<_, Graph>(
            "SELECT * 
             FROM graph
             WHERE instance_id = ?",
        )
        .bind(instance_id)
        .fetch_all(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn get_graph_pre_kickoff_chain_by_cur_pre_kickoff(
        &mut self,
        current_pre_kickoff: SerializableTxid,
    ) -> anyhow::Result<Option<(Uuid, Uuid, SerializableTxid, SerializableTxid)>> {
        #[derive(sqlx::FromRow)]
        struct NextPrekickoffRow {
            pub graph_id: Uuid,
            pub instance_id: Uuid,
            pub cur_prekickoff_txid: SerializableTxid,
            pub next_prekickoff: SerializableTxid,
        }
        let res = sqlx::query_as::<_, NextPrekickoffRow>(
            "SELECT graph_id,  instance_id,  cur_prekickoff_txid, next_prekickoff FROM graph WHERE cur_prekickoff_txid  = ?",
        )
        .bind(current_pre_kickoff)
        .fetch_optional(self.conn())
        .await?;
        Ok(res.map(|v| (v.graph_id, v.instance_id, v.cur_prekickoff_txid, v.next_prekickoff)))
    }

    pub async fn update_graphs_status_by_instance_ids(
        &mut self,
        status: &str,
        ids: &[Uuid],
    ) -> anyhow::Result<()> {
        let current_time = get_current_timestamp_secs();
        let query_str = format!(
            "UPDATE graph SET \
                status = \'{status}\',
                updated_at = {current_time}
            WHERE hex(instance_id)
                     COLLATE NOCASE IN ({})",
            create_place_holders(ids)
        );
        let mut update_query = sqlx::query(&query_str);
        for id in ids {
            update_query = update_query.bind(hex::encode(id));
        }
        update_query.execute(self.conn()).await?;
        Ok(())
    }

    pub async fn get_graphs_ids_and_operator_by_instance_ids(
        &mut self,
        ids: &[Uuid],
    ) -> anyhow::Result<Vec<(Uuid, Uuid, String)>> {
        #[derive(sqlx::FromRow)]
        struct GraphIdRow {
            pub graph_id: Uuid,
            pub instance_id: Uuid,
            pub operator: String,
        }
        let query_str = format!(
            "SELECT graph_id, instance_id, operator
             FROM graph
             WHERE hex(instance_id)
                       COLLATE NOCASE IN ({})",
            create_place_holders(ids)
        );
        let mut update_query = sqlx::query_as::<_, GraphIdRow>(&query_str);
        for id in ids {
            update_query = update_query.bind(hex::encode(id));
        }
        let graph_ids = update_query.fetch_all(self.conn()).await?;
        Ok(graph_ids.into_iter().map(|v| (v.graph_id, v.instance_id, v.operator)).collect())
    }

    pub async fn get_operator_graphs(&mut self, params: GraphQuery) -> anyhow::Result<Vec<Graph>> {
        let graph_query_builder = params.get_query_builder("SELECT * FROM graph");
        let operator_graph_sql = graph_query_builder.get_sql();
        let mut operator_graphs_query = sqlx::query_as::<_, Graph>(&operator_graph_sql);
        operator_graphs_query = graph_query_builder.query_as(operator_graphs_query);
        Ok(operator_graphs_query.fetch_all(self.conn()).await?)
    }

    pub async fn get_operator_max_kickoff_index(
        &mut self,
        operator_pubkey: &str,
    ) -> anyhow::Result<(Option<Uuid>, i64)> {
        #[derive(sqlx::FromRow)]
        struct MaxPreKickoffIndexRow {
            pub graph_id: Uuid,
            pub kickoff_index: i64,
        }

        let record = sqlx::query_as!(
            MaxPreKickoffIndexRow,
            "SELECT graph_id AS  \"graph_id:Uuid\", kickoff_index
                    FROM graph
                    WHERE operator_pubkey = ?
                    ORDER BY kickoff_index DESC
                    limit 1",
            operator_pubkey
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(record.map_or((None, 0), |v| (Some(v.graph_id), v.kickoff_index)))
    }

    pub async fn update_node_timestamp(
        &mut self,
        peer_id: &str,
        timestamp: i64,
    ) -> anyhow::Result<()> {
        let result =
            sqlx::query!(r#"UPDATE node SET updated_at = ? WHERE peer_id = ?"#, timestamp, peer_id)
                .execute(self.conn())
                .await?;

        if result.rows_affected() == 0 {
            warn!("Node {peer_id} not found in DB, no rows updated");
        }

        Ok(())
    }

    pub async fn update_graphs_status_with_instance_id(
        &mut self,
        instance_id: Uuid,
        ignore_graph_id: Option<Uuid>,
        status: &str,
    ) -> anyhow::Result<()> {
        if let Some(ignore_graph_id) = ignore_graph_id {
            sqlx::query!(
                "UPDATE graph SET status = ? WHERE instance_id = ? AND graph_id != ? ",
                status,
                instance_id,
                ignore_graph_id
            )
            .execute(self.conn())
            .await?;
        } else {
            sqlx::query!(
                "UPDATE graph SET status = ? WHERE instance_id = ?  ",
                status,
                instance_id,
            )
            .execute(self.conn())
            .await?;
        }
        Ok(())
    }

    /// Insert or update node without reward field
    pub async fn upsert_node(&mut self, node: Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            r#"
            INSERT INTO node (peer_id, node_name, actor, goat_addr, btc_pub_key, socket_addr, service_fee_rate, available_peg_btc,
                              created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (peer_id) DO UPDATE SET actor             = excluded.actor,
                                                node_name         = excluded.node_name,
                                                goat_addr         = excluded.goat_addr,
                                                btc_pub_key       = excluded.btc_pub_key,
                                                service_fee_rate       = excluded.service_fee_rate,
                                                available_peg_btc = excluded.available_peg_btc,
                                                socket_addr       = excluded.socket_addr,
                                                updated_at        = excluded.updated_at
            "#,
            node.peer_id,
            node.node_name,
            node.actor,
            node.goat_addr,
            node.btc_pub_key,
            node.socket_addr,
            node.service_fee_rate,
            node.available_peg_btc,
            node.created_at,
            node.updated_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    // Do not update the `updated_at` field; this field is updated based on heartbeat messages
    // and is used to determine whether a node is alive.
    pub async fn add_node_reward_by_addr(
        &mut self,
        goat_addr: &str,
        reward_add: i64,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"UPDATE node SET reward = reward + ? WHERE goat_addr = ?"#,
            reward_add,
            goat_addr
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn add_node_peg_btc_by_addr(
        &mut self,
        goat_addr: &str,
        peg_btc: i64,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"UPDATE node SET available_peg_btc = ? WHERE goat_addr = ?"#,
            peg_btc,
            goat_addr
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn get_node_by_btc_pub_key(
        &mut self,
        btc_pub_key: &str,
    ) -> anyhow::Result<Option<Node>> {
        Ok(sqlx::query_as!(Node, r#"SELECT *  FROM node WHERE btc_pub_key = ?"#, btc_pub_key)
            .fetch_optional(self.conn())
            .await?)
    }

    pub async fn find_nodes(&mut self, params: &NodeQuery) -> anyhow::Result<(Vec<Node>, i64)> {
        let data_query_builder = params.get_query_builder("SELECT *  FROM node");
        let mut count_params = params.clone();
        (count_params.offset, count_params.limit) = (None, None);
        let count_query_builder =
            count_params.get_query_builder("SELECT count(peer_id) as total_nodes FROM node");

        let data_sql = data_query_builder.get_sql();
        let mut nodes_query = sqlx::query_as::<_, Node>(&data_sql);
        nodes_query = data_query_builder.query_as(nodes_query);

        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);

        Ok((
            nodes_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_nodes"),
        ))
    }

    pub async fn node_overview(&mut self, time_threshold: i64) -> anyhow::Result<NodesOverview> {
        let records = sqlx::query!(
            r#"SELECT count(*) AS total,
                    actor,
                    SUM(CASE WHEN updated_at >= ? THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN updated_at < ? THEN 1 ELSE 0 END) AS offline
             FROM node
             GROUP BY actor"#,
            time_threshold,
            time_threshold
        )
        .fetch_all(self.conn())
        .await?;

        let mut res = NodesOverview::default();
        for record in records {
            res.total += record.total;
            match record.actor.as_str() {
                "Challenger" => {
                    (res.offline_challenger, res.online_challenger) =
                        (record.offline, record.online);
                }
                "Operator" => {
                    (res.offline_operator, res.online_operator) = (record.offline, record.online);
                }
                "Committee" => {
                    (res.offline_committee, res.online_committee) = (record.offline, record.online);
                }
                "Relayer" => {
                    (res.offline_watchtower, res.online_watchtower) =
                        (record.offline, record.online);
                }
                _ => {}
            };
        }
        Ok(res)
    }

    pub async fn node_by_id(&mut self, peer_id: &str) -> anyhow::Result<Option<Node>> {
        let res = sqlx::query_as!(Node, r#"SELECT * FROM node WHERE peer_id = ?"#, peer_id)
            .fetch_optional(self.conn())
            .await?;
        Ok(res)
    }

    pub async fn get_sum_bridge_in(&mut self, statuses: &[String]) -> anyhow::Result<(i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct BridgeInRow {
            pub total: i64,
            pub tx_count: i64,
        }

        let query_str = format!(
            "SELECT SUM(amount) AS total, COUNT(*) AS tx_count
             FROM instance
             WHERE status IN ({})",
            create_place_holders(statuses)
        );
        let mut query = sqlx::query_as::<_, BridgeInRow>(&query_str);
        for status in statuses {
            query = query.bind(status);
        }
        let record = query.fetch_one(self.conn()).await?;
        Ok((record.total, record.tx_count))
    }

    pub async fn get_sum_bridge_out(&mut self, statuses: &[String]) -> anyhow::Result<(i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct BridgeOutRow {
            pub total: i64,
            pub tx_count: i64,
        }

        let query_str = format!(
            "SELECT SUM(amount) AS total, COUNT(*) AS tx_count
            FROM graph
            WHERE status IN
                  ({})",
            create_place_holders(statuses)
        );
        let mut query = sqlx::query_as::<_, BridgeOutRow>(&query_str);
        for status in statuses {
            query = query.bind(status);
        }
        let record = query.fetch_one(self.conn()).await?;
        Ok((record.total, record.tx_count))
    }

    pub async fn get_nodes_info(&mut self, time_threshold: i64) -> anyhow::Result<(i64, i64)> {
        let total = sqlx::query!(r#"SELECT COUNT(peer_id) AS total FROM node"#)
            .fetch_one(self.conn())
            .await?
            .total;
        let time_pri =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 - time_threshold;
        tracing::info!("{time_pri}");
        let alive = sqlx::query!(
            r#"SELECT COUNT(peer_id) AS alive FROM node WHERE updated_at >= ?"#,
            time_pri
        )
        .fetch_one(self.conn())
        .await?
        .alive;
        Ok((total, alive))
    }

    pub async fn update_messages_state(
        &mut self,
        message_id: &str,
        message_version: i64,
        state: String,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "Update  message Set state = ?, updated_at = ? WHERE message_id = ? AND  message_version = ?",
           state,
          current_time,
          message_id,
          message_version

        ).execute(self.conn()).await?;

        Ok(res.rows_affected() > 0)
    }

    pub async fn update_messages_lock_time_until(
        &mut self,
        message_id: &str,
        message_version: i64,
        lock_time_until: i64,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "Update  message Set lock_time_until = ?, updated_at = ? WHERE message_id = ? AND  message_version = ?",
            lock_time_until,
            current_time,
            message_id,
            message_version

        ).execute(self.conn()).await?;

        Ok(res.rows_affected() > 0)
    }

    pub async fn set_messages_expired(&mut self, expired: i64) -> anyhow::Result<()> {
        sqlx::query!(
            r#"UPDATE message
             SET state = 'Expired'
             WHERE state IN ('Pending', 'Processing')
               AND updated_at < ?"#,
            expired
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn delete_old_messages(&mut self, expired: i64) -> anyhow::Result<()> {
        sqlx::query!(r#"DELETE FROM message WHERE  updated_at < ?"#, expired)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn find_messages_by_id(
        &mut self,
        message_id: &str,
    ) -> anyhow::Result<Option<Message>> {
        let res = sqlx::query_as!(
            Message,
            "SELECT message_id,
                    business_id AS \"business_id:Uuid\",
                    from_peer,
                    actor,
                    msg_type,
                    content,
                    message_version,
                    state,
                    weight,
                    lock_time_until
             FROM message
             WHERE message_id = ?",
            message_id,
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn filter_messages(
        &mut self,
        state: String,
        weight: i64,
        lock_time_until: i64,
        expired: i64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Message>> {
        let res = sqlx::query_as!(
            Message,
            "SELECT message_id,
                    business_id AS \"business_id:Uuid\",
                    from_peer,
                    actor,
                    msg_type,
                    content,
                    message_version,
                    state,
                    weight,
                    lock_time_until
             FROM message
             WHERE state = ?
               AND weight >= ?
               AND lock_time_until <= ?
               AND updated_at >= ?
             ORDER BY created_at ASC
             LIMIT ? OFFSET ?",
            state,
            weight,
            lock_time_until,
            expired,
            limit,
            offset
        )
        .fetch_all(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn upsert_message(&mut self, msg: Message) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            r#"INSERT INTO message (message_id, business_id, from_peer, actor, msg_type, content, state, message_version,  lock_time_until, weight, updated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(message_id)  DO UPDATE SET business_id = excluded.business_id,
                                                    from_peer = excluded.from_peer,
                                                    actor = excluded.actor,
                                                    msg_type = excluded.msg_type,
                                                    content = excluded.content,
                                                    state = excluded.state,
                                                    message_version = message.message_version + 1,
                                                    lock_time_until = excluded.lock_time_until,
                                                    weight = excluded.weight,
                                                    updated_at = excluded.updated_at"#,
            msg.message_id,
            msg.business_id,
            msg.from_peer,
            msg.actor,
            msg.msg_type,
            msg.content,
            msg.state,
            msg.message_version,
            msg.lock_time_until,
            msg.weight,
            current_time,
            current_time

        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn upsert_pegin_instance_process_data(
        &mut self,
        pegin_instance_process_data: &PeginInstanceProcessData,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO pegin_instance_process_data
                (instance_id, process_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(instance_id) DO UPDATE
                SET process_data = excluded.process_data,
                    updated_at       = excluded.updated_at",
            pegin_instance_process_data.instance_id,
            pegin_instance_process_data.process_data,
            pegin_instance_process_data.created_at,
            pegin_instance_process_data.updated_at
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_pegin_instance_process_data(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<PeginInstanceProcessData>> {
        let row = sqlx::query_as!(
            PeginInstanceProcessData,
            "SELECT 
                instance_id AS  \"instance_id:Uuid\", 
                process_data, 
                created_at,
                updated_at
             FROM pegin_instance_process_data
             WHERE instance_id = ?",
            instance_id
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn upsert_pegin_graph_process_data(
        &mut self,
        pegin_graph_process_data: &PeginGraphProcessData,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO pegin_graph_process_data
                (graph_id, instance_id, process_data, is_endorsed, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(graph_id) DO UPDATE
                SET process_data = excluded.process_data,
                    instance_id  = excluded.instance_id,
                    is_endorsed  = excluded.is_endorsed,
                    updated_at   = excluded.updated_at",
            pegin_graph_process_data.graph_id,
            pegin_graph_process_data.instance_id,
            pegin_graph_process_data.process_data,
            pegin_graph_process_data.is_endorsed,
            pegin_graph_process_data.created_at,
            pegin_graph_process_data.updated_at
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_pegin_graph_process_data(
        &mut self,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<PeginGraphProcessData>> {
        let row = sqlx::query_as!(
            PeginGraphProcessData,
            "SELECT
                graph_id AS  \"graph_id:Uuid\",
                instance_id AS  \"instance_id:Uuid\", 
                process_data,
                is_endorsed,
                created_at,
                updated_at
             FROM pegin_graph_process_data
             WHERE graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn update_pegin_graph_endorsed(
        &mut self,
        graph_id: &Uuid,
        is_endorsed: bool,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"UPDATE
                    pegin_graph_process_data
               SET  is_endorsed = ?
               WHERE graph_id = ?"#,
            is_endorsed,
            graph_id
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }
    pub async fn get_pegin_graph_endorsed_len_by_instance_id(
        &mut self,
        instance_id: &Uuid,
        is_endorsed: bool,
    ) -> anyhow::Result<i64> {
        let record = sqlx::query!(
            r#"SELECT count(*) AS length 
               FROM pegin_graph_process_data
               WHERE instance_id = ? AND is_endorsed = ?"#,
            instance_id,
            is_endorsed
        )
        .fetch_one(self.conn())
        .await?;
        Ok(record.length)
    }

    pub async fn upsert_graph_raw_data(
        &mut self,
        graph_raw_data: GraphRawData,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query!(
            r#"
            INSERT OR REPLACE INTO graph_raw_data (graph_id, raw_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
            graph_raw_data.graph_id,
            graph_raw_data.raw_data,
            graph_raw_data.created_at,
            graph_raw_data.updated_at
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_graph_raw_data(
        &mut self,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<GraphRawData>> {
        let row = sqlx::query_as!(
            GraphRawData,
            "SELECT
                graph_id AS \"graph_id:Uuid\",
                raw_data,
                created_at,
                updated_at
            FROM graph_raw_data WHERE graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row)
    }

    pub async fn update_graph_raw_data(
        &mut self,
        graph_id: &Uuid,
        raw_data: &str,
    ) -> anyhow::Result<u64> {
        let timestamp = get_current_timestamp_millis();

        let result = sqlx::query!(
            r#"
            UPDATE graph_raw_data
            SET raw_data = ?, updated_at = ?
            WHERE graph_id = ?
            "#,
            raw_data,
            timestamp,
            graph_id
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_graph_raw_data(&mut self, graph_id: &str) -> anyhow::Result<u64> {
        let result = sqlx::query!(r#"DELETE FROM graph_raw_data WHERE graph_id = ?"#, graph_id)
            .execute(self.conn())
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_message_broadcast_times(
        &mut self,
        graph_id: &Uuid,
        graph_status: &str,
        msg_type: &str,
    ) -> anyhow::Result<(i64, i64)> {
        let res = sqlx::query!(
            "SELECT msg_times, updated_at
             FROM message_broadcast
             WHERE graph_id = ?
               AND graph_status = ?
               AND msg_type = ?",
            graph_status,
            graph_id,
            msg_type
        )
        .fetch_optional(self.conn())
        .await?;
        match res {
            Some(row) => Ok((row.msg_times, row.updated_at)),
            None => Ok((0, 0)),
        }
    }

    pub async fn find_message_broadcasts(
        &mut self,
        graph_status: &str,
    ) -> anyhow::Result<Vec<MessageBroadcast>> {
        let records = sqlx::query_as!(
            MessageBroadcast,
            "SELECT graph_id AS \"graph_id:Uuid\", graph_status, msg_type, msg_times, created_at, updated_at
            FROM message_broadcast
            WHERE graph_status = ? ",
            graph_status
        ).fetch_all(self.conn()).await?;
        Ok(records)
    }

    pub async fn add_message_broadcast_times(
        &mut self,
        graph_id: &Uuid,
        graph_status: &str,
        msg_type: &str,
        add_times: i64,
    ) -> anyhow::Result<()> {
        let current_time = get_current_timestamp_secs();
        sqlx::query!(
            "INSERT INTO message_broadcast (graph_id, graph_status, msg_type, msg_times, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(graph_id, graph_status, msg_type) DO UPDATE SET updated_at = excluded.updated_at,
                                                           msg_times  = message_broadcast.msg_times + excluded.msg_times",
            graph_id,
            graph_status,
            msg_type,
            add_times,
            current_time,
            current_time,
        ).execute(self.conn()).await?;
        Ok(())
    }

    pub async fn get_block_execution_start_time(
        &mut self,
        block_number: i64,
    ) -> anyhow::Result<i64> {
        #[derive(sqlx::FromRow)]
        struct TimestampRow {
            created_at: Option<i64>,
        }

        let row = sqlx::query_as!(
            TimestampRow,
            r#"
            SELECT
                created_at as "created_at?: i64"
            FROM block_proof
            WHERE block_number = ?
            "#,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row.and_then(|r| r.created_at).unwrap_or(0))
    }

    pub async fn create_block_proving_task(
        &mut self,
        block_number: i64,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            INSERT INTO block_proof
                (block_number, state, created_at, updated_at)
            VALUES 
                (?, ?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                state = excluded.state,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
            block_number,
            state,
            timestamp,
            timestamp,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn delete_block_proofs(&mut self, block_number: i64) -> anyhow::Result<()> {
        sqlx::query!(r#"DELETE FROM block_proof WHERE block_number < ?"#, block_number)
            .execute(self.conn())
            .await?;

        Ok(())
    }

    pub async fn update_block_executed(
        &mut self,
        block_number: i64,
        tx_count: i64,
        gas_used: i64,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            UPDATE block_proof 
            SET 
                tx_count = ?, 
                gas_used = ?, 
                state = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            tx_count,
            gas_used,
            state,
            timestamp,
            block_number
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_block_proved(
        &mut self,
        block_number: i64,
        proving_time: i64,
        proving_cycles: i64,
        proof: &[u8],
        public_values: &[u8],
        verifier_id: String,
        zkm_version: &str,
        state: String,
    ) -> anyhow::Result<()> {
        let end_timestamp = get_current_timestamp_millis();

        let start_timestamp = self.get_block_execution_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size = proof.len() as i64;
        let proof = hex::encode(proof);

        let public_values = hex::encode(public_values);

        sqlx::query!(
            r#"
            UPDATE block_proof 
            SET
                total_time_to_proof = ?,
                proving_time = ?, 
                proving_cycles = ?, 
                proof = ?,
                proof_size = ?,
                public_values = ?,
                verifier_id = ?,
                zkm_version = ?,
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            total_time_to_proof,
            proving_time,
            proving_cycles,
            proof,
            proof_size,
            public_values,
            verifier_id,
            zkm_version,
            state,
            "",
            end_timestamp,
            block_number,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn update_block_proving_failed(
        &mut self,
        block_number: i64,
        state: String,
        reason: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();
        let reason = truncate_string(&reason, 100);

        sqlx::query!(
            r#"
            UPDATE block_proof 
            SET 
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            state,
            reason,
            timestamp,
            block_number
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn get_block_proof(
        &mut self,
        block_number: i64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, String, String)> {
        #[derive(sqlx::FromRow)]
        struct BlockProofRow {
            proof: String,
            public_values: String,
            verifier_id: String,
            zkm_version: String,
        }

        let row = sqlx::query_as!(
            BlockProofRow,
            r#"
            SELECT proof, public_values, verifier_id, zkm_version
            FROM block_proof
            WHERE block_number = ?
            "#,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(r) => {
                let proof = hex::decode(r.proof)?;
                let public_values = hex::decode(r.public_values)?;
                Ok((proof, public_values, r.verifier_id, r.zkm_version))
            }
            None => {
                Ok((Default::default(), Default::default(), Default::default(), Default::default()))
            }
        }
    }

    pub async fn get_last_continuous_number(&mut self) -> anyhow::Result<Option<i64>> {
        #[derive(sqlx::FromRow)]
        struct BlockNumberRow {
            block_number: Option<i64>,
        }

        let row = sqlx::query_as!(
            BlockNumberRow,
            r#"
            SELECT MIN(block_number) as block_number
            FROM block_proof
            WHERE state != 'proved'
            "#,
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(if let Some(r) = row { r.block_number } else { None })
    }

    pub async fn create_aggregation_task(
        &mut self,
        block_number: i64,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            INSERT INTO aggregation_proof 
                (block_number, state, created_at, updated_at)
            VALUES
                (?, ?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                state = excluded.state,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
            block_number,
            state,
            timestamp,
            timestamp,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn delete_aggregation_proofs(&mut self, block_number: i64) -> anyhow::Result<()> {
        sqlx::query!(r#"DELETE FROM aggregation_proof WHERE block_number < ?"#, block_number)
            .execute(self.conn())
            .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_aggregation_succ(
        &mut self,
        block_number: i64,
        proving_time: i64,
        proving_cycles: i64,
        proof: &[u8],
        public_values: &[u8],
        verifier_id: String,
        zkm_version: &str,
        state: String,
    ) -> anyhow::Result<()> {
        let end_timestamp = get_current_timestamp_millis();

        let start_timestamp = self.get_aggregation_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size = proof.len() as i64;
        let proof = hex::encode(proof);

        let public_values = hex::encode(public_values);

        sqlx::query!(
            r#"
            UPDATE aggregation_proof 
            SET
                total_time_to_proof = ?,
                proving_time = ?, 
                proving_cycles = ?, 
                proof = ?,
                proof_size = ?,
                public_values = ?,
                verifier_id = ?,
                zkm_version = ?,
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            total_time_to_proof,
            proving_time,
            proving_cycles,
            proof,
            proof_size,
            public_values,
            verifier_id,
            zkm_version,
            state,
            "",
            end_timestamp,
            block_number,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn update_aggregation_failed(
        &mut self,
        block_number: i64,
        state: String,
        reason: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();
        let reason = truncate_string(&reason, 100);

        sqlx::query!(
            r#"
            UPDATE aggregation_proof 
            SET 
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            state,
            reason,
            timestamp,
            block_number
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn get_aggregation_start_time(&mut self, block_number: i64) -> anyhow::Result<i64> {
        #[derive(sqlx::FromRow)]
        struct TimestampRow {
            created_at: Option<i64>,
        }

        let row = sqlx::query_as!(
            TimestampRow,
            r#"
            SELECT
                created_at as "created_at?: i64"
            FROM aggregation_proof
            WHERE block_number = ?
            "#,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row.and_then(|r| r.created_at).unwrap_or(0))
    }

    pub async fn get_aggregation_proof(
        &mut self,
        block_number: i64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, String, String)> {
        #[derive(sqlx::FromRow)]
        struct AggregationProofRow {
            proof: String,
            public_values: String,
            verifier_id: String,
            zkm_version: String,
        }

        let row = sqlx::query_as!(
            AggregationProofRow,
            r#"
            SELECT proof, public_values, verifier_id, zkm_version
            FROM aggregation_proof
            WHERE block_number = ?
            "#,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(r) => {
                let proof = hex::decode(r.proof)?;
                let public_values = hex::decode(r.public_values)?;
                Ok((proof, public_values, r.verifier_id, r.zkm_version))
            }
            None => {
                Ok((Default::default(), Default::default(), Default::default(), Default::default()))
            }
        }
    }

    pub async fn get_last_aggregation_number(&mut self) -> anyhow::Result<Option<i64>> {
        #[derive(sqlx::FromRow)]
        struct BlockNumberRow {
            block_number: Option<i64>,
        }

        let row = sqlx::query_as!(
            BlockNumberRow,
            r#"
            SELECT MAX(block_number) as block_number
            FROM aggregation_proof
            WHERE state = 'proved'
            "#,
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(if let Some(r) = row { r.block_number } else { None })
    }

    pub async fn create_groth16_task(
        &mut self,
        block_number: i64,
        start_number: i64,
        real_numbers: String,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            INSERT INTO groth16_proof 
                (block_number, start_number, real_numbers, state, created_at, updated_at)
            VALUES
                (?, ?, ?, ?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                start_number = excluded.start_number,
                real_numbers = excluded.real_numbers,
                state = excluded.state,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
            block_number,
            start_number,
            real_numbers,
            state,
            timestamp,
            timestamp
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_groth16_succ(
        &mut self,
        block_number: i64,
        init_number: i64,
        proving_time: i64,
        proving_cycles: i64,
        proof: &[u8],
        public_values: &[u8],
        verifier_id: String,
        zkm_version: &str,
        state: String,
    ) -> anyhow::Result<()> {
        let end_timestamp = get_current_timestamp_millis();
        let start_timestamp = self.get_groth16_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size = proof.len() as f64;
        let proof = hex::encode(proof);

        let public_values = hex::encode(public_values);

        sqlx::query!(
            r#"
            UPDATE groth16_proof 
            SET
                init_number = ?,
                total_time_to_proof = ?,
                proving_time = ?, 
                proving_cycles = ?, 
                proof = ?,
                proof_size = ?,
                public_values = ?,
                verifier_id = ?,
                zkm_version = ?,
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            init_number,
            total_time_to_proof,
            proving_time,
            proving_cycles,
            proof,
            proof_size,
            public_values,
            verifier_id,
            zkm_version,
            state,
            "",
            end_timestamp,
            block_number,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn update_groth16_failed(
        &mut self,
        block_number: i64,
        state: String,
        reason: String,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();
        let reason = truncate_string(&reason, 100);

        sqlx::query!(
            r#"
            UPDATE groth16_proof 
            SET 
                state = ?,
                reason = ?,
                updated_at = ?
            WHERE block_number = ?
            "#,
            state,
            reason,
            timestamp,
            block_number
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_groth16_proof(
        &mut self,
        block_number: i64,
        start_number: i64,
        real_numbers: &str,
        proof: &[u8],
        public_values: &[u8],
        verifier_id: &str,
        zkm_version: &str,
        state: &str,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();
        let proof = hex::encode(proof);
        let public_values = hex::encode(public_values);
        sqlx::query!(
            "INSERT INTO groth16_proof
                         (block_number, start_number, real_numbers, proof, public_values, verifier_id, zkm_version, state, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT(block_number) DO UPDATE SET proof         = excluded.proof,
                                                                 public_values = excluded.public_values,
                                                                 start_number = excluded.start_number,
                                                                 real_numbers = excluded.real_numbers,
                                                                 verifier_id   = excluded.verifier_id,
                                                                 zkm_version   = excluded.zkm_version,
                                                                 state         = excluded.state,
                                                                 updated_at    = excluded.updated_at",
            block_number,
            start_number,
            real_numbers,
            proof,
            public_values,
            verifier_id,
            zkm_version,
            state,
            timestamp,
            timestamp
        )
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn get_groth16_start_time(&mut self, block_number: i64) -> anyhow::Result<i64> {
        #[derive(sqlx::FromRow)]
        struct TimestampRow {
            created_at: Option<i64>,
        }

        let row = sqlx::query_as!(
            TimestampRow,
            r#"
            SELECT
                created_at as "created_at?: i64"
            FROM groth16_proof
            WHERE block_number = ?
            "#,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row.and_then(|r| r.created_at).unwrap_or(0))
    }

    pub async fn get_groth16_proof(
        &mut self,
        block_number: i64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, String, String)> {
        #[derive(sqlx::FromRow)]
        struct Groth16ProofRow {
            proof: String,
            public_values: String,
            verifier_id: String,
            zkm_version: String,
        }

        let row = sqlx::query_as!(
            Groth16ProofRow,
            r#"
            SELECT proof, public_values, verifier_id, zkm_version
            FROM groth16_proof
            WHERE block_number >= ? AND start_number <= ?
            "#,
            block_number,
            block_number
        )
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(r) => {
                let proof = hex::decode(r.proof)?;
                let public_values = hex::decode(r.public_values)?;
                Ok((proof, public_values, r.verifier_id, r.zkm_version))
            }
            None => {
                Ok((Default::default(), Default::default(), Default::default(), Default::default()))
            }
        }
    }

    pub async fn set_block_proof_concurrency(&mut self, concurrency: i64) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            INSERT INTO proof_config
                (id, block_proof_concurrency, updated_at)
            VALUES
                (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                block_proof_concurrency = excluded.block_proof_concurrency,
                updated_at = excluded.updated_at
            "#,
            1,
            concurrency,
            timestamp,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn set_aggregation_count(
        &mut self,
        aggregate_block_count: i64,
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            UPDATE proof_config
            SET 
                aggregate_block_count = ?,
                updated_at = ?
            WHERE id = ?
            "#,
            aggregate_block_count,
            timestamp,
            1,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn set_init_number(&mut self, start_aggregation_number: i64) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();

        sqlx::query!(
            r#"
            UPDATE proof_config
            SET
                start_aggregation_number = ?,
                updated_at = ?
            WHERE id = ?
            "#,
            start_aggregation_number,
            timestamp,
            1,
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn get_proof_config(&mut self) -> anyhow::Result<(i64, i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct ProofConfig {
            block_proof_concurrency: Option<i64>,
            aggregate_block_count: Option<i64>,
            start_aggregation_number: Option<i64>,
        }

        let row = sqlx::query_as!(
            ProofConfig,
            "SELECT
                block_proof_concurrency, aggregate_block_count, start_aggregation_number
            FROM
                proof_config
            WHERE id = ?",
            1
        )
        .fetch_optional(self.conn())
        .await?;

        if let Some(row) = row {
            Ok((
                row.block_proof_concurrency.unwrap_or(1),
                row.aggregate_block_count.unwrap_or(1),
                row.start_aggregation_number.unwrap_or(2),
            ))
        } else {
            Ok((1, 1, 2))
        }
    }

    pub async fn create_verifier_key(
        &mut self,
        verifier_id: &str,
        verifier_key: &[u8],
    ) -> anyhow::Result<()> {
        let timestamp = get_current_timestamp_millis();
        let verifier_key = hex::encode(verifier_key);

        sqlx::query!(
            r#"
            INSERT OR IGNORE INTO verifier_key
                (verifier_id, verifier_key, created_at) 
            VALUES
                (?, ?, ?)
            "#,
            verifier_id,
            verifier_key,
            timestamp
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn get_verifier_key(&mut self, verifier_id: &str) -> anyhow::Result<Vec<u8>> {
        #[derive(sqlx::FromRow)]
        struct VerifierKeyRow {
            verifier_key: String,
        }

        let row = sqlx::query_as!(
            VerifierKeyRow,
            r#"
            SELECT verifier_key
            FROM verifier_key
            WHERE verifier_id = ?
            "#,
            verifier_id
        )
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(r) => Ok(hex::decode(r.verifier_key)?),
            None => Ok(Default::default()),
        }
    }

    pub async fn get_groth16_vk(&mut self, zkm_version: &str) -> anyhow::Result<Vec<u8>> {
        #[derive(sqlx::FromRow)]
        struct VerifierKeyRow {
            verifier_key: String,
        }

        let row = sqlx::query_as!(
            VerifierKeyRow,
            r#"
            SELECT verifier_key
            FROM verifier_key
            WHERE verifier_id = ?
            "#,
            zkm_version
        )
        .fetch_optional(self.conn())
        .await?;

        match row {
            Some(r) => Ok(hex::decode(r.verifier_key)?),
            None => Ok(Default::default()),
        }
    }

    pub async fn get_watch_contract(
        &mut self,
        addr: &str,
    ) -> anyhow::Result<Option<WatchContract>> {
        Ok(sqlx::query_as!(
            WatchContract,
            "SELECT addr, the_graph_url, from_height, gap, status, extra, updated_at
             FROM watch_contract
             WHERE addr = ? ",
            addr
        )
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn upsert_watch_contract(
        &mut self,
        watch_contract: &WatchContract,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "INSERT OR
             REPLACE INTO watch_contract (addr, the_graph_url, gap, from_height, status, extra, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            watch_contract.addr,
            watch_contract.the_graph_url,
            watch_contract.gap,
            watch_contract.from_height,
            watch_contract.status,
            watch_contract.extra,
            watch_contract.updated_at,
        ).execute(self.conn()).await;
        Ok(())
    }

    pub async fn update_watch_contract_status(
        &mut self,
        addr: &str,
        status: &str,
        updated_at: i64,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "UPDATE watch_contract SET status =?,  updated_at=? WHERE addr =?",
            status,
            updated_at,
            addr,
        )
        .execute(self.conn())
        .await;
        Ok(())
    }

    pub async fn upsert_goat_tx_record(
        &mut self,
        goat_tx_record: &GoatTxRecord,
    ) -> anyhow::Result<()> {
        let mut update_goat_tx_record = goat_tx_record.clone();
        if let Some(goat_tx_record_store) =
            self.get_graph_goat_tx_record(&goat_tx_record.graph_id, &goat_tx_record.tx_type).await?
        {
            update_goat_tx_record.created_at = goat_tx_record_store.created_at;
            update_goat_tx_record.is_local = goat_tx_record_store.is_local;
            if update_goat_tx_record.height < goat_tx_record_store.height {
                update_goat_tx_record.height = goat_tx_record_store.height;
            }
            if goat_tx_record_store.extra.is_some() && update_goat_tx_record.extra.is_none() {
                update_goat_tx_record.extra = goat_tx_record_store.extra.clone();
            }

            if !goat_tx_record_store.tx_hash.is_empty() {
                update_goat_tx_record.tx_hash = goat_tx_record_store.tx_hash.clone();
            }
        }
        sqlx::query!(
            "INSERT OR
            REPLACE INTO goat_tx_record (instance_id,
                            graph_id,
                            tx_type,
                            tx_hash,
                            height,
                            is_local,
                            processing_status,
                            extra,
                            created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            update_goat_tx_record.instance_id,
            update_goat_tx_record.graph_id,
            update_goat_tx_record.tx_type,
            update_goat_tx_record.tx_hash,
            update_goat_tx_record.height,
            update_goat_tx_record.is_local,
            update_goat_tx_record.processing_status,
            update_goat_tx_record.extra,
            update_goat_tx_record.created_at
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn get_graph_goat_tx_record(
        &mut self,
        graph_id: &Uuid,
        tx_type: &str,
    ) -> anyhow::Result<Option<GoatTxRecord>> {
        Ok(sqlx::query_as!(
            GoatTxRecord,
            "SELECT instance_id AS \"instance_id:Uuid\",
                        graph_id  AS \"graph_id:Uuid\",
                        tx_type,
                        tx_hash,
                        height,
                        is_local,
                        processing_status,
                        extra,
                        created_at
            FROM goat_tx_record
            WHERE graph_id = ?
                AND tx_type = ?",
            graph_id,
            tx_type
        )
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn get_goat_tx_record_by_processing_status(
        &mut self,
        tx_type: &str,
        processing_status: &str,
    ) -> anyhow::Result<Vec<GoatTxRecord>> {
        Ok(sqlx::query_as!(
            GoatTxRecord,
            "SELECT instance_id AS \"instance_id:Uuid\",
                        graph_id  AS \"graph_id:Uuid\",
                        tx_type, tx_hash,
                        height,
                        is_local,
                        processing_status,
                        extra,
                        created_at
            FROM goat_tx_record
            WHERE tx_type = ?
                AND processing_status = ?
                ORDER BY height ASC",
            tx_type,
            processing_status
        )
        .fetch_all(self.conn())
        .await?)
    }

    pub async fn get_goat_tx_records_by_height_range_and_filters(
        &mut self,
        tx_type: &str,
        processing_status: &str,
        start_number: i64,
        end_number: i64,
    ) -> anyhow::Result<Vec<i64>> {
        let records = sqlx::query!(
            "SELECT DISTINCT height
            FROM goat_tx_record
            WHERE tx_type = ?
                AND processing_status = ?
                AND height > ?
                AND height <= ?
                ORDER BY height ASC",
            tx_type,
            processing_status,
            start_number,
            end_number,
        )
        .fetch_all(self.conn())
        .await?;
        Ok(records.iter().map(|v| v.height).collect())
    }

    pub async fn get_tx_info_for_gen_proof(
        &mut self,
        block_number: i64,
        goat_tx_type: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, String)>> {
        #[derive(sqlx::FromRow)]
        struct TxInfoRow {
            graph_id: Uuid,
            zkm_version: String,
            tx_hash: String,
        }
        let tx_info_rows = sqlx::query_as!(
            TxInfoRow,
            "SELECT g.graph_id AS \"graph_id:Uuid\",
                    g.zkm_version AS zkm_version, gtr.tx_hash AS tx_hash
             FROM graph g
                     INNER JOIN goat_tx_record gtr ON g.graph_id = gtr.graph_id
             WHERE gtr.height = ?
               AND gtr.tx_type = ?",
            block_number,
            goat_tx_type
        )
        .fetch_all(self.conn())
        .await?;
        Ok(tx_info_rows.into_iter().map(|v| (v.graph_id, v.tx_hash, v.zkm_version)).collect())
    }

    pub async fn update_goat_tx_record_processing_status(
        &mut self,
        graph_id: &Uuid,
        instance_id: &Uuid,
        tx_type: &str,
        status: &str,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            "UPDATE goat_tx_record
             SET processing_status = ?
             where instance_id = ?
               AND graph_id = ?
               AND tx_type = ?",
            status,
            instance_id,
            graph_id,
            tx_type
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn get_groth16_proof_info(
        &mut self,

        block_number: i64,
    ) -> anyhow::Result<Option<ProofInfo>> {
        Ok(sqlx::query_as!(ProofInfo, "SELECT block_number, real_numbers, proving_cycles, state, proving_time, proof_size, zkm_version, created_at, updated_at
                 FROM groth16_proof
                 WHERE   block_number >= ? AND  start_number  <= ? LIMIT 1", block_number, block_number).fetch_optional(self.conn()).await?)
    }

    pub async fn get_range_proofs(
        &mut self,
        proof_type: ProofType,
        block_number_min: i64,
        block_number_max: i64,
    ) -> anyhow::Result<Vec<ProofInfo>> {
        let query = match proof_type {
            ProofType::BlockProof => {
                "SELECT block_number, CAST(block_number AS TEXT) AS real_numbers, proving_cycles, state, proving_time, proof_size, zkm_version, created_at, updated_at
                FROM block_proof
                WHERE block_number BETWEEN ? AND ?
                ORDER BY block_number ASC"
            }
            ProofType::AggregationProof => {
                "SELECT block_number, CAST(block_number AS TEXT) AS real_numbers, proving_cycles, state, proving_time, proof_size, zkm_version, created_at, updated_at
                 FROM aggregation_proof
                 WHERE block_number BETWEEN ? AND ?
                 ORDER BY block_number ASC"
            }
            ProofType::Groth16Proof => {
                "SELECT block_number, CAST(block_number AS TEXT) AS real_numbers, proving_cycles, state, proving_time, proof_size, zkm_version, created_at, updated_at
                 FROM groth16_proof
                 WHERE block_number BETWEEN ? AND ?
                 ORDER BY block_number ASC"
            }
        };

        Ok(sqlx::query_as::<_, ProofInfo>(query)
            .bind(block_number_min)
            .bind(block_number_max)
            .fetch_all(self.conn())
            .await?)
    }

    pub async fn get_proof_overview(
        &mut self,
        proof_type: ProofType,
        avg_range: i64,
    ) -> anyhow::Result<(i64, i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct OverviewProof {
            max_block_number: i64,
            total_proof_time_sum: i64,
            proof_record_count: i64,
        }
        let query = match proof_type {
            ProofType::BlockProof => {
                format!("WITH top_blocks AS (
                        SELECT total_time_to_proof
                        FROM block_proof
                        WHERE state = 'proved'
                        ORDER BY block_number DESC
                        LIMIT {avg_range}
                    )
                    SELECT
                        COALESCE((SELECT MAX(block_number) FROM block_proof), 0) AS max_block_number,
                        COALESCE((SELECT SUM(total_time_to_proof) FROM top_blocks), 0) AS total_proof_time_sum,
                        COALESCE((SELECT COUNT(*) FROM top_blocks), 0) AS proof_record_count
                    ")
            }
            ProofType::AggregationProof => {
                format!("WITH top_blocks AS (
                        SELECT total_time_to_proof
                        FROM aggregation_proof
                        WHERE state = 'proved'
                        ORDER BY block_number DESC
                        LIMIT {avg_range}
                    )
                    SELECT
                        COALESCE((SELECT MAX(block_number) FROM aggregation_proof), 0) AS max_block_number,
                        COALESCE((SELECT SUM(total_time_to_proof) FROM top_blocks), 0) AS total_proof_time_sum,
                        COALESCE((SELECT COUNT(*) FROM top_blocks), 0) AS proof_record_count")
            }
            ProofType::Groth16Proof => {
                format!("WITH top_blocks AS (
                        SELECT total_time_to_proof
                        FROM groth16_proof
                        WHERE state = 'proved'
                        ORDER BY block_number DESC
                        LIMIT {avg_range}
                    )
                    SELECT
                        COALESCE((SELECT MAX(block_number) FROM groth16_proof), 0) AS max_block_number,
                        COALESCE((SELECT SUM(total_time_to_proof) FROM top_blocks), 0) AS total_proof_time_sum,
                        COALESCE((SELECT COUNT(*) FROM top_blocks), 0) AS proof_record_count")
            }
        };
        let res = sqlx::query_as::<_, OverviewProof>(query.as_str()).fetch_one(self.conn()).await?;
        Ok((res.max_block_number, res.total_proof_time_sum, res.proof_record_count))
    }

    pub async fn get_socket_addr_for_graph_query_proof(
        &mut self,
        ids: &[Uuid],
        goat_tx_type: &str,
    ) -> anyhow::Result<HashMap<Uuid, (String, i64)>> {
        #[derive(sqlx::FromRow)]
        struct SocketInfoRow {
            pub graph_id: Uuid,
            pub socket_addr: String,
            pub height: i64,
        }
        let query_str = format!(
            "WITH filtered_tx AS (SELECT graph_id, height FROM goat_tx_record WHERE tx_type = \'{goat_tx_type}\')
            SELECT g.graph_id AS graph_id, n.socket_addr, COALESCE(ft.height, 0) AS height
            FROM graph g
                     JOIN node n
                          ON g.operator = n.btc_pub_key
                     LEFT JOIN filtered_tx ft ON g.graph_id = ft.graph_id
            WHERE hex(g.graph_id)
                      COLLATE NOCASE IN ({})",
            create_place_holders(ids)
        );
        let mut query_as = sqlx::query_as::<_, SocketInfoRow>(&query_str);
        for id in ids {
            query_as = query_as.bind(hex::encode(id));
        }
        let rows = query_as.fetch_all(self.conn()).await?;
        let res: HashMap<Uuid, (String, i64)> =
            rows.into_iter().map(|v| (v.graph_id, (v.socket_addr, v.height))).collect();
        Ok(res)
    }

    pub async fn upsert_graph_btc_tx_vout_monitor(
        &mut self,
        monitor: &GraphBtcTxVoutMonitor,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();

        let res = sqlx::query!(
            r#"
            INSERT OR REPLACE INTO graph_btc_tx_vout_monitor
            (graph_id, tx_name, txid, height, vout_len, monitor_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            monitor.graph_id,
            monitor.tx_name,
            monitor.txid,
            monitor.height,
            monitor.vout_len,
            monitor.monitor_data,
            monitor.created_at,
            current_time
        )
        .execute(self.conn())
        .await?;

        Ok(res.rows_affected())
    }

    pub async fn get_graph_btc_tx_vout_monitor(
        &mut self,
        graph_id: &Uuid,
        txid: &SerializableTxid,
    ) -> anyhow::Result<Option<GraphBtcTxVoutMonitor>> {
        let row = sqlx::query_as!(
            GraphBtcTxVoutMonitor,
            r#"
            SELECT
                graph_id AS "graph_id: Uuid",
                tx_name,
                txid AS "txid: SerializableTxid",
                height,
                vout_len,
                monitor_data,
                created_at,
                updated_at
            FROM graph_btc_tx_vout_monitor
            WHERE graph_id = ? AND txid = ?
            "#,
            graph_id,
            txid
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row)
    }

    pub async fn update_graph_btc_tx_vout_monitor_data(
        &mut self,
        graph_id: &Uuid,
        txid: &SerializableTxid,
        monitor_data: String,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE graph_btc_tx_vout_monitor
             SET monitor_data = ?,
                 updated_at   = ?
             WHERE graph_id = ? AND txid = ?",
            monitor_data,
            current_time,
            graph_id,
            txid
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn upsert_commit_info(&mut self, commit_info: &CommitInfo) -> anyhow::Result<bool> {
        let pubkeys_json = serde_json::to_string(&commit_info.publisher_public_keys)?;
        let res = sqlx::query!(
            r#"INSERT OR REPLACE INTO commit_info (txid, threshold, publisher_public_keys, commit_proof_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
            commit_info.txid,
            commit_info.threshold,
           pubkeys_json,
            commit_info.commit_proof_id,
            commit_info.created_at,
            commit_info.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_commit_info(
        &mut self,
        txid: SerializableTxid,
    ) -> anyhow::Result<Option<CommitInfo>> {
        Ok(sqlx::query_as::<_, CommitInfo>(
            "SELECT * 
                 FROM commit_info
                 WHERE txid = ?",
        )
        .bind(txid)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn update_commit_info_proof_id(
        &mut self,
        txid: SerializableTxid,
        proof_id: i64,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            r#"UPDATE commit_info SET commit_proof_id = ? WHERE txid = ?"#,
            proof_id,
            txid,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn insert_commit_chain_proof(
        &mut self,
        commit_chain_proof: &CommitChainProof,
    ) -> anyhow::Result<bool> {
        let commit_info_txids = serde_json::to_string(&commit_chain_proof.commit_info_txids)?;
        let res = sqlx::query!(
            r#"INSERT OR REPLACE INTO commit_chain_proof (commit_info_txids, in_location, prev_proof, out_location, proof,
                                vk,  public_inputs,  status, proving_time, zkm_version, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            commit_info_txids,
            commit_chain_proof.in_location,
            commit_chain_proof.prev_proof,
            commit_chain_proof.out_location,
            commit_chain_proof.proof,
            commit_chain_proof.vk,
            commit_chain_proof.public_inputs,
            commit_chain_proof.status,
            commit_chain_proof.proving_time,
            commit_chain_proof.zkm_version,
            commit_chain_proof.created_at,
            commit_chain_proof.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_commit_chain_proof_by_id(
        &mut self,
        id: i64,
    ) -> anyhow::Result<Option<CommitChainProof>> {
        Ok(sqlx::query_as::<_, CommitChainProof>(
            "SELECT * 
                 FROM commit_chain_proof
                 WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn update_commit_chain_proof_status(
        &mut self,
        id: i64,
        status: &str,
    ) -> anyhow::Result<bool> {
        let res =
            sqlx::query!(r#"UPDATE commit_chain_proof SET status = ? WHERE id = ?"#, status, id,)
                .execute(self.conn())
                .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn insert_header_chain_proof(
        &mut self,
        header_chain_proof: &HeaderChainProof,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            r#"INSERT INTO header_chain_proof (in_location,  prev_proof, batch_size, start, out_location, proof,
                                vk,  public_inputs,  status, proving_time, zkm_version, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            header_chain_proof.in_location,
            header_chain_proof.prev_proof,
            header_chain_proof.batch_size,
            header_chain_proof.start,
            header_chain_proof.out_location,
            header_chain_proof.proof,
            header_chain_proof.vk,
            header_chain_proof.public_inputs,
            header_chain_proof.status,
            header_chain_proof.proving_time,
            header_chain_proof.zkm_version,
            header_chain_proof.created_at,
            header_chain_proof.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_header_chain_proof_by_id(
        &mut self,
        id: i64,
    ) -> anyhow::Result<Option<HeaderChainProof>> {
        Ok(sqlx::query_as!(
            HeaderChainProof,
            r#"SELECT * FROM header_chain_proof WHERE id = ?"#,
            id
        )
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn update_header_chain_proof_status(
        &mut self,
        id: i64,
        status: &str,
    ) -> anyhow::Result<bool> {
        let res =
            sqlx::query!(r#"UPDATE header_chain_proof SET status = ? WHERE id = ?"#, status, id,)
                .execute(self.conn())
                .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn upsert_watchtower_proof(
        &mut self,
        watchtower_proof: &WatchtowerProof,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            r#"INSERT OR REPLACE INTO watchtower_proof (graph_id, instance_id, latest_sequencer_commit_txid, in_location, header_chain_proof,
                    commit_chain_proof, out_location,  proof, groth16_vk, public_inputs, status, proving_time, zkm_version,
                    created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            watchtower_proof.graph_id,
            watchtower_proof.instance_id,
            watchtower_proof.latest_sequencer_commit_txid,
            watchtower_proof.in_location,
            watchtower_proof.header_chain_proof,
            watchtower_proof.commit_chain_proof,
            watchtower_proof.out_location,
            watchtower_proof.proof,
            watchtower_proof.groth16_vk,
            watchtower_proof.public_inputs,
            watchtower_proof.status,
            watchtower_proof.proving_time,
            watchtower_proof.zkm_version,
            watchtower_proof.created_at,
            watchtower_proof.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_watchtower_proof(
        &mut self,
        graph_id: &Uuid,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<WatchtowerProof>> {
        Ok(sqlx::query_as::<_, WatchtowerProof>(
            "SELECT * 
                 FROM watchtower_proof
                 WHERE  graph_id = ? AND instance_id = ?",
        )
        .bind(graph_id)
        .bind(instance_id)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn update_watchtower_proof_status(
        &mut self,
        graph_id: Uuid,
        instance_id: Uuid,
        status: &str,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            r#"UPDATE 
                     watchtower_proof 
                SET status = ?
                WHERE graph_id = ? AND instance_id = ?"#,
            status,
            graph_id,
            instance_id,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn upsert_operator_proof(
        &mut self,
        operator_proof: &OperatorProof,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            r#"INSERT OR REPLACE INTO operator_proof (graph_id, instance_id,  included_watchtowers, latest_sequencer_commit_txid, in_location,
                            header_chain_proof, commit_chain_proof, execution_layer_block_number, watchtower_challenge_info, watchtower_challenge_init_txid,
                            block_headers_file_path, out_location, proof, groth16_vk, public_inputs, status, proving_time, zkm_version,
                            created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            operator_proof.graph_id,
            operator_proof.instance_id,
            operator_proof.included_watchtowers,
            operator_proof.latest_sequencer_commit_txid,
            operator_proof.in_location,
            operator_proof.header_chain_proof,
            operator_proof.commit_chain_proof,
            operator_proof.execution_layer_block_number,
            operator_proof.watchtower_challenge_info,
            operator_proof.watchtower_challenge_init_txid,
            operator_proof.block_headers_file_path,
            operator_proof.out_location,
            operator_proof.proof,
            operator_proof.groth16_vk,
            operator_proof.public_inputs,
            operator_proof.status,
            operator_proof.proving_time,
            operator_proof.zkm_version,
            operator_proof.created_at,
            operator_proof.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_operator_proof(
        &mut self,
        graph_id: &Uuid,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<OperatorProof>> {
        Ok(sqlx::query_as::<_, OperatorProof>(
            "SELECT * 
                 FROM operator_proof
                 WHERE  graph_id = ? AND instance_id = ?",
        )
        .bind(graph_id)
        .bind(instance_id)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn update_operator_proof_status(
        &mut self,
        graph_id: Uuid,
        instance_id: Uuid,
        status: &str,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "UPDATE operator_proof SET status = ? WHERE graph_id = ? AND instance_id = ?",
            status,
            graph_id,
            instance_id
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn truncate_string(s: &str, max_len: usize) -> &str {
    if s.len() > max_len { &s[..max_len] } else { s }
}

pub async fn create_local_db(db_path: &str) -> LocalDB {
    let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
    local_db.migrate().await;
    local_db
}
