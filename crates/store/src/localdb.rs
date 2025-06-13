use crate::schema::NODE_STATUS_OFFLINE;
use crate::schema::NODE_STATUS_ONLINE;
use crate::{
    COMMITTEE_PRE_SIGN_NUM, GoatTxRecord, GrapFullData, Graph, GraphTickActionMetaData, Instance,
    Message, MessageBroadcast, Node, NodesOverview, NonceCollect, NonceCollectMetaData, ProofType,
    ProofWithPis, PubKeyCollect, PubKeyCollectMetaData, WatchContract,
};

use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::types::Uuid;
use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

#[derive(Clone)]
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

#[derive(Clone, Debug)]
pub struct FilterGraphParams {
    pub status: Option<String>,
    pub is_bridge_out: bool,
    pub operator: Option<String>,
    pub from_addr: Option<String>,
    pub graph_id: Option<String>,
    pub pegin_txid: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct UpdateGraphParams {
    pub graph_id: Uuid,
    pub status: Option<String>,
    pub ipfs_base_url: Option<String>,
    pub challenge_txid: Option<String>,
    pub disprove_txid: Option<String>,
    pub bridge_out_start_at: Option<i64>,
    pub init_withdraw_txid: Option<String>,
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

    pub async fn create_instance(&mut self, instance: Instance) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  instance (instance_id, network, bridge_path, from_addr, to_addr, amount, \
            status, goat_txid, btc_txid, pegin_txid,  input_uxtos, fee, created_at, updated_at)  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            instance.instance_id,
            instance.network,
            instance.bridge_path,
            instance.from_addr,
            instance.to_addr,
            instance.amount,
            instance.status,
            instance.goat_txid,
            instance.btc_txid,
            instance.pegin_txid,
            instance.input_uxtos,
            instance.fee,
            instance.created_at,
            instance.updated_at
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<Option<Instance>> {
        let row = sqlx::query_as!(
            Instance,
            "SELECT instance_id as \"instance_id:Uuid\", network,   bridge_path, from_addr, to_addr, amount, status, goat_txid,  \
            btc_txid ,pegin_txid, input_uxtos, fee ,created_at, updated_at \
            FROM  instance where instance_id = ?",
            instance_id
        ).fetch_optional(self.conn())
            .await?;
        Ok(row)
    }

    pub async fn get_instance_network(&mut self, instance_id: &Uuid) -> anyhow::Result<String> {
        if let Some(raw) =
            sqlx::query!("SELECT  network FROM  instance where instance_id = ?", instance_id)
                .fetch_optional(self.conn())
                .await?
        {
            Ok(raw.network)
        } else {
            Ok("".to_string())
        }
    }
    pub async fn instance_list(
        &mut self,
        from_addr: Option<String>,
        bridge_path: Option<u8>,
        status: Option<String>,
        earliest_updated: Option<i64>,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> anyhow::Result<(Vec<Instance>, i64)> {
        let mut instance_query_str =
            "SELECT instance_id, network,  bridge_path, from_addr, to_addr,\
                     amount, status, goat_txid, btc_txid ,pegin_txid, \
                    created_at, updated_at, input_uxtos, fee FROM instance"
                .to_string();
        let mut instance_count_str = "SELECT count(*) as total_instances FROM instance".to_string();
        let mut conditions: Vec<String> = vec![];
        if let Some(from_addr) = from_addr {
            conditions.push(format!("from_addr = \'{from_addr}\'"));
        }
        if let Some(status) = status {
            conditions.push(format!("status = \'{status}\'"));
        }
        if let Some(bridge_path) = bridge_path {
            conditions.push(format!("bridge_path = {bridge_path}"));
        }

        if let Some(earliest_updated) = earliest_updated {
            conditions.push(format!("updated_at >= {earliest_updated}"));
        }
        if !conditions.is_empty() {
            let condition_str = conditions.join(" AND ");
            instance_query_str = format!("{instance_query_str} WHERE {condition_str}");
            instance_count_str = format!("{instance_count_str} WHERE {condition_str}");
        }

        instance_query_str = format!("{instance_query_str} ORDER BY created_at DESC ");
        if let Some(limit) = limit {
            instance_query_str = format!("{instance_query_str} LIMIT {limit}");
        }
        if let Some(offset) = offset {
            instance_query_str = format!("{instance_query_str} OFFSET {offset}");
        }
        let instances = sqlx::query_as::<_, Instance>(instance_query_str.as_str())
            .fetch_all(self.conn())
            .await?;
        let total_instances = sqlx::query(instance_count_str.as_str())
            .fetch_one(self.conn())
            .await?
            .get::<i64, &str>("total_instances");

        Ok((instances, total_instances))
    }

    /// Update Instance
    pub async fn update_instance(&mut self, instance: Instance) -> anyhow::Result<u64> {
        let row = sqlx::query!(
            "UPDATE instance SET bridge_path = ?, from_addr= ?, to_addr= ?,  network =?, \
        amount= ?, status= ?, goat_txid= ?, btc_txid= ?, pegin_txid= ?,  input_uxtos = ?,  \
        fee = ?, updated_at = ? WHERE instance_id = ?",
            instance.bridge_path,
            instance.from_addr,
            instance.to_addr,
            instance.network,
            instance.amount,
            instance.status,
            instance.goat_txid,
            instance.btc_txid,
            instance.pegin_txid,
            instance.instance_id,
            instance.input_uxtos,
            instance.fee,
            instance.updated_at,
        )
        .execute(self.conn())
        .await?;
        Ok(row.rows_affected())
    }

    /// Insert or update graph
    pub async fn update_graph(&mut self, graph: Graph) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  graph (graph_id, instance_id, graph_ipfs_base_url, pegin_txid, \
             amount, status, pre_kickoff_txid, kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
            assert_final_txid, take2_txid, disprove_txid, operator, raw_data,  bridge_out_start_at, bridge_out_from_addr,  \
            bridge_out_to_addr, init_withdraw_txid, zkm_version,  created_at, updated_at)  \
            VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ",
            graph.graph_id,
            graph.instance_id,
            graph.graph_ipfs_base_url,
            graph.pegin_txid,
            graph.amount,
            graph.status,
            graph.pre_kickoff_txid,
            graph.kickoff_txid,
            graph.challenge_txid,
            graph.take1_txid,
            graph.assert_init_txid,
            graph.assert_commit_txids,
            graph.assert_final_txid,
            graph.take2_txid,
            graph.disprove_txid,
            graph.operator,
            graph.raw_data,
            graph.bridge_out_start_at,
            graph.bridge_out_from_addr,
            graph.bridge_out_to_addr,
            graph.init_withdraw_txid,
            graph.zkm_version,
            graph.created_at,
            graph.updated_at,
        ).execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_expired_instance(
        &mut self,
        current_status: &str,
        expired_status: &str,
        time_threshold: i64,
    ) -> anyhow::Result<u64> {
        let row = sqlx::query!(
            "UPDATE instance SET status = ? WHERE status = ? AND updated_at < ?",
            expired_status,
            current_status,
            time_threshold
        )
        .execute(self.conn())
        .await?;
        Ok(row.rows_affected())
    }

    pub async fn update_instance_fields(
        &mut self,
        instance_id: &Uuid,
        status: Option<String>,
        pegin_tx_info: Option<(String, i64)>,
        goat_txid: Option<String>,
    ) -> anyhow::Result<()> {
        let instance_option = sqlx::query_as!(
            Instance,
            "SELECT instance_id as \"instance_id:Uuid\", network,   bridge_path, from_addr, to_addr, amount, status, goat_txid,  \
            btc_txid ,pegin_txid, input_uxtos, fee ,created_at, updated_at \
            FROM  instance where instance_id = ?",
            instance_id
        ).fetch_optional(self.conn())
            .await?;
        if instance_option.is_none() {
            warn!("instance :{instance_id:?} not exit");
            return Ok(());
        }
        let instance = instance_option.unwrap();
        let status = if let Some(status) = status { status } else { instance.status };

        let (pegin_txid, fee) = if let Some((pegin_txid, fee)) = pegin_tx_info {
            (Some(pegin_txid), fee)
        } else {
            (instance.pegin_txid, instance.fee)
        };
        let goat_txid =
            if let Some(goat_txid) = goat_txid { goat_txid } else { instance.goat_txid };
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let _ = sqlx::query!(
            "UPDATE instance SET status =?, pegin_txid =?, goat_txid = ?, fee = ?, updated_at = ? WHERE instance_id = ?",
            status,
            pegin_txid,
            goat_txid,
            fee,
            current_time,
            instance_id
        )
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn update_graph_fields(&mut self, params: UpdateGraphParams) -> anyhow::Result<()> {
        let mut update_fields = vec![];
        if let Some(status) = params.status {
            update_fields.push(format!("status = \'{status}\'"));
        }
        if let Some(ipfs_base_url) = params.ipfs_base_url {
            update_fields.push(format!("graph_ipfs_base_url = \'{ipfs_base_url}\'"));
        }

        if let Some(challenge_txid) = params.challenge_txid {
            update_fields.push(format!("challenge_txid = \'{challenge_txid}\'"));
        }
        if let Some(disprove_txid) = params.disprove_txid {
            update_fields.push(format!("disprove_txid = \'{disprove_txid}\'"));
        }
        if let Some(bridge_out_start_at) = params.bridge_out_start_at {
            update_fields.push(format!("bridge_out_start_at = {bridge_out_start_at}"));
        }
        if let Some(init_withdraw_txid) = params.init_withdraw_txid {
            if init_withdraw_txid.is_empty() {
                update_fields.push("init_withdraw_txid = NULL".to_string());
            } else {
                update_fields.push(format!("init_withdraw_txid = \'{init_withdraw_txid}\'"));
            }
        }
        if update_fields.is_empty() {
            return Ok(());
        }
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        update_fields.push(format!("updated_at = {current_time}"));

        let update_str = format!(
            "UPDATE graph SET {} WHERE hex(graph_id) = \'{}\' COLLATE NOCASE ",
            update_fields.join(" , "),
            hex::encode(params.graph_id)
        );
        let _ = sqlx::query(update_str.as_str()).execute(self.conn()).await?;
        Ok(())
    }

    pub async fn get_graph(&mut self, graph_id: &Uuid) -> anyhow::Result<Option<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \", instance_id  as \"instance_id:Uuid \", graph_ipfs_base_url, \
             pre_kickoff_txid, pegin_txid, amount, status, kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
              assert_final_txid, take2_txid, disprove_txid, operator, raw_data,bridge_out_start_at,  bridge_out_from_addr, bridge_out_to_addr,\
              init_withdraw_txid, zkm_version, created_at, updated_at  FROM graph WHERE  graph_id = ?",
            graph_id
        ).fetch_optional(self.conn()).await?;
        Ok(res)
    }

    pub async fn get_graph_operator(&mut self, graph_id: &Uuid) -> anyhow::Result<Option<String>> {
        #[derive(sqlx::FromRow)]
        struct OperatorRow {
            operator: String,
        }
        if let Some(operator_raw) = sqlx::query_as!(
            OperatorRow,
            "SELECT   operator  FROM graph WHERE  graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?
        {
            Ok(Some(operator_raw.operator))
        } else {
            Ok(None)
        }
    }

    pub async fn filter_graphs(
        &mut self,
        mut params: FilterGraphParams,
    ) -> anyhow::Result<(Vec<GrapFullData>, i64)> {
        let mut graph_query_str = "SELECT graph.graph_id, graph.instance_id, instance.bridge_path AS bridge_path, graph.status AS status, \
            instance.network AS network, instance.from_addr AS from_addr,  instance.to_addr AS to_addr,  \
            graph.amount, graph.pegin_txid, graph.kickoff_txid, graph.challenge_txid,  \
            graph.take1_txid, graph.assert_init_txid, graph.assert_commit_txids, graph.assert_final_txid,  \
            graph.take2_txid, graph.disprove_txid, graph.operator, graph.bridge_out_start_at, graph.bridge_out_from_addr, graph.bridge_out_to_addr,\
            graph.init_withdraw_txid, graph.created_at, graph.updated_at FROM graph  INNER JOIN  instance ON  graph.instance_id = instance.instance_id".to_string();

        let mut graph_count_str = "SELECT count(graph.graph_id) as total_graphs FROM graph \
         INNER JOIN instance ON  graph.instance_id = instance.instance_id"
            .to_string();

        if let Some(from_addr) = params.from_addr {
            let node_op = sqlx::query_as!(
                Node,
                "SELECT peer_id, actor, goat_addr, btc_pub_key,  socket_addr, created_at, updated_at  \
                    FROM node WHERE goat_addr =?",
                from_addr
            )
                .fetch_optional(self.conn())
                .await?;
            if node_op.is_none() {
                warn!("no node find refer to goat address:{from_addr}");
                return Ok((vec![], 0));
            }
            let btc_pub_key = node_op.unwrap().btc_pub_key;
            if let Some(operator) = params.operator.clone() {
                if operator != btc_pub_key {
                    warn!(
                        "find node  refer to goat address:{from_addr} has different operator,  \
                            input:{operator}, find:{btc_pub_key}"
                    );
                    return Ok((vec![], 0));
                }
            } else {
                params.operator = Some(btc_pub_key);
            }
        }

        let mut conditions: Vec<String> = vec![];

        if let Some(status) = params.status.clone() {
            conditions.push(format!("graph.status = \'{status}\'"));
        }
        if let Some(operator) = params.operator {
            conditions.push(format!("graph.operator = \'{operator}\'"));
        }
        if let Some(pegin_txid) = params.pegin_txid {
            conditions.push(format!("graph.pegin_txid = \'{pegin_txid}\'"));
        }

        if let Some(graph_id) = params.graph_id {
            conditions.push(format!(" hex(graph.graph_id) = \'{graph_id}\' COLLATE NOCASE"));
        }

        if params.is_bridge_out && params.status.is_none() {
            conditions.push(
                "( graph.status NOT IN (\'OperatorPresigned\',\'CommitteePresigned\', \'OperatorDataPushed\') OR \
                 (graph.status == \'OperatorDataPushed\'  AND graph.init_withdraw_txid NOT NULL ) )".to_string(),
            );
        }

        if !conditions.is_empty() {
            let condition_str = conditions.join(" AND ");
            graph_query_str = format!("{graph_query_str} WHERE {condition_str}");
            graph_count_str = format!("{graph_count_str} WHERE {condition_str}");
        }

        if let Some(limit) = params.limit {
            graph_query_str = format!("{graph_query_str} LIMIT {limit}");
        }

        if let Some(offset) = params.offset {
            graph_query_str = format!("{graph_query_str} OFFSET {offset}");
        }
        tracing::info!("{graph_query_str}");
        let graphs = sqlx::query_as::<_, GrapFullData>(graph_query_str.as_str())
            .fetch_all(self.conn())
            .await?;
        let total_graphs = sqlx::query(graph_count_str.as_str())
            .fetch_one(self.conn())
            .await?
            .get::<i64, &str>("total_graphs");

        Ok((graphs, total_graphs))
    }

    pub async fn get_graph_by_instance_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \" , instance_id as \"instance_id:Uuid \", graph_ipfs_base_url, \
            pre_kickoff_txid,pegin_txid, amount, status,kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
             assert_final_txid, take2_txid, disprove_txid, operator, raw_data, bridge_out_start_at,  bridge_out_from_addr, bridge_out_to_addr, \
            init_withdraw_txid, zkm_version, created_at, updated_at FROM graph WHERE instance_id = ?",
            instance_id
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    pub async fn update_node_timestamp(
        &mut self,
        peer_id: &str,
        timestamp: i64,
    ) -> anyhow::Result<()> {
        let node_op = sqlx::query_as!(
            Node,
            "SELECT peer_id, actor, goat_addr, btc_pub_key, socket_addr, created_at, updated_at  \
            FROM node WHERE peer_id = ?",
            peer_id
        )
        .fetch_optional(self.conn())
        .await?;
        if node_op.is_none() {
            warn!("Node {peer_id} not found in DB");
            return Ok(());
        }
        let _ =
            sqlx::query!("UPDATE  node SET updated_at = ? WHERE peer_id = ? ", timestamp, peer_id)
                .execute(self.conn())
                .await;

        Ok(())
    }

    /// Insert or update node
    pub async fn update_node(&mut self, node: Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  node (peer_id, actor, goat_addr, btc_pub_key, socket_addr, created_at, updated_at) VALUES ( ?, ?, ?, ?, ?, ?, ?) ",
            node.peer_id,
            node.actor,
            node.goat_addr,
            node.btc_pub_key,
            node.socket_addr,
            node.created_at,
            node.updated_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_node_by_btc_pub_key(
        &mut self,
        btc_pub_key: &str,
    ) -> anyhow::Result<Option<Node>> {
        Ok(sqlx::query_as!(
            Node,
            "SELECT peer_id, actor, goat_addr, btc_pub_key, socket_addr, created_at, updated_at FROM node WHERE btc_pub_key = ?",
            btc_pub_key
        ).fetch_optional(self.conn()).await?)
    }

    /// Query node list
    pub async fn node_list(
        &mut self,
        actor: Option<String>,
        goat_addr: Option<String>,
        offset: Option<u32>,
        limit: Option<u32>,
        time_threshold: i64,
        status_expect: Option<String>,
    ) -> anyhow::Result<(Vec<Node>, i64)> {
        let mut nodes_query_str =
            "SELECT peer_id, actor, goat_addr, btc_pub_key, created_at, updated_at FROM node"
                .to_string();
        let mut nodes_count_str = "SELECT count(*) as total_nodes FROM node".to_string();
        let mut conditions: Vec<String> = vec![];
        if let Some(actor) = actor {
            conditions.push(format!("actor = \'{actor}\'"));
        }
        if let Some(goat_addr) = goat_addr {
            conditions.push(format!("goat_addr = \'{goat_addr}\'"));
        }
        if let Some(status_expect) = status_expect {
            match status_expect.as_str() {
                NODE_STATUS_ONLINE => conditions.push(format!("updated_at > {time_threshold}")),
                NODE_STATUS_OFFLINE => conditions.push(format!("updated_at <= {time_threshold}")),
                _ => {}
            }
        }
        if !conditions.is_empty() {
            let condition_str = conditions.join(" AND ");
            nodes_query_str = format!("{nodes_query_str} WHERE {condition_str}");
            nodes_count_str = format!("{nodes_count_str} WHERE {condition_str}");
        }

        if let Some(limit) = limit {
            nodes_query_str = format!("{nodes_query_str} LIMIT {limit}");
        }
        if let Some(offset) = offset {
            nodes_query_str = format!("{nodes_query_str} OFFSET {offset}");
        }
        let nodes =
            sqlx::query_as::<_, Node>(nodes_query_str.as_str()).fetch_all(self.conn()).await?;
        let total_nodes = sqlx::query(nodes_count_str.as_str())
            .fetch_one(self.conn())
            .await?
            .get::<i64, &str>("total_nodes");
        Ok((nodes, total_nodes))
    }

    pub async fn node_overview(&mut self, time_threshold: i64) -> anyhow::Result<NodesOverview> {
        let records = sqlx::query!(
            "SELECT count(*) as total, actor , SUM(CASE WHEN updated_at>= ? THEN 1 ELSE 0 END) AS online,  \
        SUM(CASE WHEN updated_at< ? THEN 1 ELSE 0 END)  AS offline FROM node GROUP BY actor",
            time_threshold,
            time_threshold
        ).fetch_all(self.conn()).await?;

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
                    (res.offline_relayer, res.online_relayer) = (record.offline, record.online);
                }
                _ => {}
            };
        }
        Ok(res)
    }

    pub async fn node_by_id(&mut self, peer_id: &str) -> anyhow::Result<Option<Node>> {
        let res = sqlx::query_as!(
            Node,
            "SELECT peer_id, actor, goat_addr,btc_pub_key, socket_addr, created_at,  updated_at FROM  node WHERE peer_id = ?",
            peer_id
        ).fetch_optional(self.conn()).await?;
        Ok(res)
    }

    pub async fn get_sum_bridge_in(&mut self, bridge_path: u8) -> anyhow::Result<(i64, i64)> {
        let record = sqlx::query!(
            "SELECT SUM(amount) as total, COUNT(*) as tx_count FROM instance WHERE bridge_path = ? ",
            bridge_path
        )
            .fetch_one(self.conn())
            .await?;
        Ok((record.total.unwrap_or(0), record.tx_count))
    }

    pub async fn get_sum_bridge_out(&mut self) -> anyhow::Result<(i64, i64)> {
        let record = sqlx::query!(
            "SELECT SUM(amount) as total, COUNT(*) as tx_count FROM graph WHERE status NOT IN \
            ('OperatorPresigned','CommitteePresigned','OperatorDataPushed')"
        )
        .fetch_one(self.conn())
        .await?;
        Ok((record.total.unwrap_or(0), record.tx_count))
    }

    pub async fn get_nodes_info(&mut self, time_threshold: i64) -> anyhow::Result<(i64, i64)> {
        let total = sqlx::query!("SELECT COUNT(peer_id) as total FROM node")
            .fetch_one(self.conn())
            .await?
            .total;
        let time_pri =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - time_threshold;
        tracing::info!("{time_pri}");
        let alive = sqlx::query!(
            "SELECT COUNT(peer_id)  as alive FROM node WHERE updated_at  >= ? ",
            time_pri
        )
        .fetch_one(self.conn())
        .await?
        .alive;
        Ok((total, alive))
    }

    pub async fn update_messages_state(
        &mut self,
        ids: &[i64],
        state: String,
        current_time: i64,
    ) -> anyhow::Result<bool> {
        let query_str = format!(
            "Update  message Set state = \'{state}\', updated_at = {current_time} WHERE id IN ({})",
            create_place_holders(ids)
        );
        let mut query = sqlx::query(&query_str);
        for id in ids {
            query = query.bind(id);
        }

        let res = query.execute(self.conn()).await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn set_messages_expired(&mut self, expired: i64) -> anyhow::Result<()> {
        sqlx::query!(
            "Update message Set state = 'Expired' WHERE state IN ( 'Pending', 'Processing') AND  updated_at < ?", expired)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn filter_messages(
        &mut self,
        msg_type: String,
        state: String,
        expired: i64,
    ) -> anyhow::Result<Vec<Message>> {
        let res = sqlx::query_as!(
           Message,
           "SELECT id, from_peer, actor, msg_type, content, state FROM message WHERE msg_type = ?  \
           AND state = ? AND updated_at >= ?",msg_type,state, expired
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    pub async fn create_message(
        &mut self,
        msg: Message,
        current_time: i64,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO  message (from_peer, actor, msg_type, content, state, updated_at, created_at) VALUES (?,?, ?,?, ?,?,?)",
            msg.from_peer,
            msg.actor,
            msg.msg_type,
            msg.content,
            msg.state,
            current_time,
            current_time

        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn store_pubkeys(
        &mut self,
        instance_id: Uuid,
        pubkeys: &[String],
    ) -> anyhow::Result<()> {
        let pubkey_collect = sqlx::query_as!(
            PubKeyCollect ,
            "SELECT instance_id as \"instance_id:Uuid\", pubkeys, created_at, updated_at  FROM pubkey_collect WHERE instance_id = ?",
            instance_id).fetch_optional(self.conn()).await?;

        let pubkeys = pubkeys.to_owned();
        let mut created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let pubkeys = if let Some(pubkey_collect) = pubkey_collect {
            let mut stored_pubkeys: Vec<String> = serde_json::from_str(&pubkey_collect.pubkeys)?;
            let pre_len = stored_pubkeys.len();
            for pubkey in pubkeys {
                if !stored_pubkeys.contains(&pubkey) {
                    stored_pubkeys.push(pubkey);
                }
            }
            if stored_pubkeys.len() == pre_len {
                warn!("input pubkeys have been stored");
                return Ok(());
            }
            created_at = pubkey_collect.created_at;
            stored_pubkeys
        } else {
            pubkeys
        };
        let pubkeys_str = serde_json::to_string(&pubkeys)?;
        let _ = sqlx::query!(
            "INSERT OR REPLACE INTO  pubkey_collect (instance_id, pubkeys, created_at, updated_at) VALUES ( ?,?, ?,?)",
            instance_id,
            pubkeys_str,
            created_at,
            updated_at,
        ).execute(self.conn()).await;
        Ok(())
    }

    pub async fn get_pubkeys(
        &mut self,
        instance_id: Uuid,
    ) -> anyhow::Result<Option<PubKeyCollectMetaData>> {
        let pubkey_collect = sqlx::query_as!(
            PubKeyCollect ,
            "SELECT instance_id as \"instance_id:Uuid\", pubkeys, created_at, updated_at  FROM pubkey_collect WHERE instance_id = ?",
            instance_id).fetch_optional(self.conn()).await?;
        match pubkey_collect {
            Some(pubkey_collect) => {
                let pubkeys: Vec<String> = serde_json::from_str(&pubkey_collect.pubkeys)?;
                Ok(Some(PubKeyCollectMetaData {
                    instance_id,
                    pubkeys,
                    updated_at: pubkey_collect.updated_at,
                    created_at: pubkey_collect.created_at,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn store_nonces(
        &mut self,
        instance_id: Uuid,
        graph_id: Uuid,
        nonces: &[[String; COMMITTEE_PRE_SIGN_NUM]],
        committee_pubkey: String,
        partial_sigs: &[[String; COMMITTEE_PRE_SIGN_NUM]],
    ) -> anyhow::Result<()> {
        let merge_dedup_fn = |mut source: Vec<[String; COMMITTEE_PRE_SIGN_NUM]>,
                              input: Vec<[String; COMMITTEE_PRE_SIGN_NUM]>|
         -> (bool, Vec<[String; COMMITTEE_PRE_SIGN_NUM]>) {
            if input.is_empty() {
                return (false, source);
            }
            // source and input order never change
            let keys: Vec<String> = source.iter().map(|v| v[0].clone()).collect();
            let pre_len = source.len();
            for item in input {
                if !keys.contains(&item[0]) {
                    source.push(item)
                }
            }
            (source.len() > pre_len, source)
        };
        let nonce_collect = sqlx::query_as!(
            NonceCollect ,
            "SELECT instance_id as \"instance_id:Uuid\", graph_id as \"graph_id:Uuid\",nonces, committee_pubkey, \
            partial_sigs, created_at, updated_at  FROM nonce_collect WHERE instance_id = ? AND graph_id = ?",
            instance_id, graph_id).fetch_optional(self.conn()).await?;

        let nonces = nonces.to_owned();
        let partial_sigs = partial_sigs.to_owned();
        let mut created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let (nonces, partial_sigs) = if let Some(nonce_collect) = nonce_collect {
            created_at = nonce_collect.created_at;
            let stored_nonces: Vec<[String; COMMITTEE_PRE_SIGN_NUM]> =
                serde_json::from_str(&nonce_collect.nonces)?;
            let stored_signs: Vec<[String; COMMITTEE_PRE_SIGN_NUM]> =
                serde_json::from_str(&nonce_collect.partial_sigs)?;
            let (update_nonce, nonces) = merge_dedup_fn(stored_nonces, nonces);
            let (update_signs, partial_sigs) = merge_dedup_fn(stored_signs, partial_sigs);
            if !(update_nonce || update_signs) {
                warn!("nonces or partial_sigs have been stored");
                return Ok(());
            }
            (nonces, partial_sigs)
        } else {
            (nonces, partial_sigs)
        };

        let nonce_str = serde_json::to_string(&nonces)?;
        let signs_str = serde_json::to_string(&partial_sigs)?;
        let _ = sqlx::query!(
            "INSERT OR REPLACE INTO  nonce_collect (instance_id, graph_id, nonces, committee_pubkey,\
             partial_sigs, created_at, updated_at) VALUES ( ?, ?, ?, ?, ?, ?, ?)",
            instance_id,
            graph_id,
            nonce_str,
            committee_pubkey,
            signs_str,
            created_at,
            updated_at,
        ).execute(self.conn()).await;
        Ok(())
    }

    pub async fn get_nonces(
        &mut self,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> anyhow::Result<Option<NonceCollectMetaData>> {
        let nonce_collect = sqlx::query_as!(
            NonceCollect ,
            "SELECT instance_id as \"instance_id:Uuid\", graph_id as \"graph_id:Uuid\",nonces, committee_pubkey, \
            partial_sigs, created_at, updated_at  FROM nonce_collect WHERE instance_id = ? AND graph_id = ?",
            instance_id, graph_id).fetch_optional(self.conn()).await?;
        match nonce_collect {
            Some(nonce_collect) => {
                let stored_nonces: Vec<[String; COMMITTEE_PRE_SIGN_NUM]> =
                    serde_json::from_str(&nonce_collect.nonces)?;
                let stored_sigs: Vec<[String; COMMITTEE_PRE_SIGN_NUM]> =
                    serde_json::from_str(&nonce_collect.partial_sigs)?;
                Ok(Some(NonceCollectMetaData {
                    instance_id,
                    graph_id,
                    nonces: stored_nonces,
                    committee_pubkey: nonce_collect.committee_pubkey,
                    updated_at: nonce_collect.updated_at,
                    created_at: nonce_collect.created_at,
                    partial_sigs: stored_sigs,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn get_graph_tick_action_datas(
        &mut self,
        graph_status: &str,
        msg_type: &str,
    ) -> anyhow::Result<Vec<GraphTickActionMetaData>> {
        Ok(
            sqlx::query_as!(
                GraphTickActionMetaData,
                "SELECT graph.graph_id as \"graph_id:Uuid\", graph.instance_id as \"instance_id:Uuid\", graph.status, graph.kickoff_txid,  graph.take1_txid, \
                 graph.take2_txid, graph.assert_init_txid, graph.assert_commit_txids, graph.assert_final_txid, \
                 IFNULL(message_broadcast.msg_times, 0) as msg_times, IFNULL(message_broadcast.msg_type, '') as msg_type  \
                  FROM graph LEFT JOIN message_broadcast ON graph.graph_id =  message_broadcast.graph_id AND  \
                  graph.instance_id =  message_broadcast.instance_id AND message_broadcast.msg_type =  ?  \
                  WHERE  graph.status = ?",msg_type,graph_status).fetch_all(self.conn()).await?
        )
    }

    pub async fn get_message_broadcast_times(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        msg_type: &str,
    ) -> anyhow::Result<i64> {
        let res = sqlx::query(
            format!(
                "SELECT msg_times FROM message_broadcast WHERE hex(instance_id) = \'{}\' COLLATE NOCASE AND  hex(graph_id) = \'{}\' COLLATE NOCASE \
                AND msg_type = \'{}\' ", hex::encode(instance_id), hex::encode(graph_id), msg_type).as_str(),
        ).fetch_optional(self.conn()).await?;
        match res {
            Some(row) => Ok(row.get::<i64, &str>("msg_times")),
            None => Ok(0),
        }
    }

    pub async fn update_message_broadcast_times(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        msg_type: &str,
        msg_times: i64,
    ) -> anyhow::Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let message_broadcast_info = sqlx::query_as!(
            MessageBroadcast,
            "SELECT instance_id as \"instance_id:Uuid\", graph_id as \"graph_id:Uuid\", msg_type, msg_times, \
            created_at, updated_at FROM message_broadcast WHERE instance_id =? AND graph_id = ? ",
            instance_id,
           graph_id
        ).fetch_optional(self.conn())
            .await?;

        let created_at = if let Some(message_broadcast_info) = message_broadcast_info {
            message_broadcast_info.created_at
        } else {
            current_time
        };
        sqlx::query!(
            "INSERT OR REPLACE INTO  message_broadcast (instance_id, graph_id, msg_type, msg_times, created_at, updated_at)  VALUES (?,?,?,?,?,?) ",
            instance_id,
            graph_id,
            msg_type,
            msg_times,
            created_at,
            current_time

        )
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn create_or_update_proof_with_pis(
        &mut self,
        proof_with_pis: ProofWithPis,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            "INSERT OR REPLACE INTO proof_with_pis (instance_id, graph_id,  proof, pis, proof_cast, goat_block_number, created_at) \
       VALUES  (?, ?, ?, ?, ?, ?, ?)",
            proof_with_pis.instance_id,
            proof_with_pis.graph_id,
            proof_with_pis.proof,
            proof_with_pis.pis,
            proof_with_pis.proof_cast,
            proof_with_pis.goat_block_number,
            proof_with_pis.created_at
        )
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn get_proof_with_pis(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<ProofWithPis>> {
        Ok(sqlx::query_as!(
            ProofWithPis,
            "SELECT instance_id as \"instance_id:Uuid\" , graph_id as \"graph_id:Uuid\", proof, pis,  goat_block_number, proof_cast, created_at From proof_with_pis where instance_id = ? AND graph_id = ?",
            instance_id,
            graph_id
        )
            .fetch_optional(self.conn())
            .await?)
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        sqlx::query!(
            r#"
            INSERT INTO block_proof 
                (block_number, state, created_at) 
            VALUES 
                (?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                state = excluded.state,
                created_at = excluded.created_at
            "#,
            block_number,
            state,
            timestamp
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

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
        let end_timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        let start_timestamp = self.get_block_execution_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size_mb = proof.len() as f64 / (1024.0 * 1024.0);
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
                proof_size_mb = ?,
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
            proof_size_mb,
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
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
    pub async fn create_aggregation_task(
        &mut self,
        block_number: i64,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        sqlx::query!(
            r#"
            INSERT INTO aggregation_proof 
                (block_number, state, created_at) 
            VALUES
                (?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                state = excluded.state,
                created_at = excluded.created_at
            "#,
            block_number,
            state,
            timestamp
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
        let end_timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        let start_timestamp = self.get_aggregation_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size_mb = proof.len() as f64 / (1024.0 * 1024.0);
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
                proof_size_mb = ?,
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
            proof_size_mb,
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
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

    pub async fn create_groth16_task(
        &mut self,
        block_number: i64,
        state: String,
    ) -> anyhow::Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        sqlx::query!(
            r#"
            INSERT INTO groth16_proof 
                (block_number, state, created_at) 
            VALUES
                (?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                state = excluded.state,
                created_at = excluded.created_at
            "#,
            block_number,
            state,
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
        proving_time: i64,
        proving_cycles: i64,
        proof: &[u8],
        public_values: &[u8],
        verifier_id: String,
        zkm_version: &str,
        state: String,
    ) -> anyhow::Result<()> {
        let end_timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        let start_timestamp = self.get_groth16_start_time(block_number).await?;

        let total_time_to_proof = end_timestamp - start_timestamp;

        let proof_size_b = proof.len() as f64;
        let proof = hex::encode(proof);

        let public_values = hex::encode(public_values);

        sqlx::query!(
            r#"
            UPDATE groth16_proof 
            SET
                total_time_to_proof = ?,
                proving_time = ?, 
                proving_cycles = ?, 
                proof = ?,
                proof_size_b = ?,
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
            proof_size_b,
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
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

    pub async fn create_verifier_key(
        &mut self,
        verifier_id: &str,
        verifier_key: &[u8],
    ) -> anyhow::Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
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
            "SELECT addr, the_graph_url, from_height, gap, status, extra,updated_at FROM watch_contract WHERE addr = ? ",
            addr
        )
            .fetch_optional(self.conn())
            .await?)
    }

    pub async fn create_or_update_watch_contract(
        &mut self,
        watch_contract: &WatchContract,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "INSERT OR REPLACE INTO watch_contract (addr,the_graph_url, gap, from_height, status, extra, updated_at)  \
       VALUES  (?, ?, ?, ?, ?, ?, ?)",
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

    pub async fn create_or_update_goat_tx_record(
        &mut self,
        goat_tx_record: &GoatTxRecord,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "INSERT OR REPLACE INTO goat_tx_record (instance_id, graph_id, tx_type, tx_hash, height, is_local, \
       prove_status, extra, created_at)  VALUES  (?, ?, ?, ?, ?, ?, ?, ?,?) ",
            goat_tx_record.instance_id,
            goat_tx_record.graph_id,
            goat_tx_record.tx_type,
            goat_tx_record.tx_hash,
            goat_tx_record.height,
            goat_tx_record.is_local,
            goat_tx_record.prove_status,
            goat_tx_record.extra,
            goat_tx_record.created_at
        ).execute(self.conn()).await;
        Ok(())
    }

    pub async fn get_graph_goat_tx_record(
        &mut self,
        graph_id: &Uuid,
        tx_type: &str,
    ) -> anyhow::Result<Option<GoatTxRecord>> {
        Ok(
            sqlx::query_as!(
                GoatTxRecord,
                "SELECT instance_id as \"instance_id:Uuid\" , graph_id as \"graph_id:Uuid\", tx_type, tx_hash, \
                 height, is_local, prove_status, extra, created_at From goat_tx_record where  graph_id = ? AND tx_type = ?",
                graph_id,
                tx_type
            ).fetch_optional(self.conn())
                .await?
        )
    }

    pub async fn get_goat_tx_record_need_proving(
        &mut self,
        tx_type: &str,
    ) -> anyhow::Result<Vec<GoatTxRecord>> {
        Ok(
            sqlx::query_as!(
                GoatTxRecord,
                "SELECT instance_id as \"instance_id:Uuid\" , graph_id as \"graph_id:Uuid\", tx_type, \
                 tx_hash, height, is_local, prove_status, extra, created_at From goat_tx_record where tx_type = ?  \
                 AND prove_status = 'Proving' ORDER BY height asc",
                tx_type
            ).fetch_all(self.conn())
                .await?
        )
    }

    pub async fn get_tx_info_for_gen_proof(
        &mut self,
        block_number: i64,
    ) -> anyhow::Result<Vec<(Uuid, String, String)>> {
        #[derive(sqlx::FromRow)]
        struct TxInfoRow {
            graph_id: Uuid,
            zkm_version: String,
            tx_hash: String,
        }
        let tx_info_rows = sqlx::query_as!(
            TxInfoRow,
            "SELECT g.graph_id AS \"graph_id:Uuid\", g.zkm_version AS zkm_version, gtr.tx_hash AS tx_hash 
FROM graph g INNER JOIN goat_tx_record gtr ON g.graph_id = gtr.graph_id WHERE gtr.height = ? AND gtr.tx_type = 'ProceedWithdraw'",
            block_number
        ).fetch_all(self.conn()).await?;
        Ok(tx_info_rows.into_iter().map(|v| (v.graph_id, v.tx_hash, v.zkm_version)).collect())
    }

    pub async fn skip_groth16_proof(&mut self, block_number: i64) -> anyhow::Result<bool> {
        Ok(self.get_tx_info_for_gen_proof(block_number).await?.is_empty())
    }

    pub async fn update_goat_tx_record_prove_status(
        &mut self,
        graph_id: &Uuid,
        instance_id: &Uuid,
        tx_type: &str,
        status: &str,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            "UPDATE goat_tx_record SET prove_status = ?  where instance_id = ? AND graph_id = ? AND tx_type = ? ",
            status,
            instance_id,
            graph_id,
            tx_type
            ).execute(self.conn()).await?;
        Ok(())
    }

    pub async fn get_range_proofs(
        &mut self,
        proof_type: ProofType,
        block_number_min: i64,
        block_number_max: i64,
    ) -> anyhow::Result<Vec<(i64, String, i64, i64, i64)>> {
        #[derive(sqlx::FromRow)]
        struct ProofInfoRow {
            block_number: i64,
            state: String,
            proving_time: i64,
            created_at: i64,
            updated_at: i64,
        }
        let query = match proof_type {
            ProofType::BlockProof => {
                "SELECT block_number, state, proving_time, created_at, updated_at FROM block_proof WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC"
            }
            ProofType::AggregationProof => {
                "SELECT block_number, state, proving_time, created_at, updated_at FROM aggregation_proof WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC"
            }
            ProofType::Groth16Proof => {
                "SELECT block_number, state, proving_time, created_at, updated_at FROM groth16_proof WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC"
            }
        };

        let rows = sqlx::query_as::<_, ProofInfoRow>(query)
            .bind(block_number_min)
            .bind(block_number_max)
            .fetch_all(self.conn())
            .await?;

        Ok(rows
            .into_iter()
            .map(|v| (v.block_number, v.state, v.proving_time, v.created_at, v.updated_at))
            .collect())
    }
}

fn create_place_holders<T>(inputs: &[T]) -> String {
    inputs.iter().enumerate().map(|(i, _)| format!("${}", i + 1)).collect::<Vec<_>>().join(",")
}

fn truncate_string(s: &str, max_len: usize) -> &str {
    if s.len() > max_len { &s[..max_len] } else { s }
}
