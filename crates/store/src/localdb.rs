use crate::schema::NODE_STATUS_OFFLINE;
use crate::schema::NODE_STATUS_ONLINE;
use crate::{GrapRpcQueryData, Graph, Instance, Message, Node, NodesOverview};
use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::types::Uuid;
use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::time::{SystemTime, UNIX_EPOCH};

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
                Err(error) => panic!("error: {}", error),
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
                panic!("error: {}", error);
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

    pub async fn get_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<Instance> {
        let row = sqlx::query_as!(
            Instance,
            "SELECT instance_id as \"instance_id:Uuid\", network,   bridge_path, from_addr, to_addr, amount, status, goat_txid,  \
            btc_txid ,pegin_txid, input_uxtos, fee ,created_at, updated_at \
            FROM  instance where instance_id = ?",
            instance_id
        ).fetch_one(self.conn())
            .await?;
        Ok(row)
    }
    pub async fn instance_list(
        &mut self,
        from_addr: Option<String>,
        bridge_path: Option<u8>,
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
            conditions.push(format!("from_addr = \'{}\'", from_addr));
        }
        if let Some(bridge_path) = bridge_path {
            conditions.push(format!("operbridge_pathator = {}", bridge_path));
        }
        if !conditions.is_empty() {
            let condition_str = conditions.join(" and ");
            instance_query_str = format!("{} WHERE {}", instance_query_str, condition_str);
            instance_count_str = format!("{} WHERE {}", instance_count_str, condition_str);
        }
        if let Some(limit) = limit {
            instance_query_str = format!("{} LIMIT {}", instance_query_str, limit);
        }
        if let Some(offset) = offset {
            instance_query_str = format!("{} OFFSET {}", instance_query_str, offset);
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
             amount, status, kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
            assert_final_txid, take2_txid_txid, disprove_txid, raw_data, created_at, updated_at)  \
            VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?) ",
            graph.graph_id,
            graph.instance_id,
            graph.graph_ipfs_base_url,
            graph.pegin_txid,
            graph.amount,
            graph.status,
            graph.kickoff_txid,
            graph.challenge_txid,
            graph.take1_txid,
            graph.assert_init_txid,
            graph.assert_commit_txids,
            graph.assert_final_txid,
            graph.take2_txid_txid,
            graph.disprove_txid,
            graph.raw_data,
            graph.created_at,
            graph.updated_at,
        ).execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_graph(&mut self, graph_id: &Uuid) -> anyhow::Result<Graph> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \", instance_id  as \"instance_id:Uuid \", graph_ipfs_base_url, \
             pegin_txid, amount, status, kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
              assert_final_txid, take2_txid_txid, disprove_txid, operator, raw_data, created_at, updated_at  FROM graph WHERE  graph_id = ?",
            graph_id
        ).fetch_one(self.conn()).await?;
        Ok(res)
    }

    pub async fn filter_graphs(
        &mut self,
        status: Option<String>,
        operator: Option<String>,
        pegin_txid: Option<String>,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> anyhow::Result<(Vec<GrapRpcQueryData>, i64)> {
        let mut graph_query_str =
            "SELECT graph.graph_id, graph.instance_id, instance.bridge_path AS  bridge_path, \
            instance.network AS network, instance.from_addr AS from_addr,  instance.to_addr AS to_addr,  \
            graph.amount, graph.pegin_txid, graph.status, graph.kickoff_txid, graph.challenge_txid,  \
            graph.take1_txid, graph.assert_init_txid, graph.assert_commit_txids, graph.assert_final_txid,  \
            graph.take2_txid_txid, graph.disprove_txid, graph.operator,  graph.updated_at, graph.created_at FROM graph  \
            INNER JOIN  instance ON  graph.instance_id = instance.instance_id".to_string();
        let mut graph_count_str = "SELECT count(graph.graph_id) as total_graphs FROM graph \
         INNER JOIN  instance ON  graph.instance_id = instance.instance_id".to_string();

        let mut conditions: Vec<String> = vec![];

        if let Some(status) = status {
            conditions.push(format!("status = \'{}\'", status));
        }
        if let Some(operator) = operator {
            conditions.push(format!("operator = \'{}\'", operator));
        }
        if let Some(pegin_txid) = pegin_txid {
            conditions.push(format!("pegin_txid = \'{}\'", pegin_txid));
        }

        if !conditions.is_empty() {
            let condition_str = conditions.join(" and ");
            graph_query_str = format!("{} WHERE {}", graph_query_str, condition_str);
            graph_count_str = format!("{} WHERE {}", graph_count_str, condition_str);
        }

        if let Some(limit) = limit {
            graph_query_str = format!("{} LIMIT {}", graph_query_str, limit);
        }

        if let Some(offset) = offset {
            graph_query_str = format!("{} OFFSET {}", graph_query_str, offset);
        }
        let graphs = sqlx::query_as::<_, GrapRpcQueryData>(graph_query_str.as_str())
            .fetch_all(self.conn())
            .await?;
        let total_graphs = sqlx::query(graph_count_str.as_str())
            .fetch_one(self.conn())
            .await?
            .get::<i64, &str>("total_graphs");

        Ok((graphs, total_graphs))
    }

    pub async fn get_graphs(&mut self, graph_ids: &Vec<String>) -> anyhow::Result<Vec<Graph>> {
        let placeholders = graph_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let query_str = format!(
            "SELECT graph_id, instance_id, graph_ipfs_base_url, pegin_txid, amount, status, kickoff_txid, \
            challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, assert_final_txid, take2_txid_txid, \
            disprove_txid, operator, raw_data, created_at , updated_at FROM graph WHERE  graph_id IN ({})",
            placeholders
        );
        let mut query = sqlx::query_as::<_, Graph>(&query_str);
        for id in graph_ids {
            query = query.bind(id);
        }
        let res = query.fetch_all(self.conn()).await?;
        Ok(res)
    }

    pub async fn get_graph_by_instance_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \" , instance_id as \"instance_id:Uuid \", graph_ipfs_base_url, \
            pegin_txid, amount, status,kickoff_txid, challenge_txid, take1_txid, assert_init_txid, assert_commit_txids, \
             assert_final_txid, take2_txid_txid, disprove_txid, operator, raw_data, created_at, updated_at FROM graph WHERE instance_id = ?",
            instance_id
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    /// Insert or update node
    pub async fn update_node(&mut self, node: Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  node (peer_id, actor, goat_addr, btc_pub_key, created_at, updated_at) VALUES ( ?, ?, ?, ?, ?, ?) ",
            node.peer_id,
            node.actor,
            node.goat_addr,
            node.btc_pub_key,
            node.created_at,
            node.updated_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
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
            conditions.push(format!("actor = \'{}\'", actor));
        }
        if let Some(goat_addr) = goat_addr {
            conditions.push(format!("goat_addr = \'{}\'", goat_addr));
        }
        if let Some(status_expect) = status_expect {
            match status_expect.as_str() {
                NODE_STATUS_ONLINE => conditions.push(format!("updated_at > {}", time_threshold)),
                NODE_STATUS_OFFLINE => conditions.push(format!("updated_at <= {}", time_threshold)),
                _ => {}
            }
        }
        if !conditions.is_empty() {
            let condition_str = conditions.join(" and ");
            nodes_query_str = format!("{} WHERE {}", nodes_query_str, condition_str);
            nodes_count_str = format!("{} WHERE {}", nodes_count_str, condition_str);
        }

        if let Some(limit) = limit {
            nodes_query_str = format!("{} LIMIT {}", nodes_query_str, limit);
        }
        if let Some(offset) = offset {
            nodes_query_str = format!("{} OFFSET {}", nodes_query_str, offset);
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
                _ => {}
            };
        }
        Ok(res)
    }

    pub async fn node_by_id(&mut self, peer_id: &str) -> anyhow::Result<Option<Node>> {
        let res = sqlx::query_as!(
            Node,
            "SELECT peer_id, actor, goat_addr,btc_pub_key, created_at,  updated_at FROM  node WHERE peer_id = ?",
            peer_id
        ).fetch_optional(self.conn()).await?;
        Ok(res)
    }

    pub async fn get_sum_bridge_in_or_out(
        &mut self,
        bridge_path: u8,
    ) -> anyhow::Result<(i64, i64)> {
        let record = sqlx::query!(
            "SELECT SUM(amount) as total, COUNT(*) as tx_count FROM instance WHERE bridge_path = ? ",
            bridge_path
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
    ) -> anyhow::Result<bool> {
        let query_str = format!(
            "Update  message Set state = {} WHERE id IN ({})",
            state,
            create_place_holders(&ids)
        );
        let mut query = sqlx::query(&query_str);
        for id in ids {
            query = query.bind(id);
        }

        let res = query.execute(self.conn()).await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn filter_messages(
        &mut self,
        state: String,
        expired: i64,
    ) -> anyhow::Result<Vec<Message>> {
        let res = sqlx::query_as!(
           Message,
           "SELECT id, from_peer, actor, msg_type, content, state FROM message WHERE state = ? AND updated_at < ?",
           state, expired
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    pub async fn create_message(&mut self, msg: Message) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO  message (from_peer, actor, msg_type, content, state) VALUES ( ?,?, ?,?,?)",
            msg.from_peer,
            msg.actor,
            msg.msg_type,
            msg.content,
            msg.state
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn create_place_holders<T>(inputs: &[T]) -> String {
    inputs.iter().enumerate().map(|(i, _)| format!("${}", i + 1)).collect::<Vec<_>>().join(",")
}
