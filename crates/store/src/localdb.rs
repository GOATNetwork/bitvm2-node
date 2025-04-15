use crate::{FilterGraphsInfo, Graph, Instance, Message, Node};
use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::types::Uuid;
use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
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
            "INSERT OR REPLACE INTO  instance (instance_id, bridge_path, from_addr, to_addr, amount, \
            status, goat_txid, btc_txid ,pegin_tx, kickoff_tx)  VALUES (?,?,?,?,?,?,?,?,?,?)",
            instance.instance_id,
            instance.bridge_path,
            instance.from_addr,
            instance.to_addr,
            instance.amount,
            instance.status,
            instance.goat_txid,
            instance.btc_txid,
            instance.pegin_tx,
            instance.kickoff_tx,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<Instance> {
        let row = sqlx::query_as!(
            Instance,
            "SELECT instance_id as \"instance_id:Uuid\", bridge_path, from_addr, to_addr, amount, status, goat_txid,  \
            btc_txid ,pegin_tx, kickoff_tx, created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" \
            FROM  instance where instance_id = ?",
            instance_id
        ).fetch_one(self.conn())
            .await?;
        Ok(row)
    }
    pub async fn instance_list(
        &mut self,
        user: &Option<String>,
        offset: u32,
        limit: u32,
    ) -> anyhow::Result<Vec<Instance>> {
        let res = match user {
            Some(user) => {
                sqlx::query_as!(
                    Instance,
                    "SELECT instance_id as \"instance_id:Uuid\", bridge_path, from_addr, to_addr, amount, status, goat_txid, btc_txid ,pegin_tx, kickoff_tx, \
                    created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" from instance where from_addr = ? \
                    ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    user,
                    limit,
                    offset
                ).fetch_all(self.conn()).await?
            }
            None => {
                sqlx::query_as!(
                    Instance,
                    "SELECT instance_id as \"instance_id:Uuid\" , bridge_path, from_addr, to_addr, amount, status, goat_txid, btc_txid ,pegin_tx, kickoff_tx, \
                     created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" from instance  \
                     ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    limit,
                    offset
                ).fetch_all(self.conn()).await?
            }
        };
        Ok(res)
    }

    /// Update Instance
    pub async fn update_instance(&mut self, instance: Instance) -> anyhow::Result<u64> {
        let row = sqlx::query!(
            "UPDATE instance SET bridge_path = ?, from_addr= ?, to_addr= ?,  \
        amount= ?, status= ?, goat_txid= ?, btc_txid= ?, pegin_tx= ?, kickoff_tx = ? WHERE instance_id = ?",
            instance.bridge_path,
            instance.from_addr,
            instance.to_addr,
            instance.amount,
            instance.status,
            instance.goat_txid,
            instance.btc_txid,
            instance.pegin_tx,
            instance.kickoff_tx,
            instance.instance_id
        )
            .execute(self.conn())
            .await?;
        Ok(row.rows_affected())
    }

    /// Insert or update graph
    pub async fn update_graph(&mut self, graph: Graph) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  graph (graph_id, instance_id, graph_ipfs_base_url, pegin_txid, \
             amount, status, challenge_txid, disprove_txid, created_at) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?) ",
            graph.graph_id,
            graph.instance_id,
            graph.graph_ipfs_base_url,
            graph.pegin_txid,
            graph.amount,
            graph.status,
            graph.challenge_txid,
            graph.disprove_txid,
            graph.created_at,
        ).execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_graph(&mut self, graph_id: &Uuid) -> anyhow::Result<Graph> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \", instance_id  as \"instance_id:Uuid \", graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  graph_id = ?",
            graph_id
        ).fetch_one(self.conn()).await?;
        Ok(res)
    }

    pub async fn filter_graphs(
        &mut self,
        filter_graphs_info: &FilterGraphsInfo,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \" , instance_id as \"instance_id:Uuid \", graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  status = ? and pegin_txid = ?  LIMIT ? OFFSET ?",
            filter_graphs_info.status,
           filter_graphs_info.pegin_txid,
           filter_graphs_info.limit,
            filter_graphs_info.offset,
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    pub async fn get_graphs(&mut self, graph_ids: &Vec<String>) -> anyhow::Result<Vec<Graph>> {
        let placeholders = graph_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let query_str = format!(
            "SELECT graph_id, instance_id, graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at FROM graph WHERE  graph_id IN ({})",
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
        instance_id: &str,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id as \"graph_id:Uuid \" , instance_id as \"instance_id:Uuid \", graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  instance_id = ?",
            instance_id
        ).fetch_all(self.conn()).await?;
        Ok(res)
    }

    /// Insert or update node
    pub async fn update_node(&mut self, node: Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  node (peer_id, actor, updated_at) VALUES ( ?, ?, ?) ",
            node.peer_id,
            node.actor,
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
        offset: u32,
        limit: u32,
    ) -> anyhow::Result<Vec<Node>> {
        let res = match actor {
            Some(actor) => {
                sqlx::query_as!(
                    Node,
                    "SELECT peer_id, actor, updated_at as \"updated_at: i64\" FROM node \
                     WHERE actor = ? LIMIT ? OFFSET ? ",
                    actor,
                    limit,
                    offset
                )
                .fetch_all(self.conn())
                .await?
            }
            None => {
                sqlx::query_as!(
                    Node,
                    "SELECT peer_id, actor, updated_at as \"updated_at: i64\" FROM node \
                     LIMIT ? OFFSET ? ",
                    limit,
                    offset
                )
                .fetch_all(self.conn())
                .await?
            }
        };
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
        let res =  sqlx::query_as!(
           Message,
           "SELECT id, from_peer, actor, msg_type, content, state FROM message WHERE state = ? AND  strftime(\"%s\", updated_at) < strftime(?)",
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
