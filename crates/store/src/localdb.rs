use crate::{FilterGraphsInfo, Graph, Instance, Node};
use sqlx::migrate::Migrator;
use sqlx::{Row, Sqlite, SqlitePool, migrate::MigrateDatabase};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct LocalDB {
    pub path: String,
    pub is_mem: bool,
    pub conn: SqlitePool,
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

    pub async fn create_instance(&self, instance: Instance) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO  instance (instance_id, bridge_path, from_addr, to_addr, amount, \
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
        .execute(&self.conn)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_instance(&self, instance_id: &str) -> anyhow::Result<Instance> {
        let row = sqlx::query_as!(
            Instance,
            "SELECT instance_id, bridge_path, from_addr, to_addr, amount, status, goat_txid,  \
            btc_txid ,pegin_tx, kickoff_tx, created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" \
            FROM  instance where instance_id = ?",
            instance_id
        ).fetch_one(&self.conn)
            .await?;
        Ok(row)
    }
    pub async fn instance_list(
        &self,
        user: &Option<String>,
        offset: u32,
        limit: u32,
    ) -> anyhow::Result<Vec<Instance>> {
        let res = match user {
            Some(user) => {
                sqlx::query_as!(
                    Instance,
                    "SELECT instance_id, bridge_path, from_addr, to_addr, amount, status, goat_txid, btc_txid ,pegin_tx, kickoff_tx, \
                    created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" from instance where from_addr = ? \
                    ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    user,
                    limit,
                    offset
                ).fetch_all(&self.conn).await?
            }
            None => {
                sqlx::query_as!(
                    Instance,
                    "SELECT instance_id, bridge_path, from_addr, to_addr, amount, status, goat_txid, btc_txid ,pegin_tx, kickoff_tx, \
                     created_at as \"created_at: i64\", updated_at as \"updated_at: i64\" from instance  \
                     ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    limit,
                    offset
                ).fetch_all(&self.conn).await?
            }
        };
        Ok(res)
    }

    /// Update Instance
    pub async fn update_instance(&self, instance: Instance) -> anyhow::Result<u64> {
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
        .execute(&self.conn)
        .await?;
        Ok(row.rows_affected())
    }

    /// Insert or update graph
    pub async fn update_graph(&self, graph: Graph) -> anyhow::Result<u64> {
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
        ).execute(&self.conn)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_graph(&self, graph_id: &str) -> anyhow::Result<Graph> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id, instance_id, graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  graph_id = ?",
            graph_id
        ).fetch_one(&self.conn).await?;
        Ok(res)
    }

    pub async fn filter_graphs(
        &self,
        filter_graphs_info: &FilterGraphsInfo,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id, instance_id, graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  status = ? and pegin_txid = ?  LIMIT ? OFFSET ?",
            filter_graphs_info.status,
           filter_graphs_info.pegin_txid,
           filter_graphs_info.limit,
            filter_graphs_info.offset,
        ).fetch_all(&self.conn).await?;
        Ok(res)
    }

    pub async fn get_graphs(&self, graph_ids: &Vec<String>) -> anyhow::Result<Vec<Graph>> {
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
        let res = query.fetch_all(&self.conn).await?;
        Ok(res)
    }

    pub async fn get_graph_by_instance_id(&self, instance_id: &str) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as!(
            Graph,
            "SELECT  graph_id, instance_id, graph_ipfs_base_url, pegin_txid, amount, status, challenge_txid,\
             disprove_txid, created_at as \"created_at: i64\" FROM graph WHERE  instance_id = ?",
            instance_id
        ).fetch_all(&self.conn).await?;
        Ok(res)
    }

    /// Insert or update node
    pub async fn update_node(&self, node: Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT OR REPLACE INTO  node (peer_id, actor, updated_at) VALUES ( ?, ?, ?) ",
            node.peer_id,
            node.actor,
            node.updated_at,
        )
        .execute(&self.conn)
        .await?;
        Ok(res.rows_affected())
    }

    /// Query node list
    pub async fn node_list(
        &self,
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
                .fetch_all(&self.conn)
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
                .fetch_all(&self.conn)
                .await?
            }
        };
        Ok(res)
    }

    pub async fn get_sum_bridge_in_or_out(&self, bridge_path: u8) -> anyhow::Result<(i64, i64)> {
        let record = sqlx::query!(
            "SELECT SUM(amount) as total, COUNT(*) as tx_count FROM instance WHERE bridge_path = ? ",
            bridge_path
        )
        .fetch_one(&self.conn)
        .await?;
        Ok((record.total.unwrap_or(0), record.tx_count))
    }

    pub async fn get_nodes_info(&self, time_threshold: i64) -> anyhow::Result<(i64, i64)> {
        let total = sqlx::query!("SELECT COUNT(peer_id) as total FROM node")
            .fetch_one(&self.conn)
            .await?
            .total;
        let time_pri =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - time_threshold;
        tracing::info!("{time_pri}");
        let alive = sqlx::query!(
            "SELECT COUNT(peer_id)  as alive FROM node WHERE updated_at  >= ? ",
            time_pri
        )
        .fetch_one(&self.conn)
        .await?
        .alive;
        Ok((total, alive))
    }
}
