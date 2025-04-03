use crate::{FilterGraphsInfo, Graph, GraphStatus, Instance, Node};
use sqlx::{FromRow, Row, Sqlite, SqlitePool, migrate::MigrateDatabase};
use std::time::SystemTime;

#[derive(Clone)]
pub struct LocalDB {
    pub path: String,
    pub is_mem: bool,
    pub conn: SqlitePool,
}

impl LocalDB {
    pub async fn new(path: &str, is_mem: bool) -> LocalDB {
        if !Sqlite::database_exists(path).await.unwrap_or(false) {
            println!("Creating database {}", path);
            match Sqlite::create_database(path).await {
                Ok(_) => println!("Create db success"),
                Err(error) => panic!("error: {}", error),
            }
        } else {
            println!("Database already exists");
        }

        let conn = SqlitePool::connect(path).await.unwrap();
        Self { path: path.to_string(), is_mem, conn }
    }

    async fn migrate(&self) {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let migrations = std::path::Path::new(&crate_dir).join("./migrations");

        let migration_results =
            sqlx::migrate::Migrator::new(migrations).await.unwrap().run(&self.conn).await;

        match migration_results {
            Ok(_) => println!("Migration success"),
            Err(error) => {
                panic!("error: {}", error);
            }
        }
    }

    // TODO define sql for table in schema
    pub async fn create_instance(&self, instance: Instance) {
        println!("save instance {:?}", instance);
        // TODO
    }

    pub async fn get_instance(&self, instance_id: &str) -> anyhow::Result<Instance> {
        println!("query graph  by {instance_id}");
        // TODO
        let mut instance = Instance::default();
        instance.instance_id = instance_id.to_string();
        instance.from = "tb1qsyngu9wf2x46tlexhpjl4nugv0zxmgezsx5erl".to_string();
        instance.to = "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp".to_string();
        instance.btc_txid =
            "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c".to_string();
        instance.status = "BridgeInStatus | BridgeOutStutus".to_string();
        instance.amount = 1000000;
        instance.update_at = 200000;
        instance.goat_txid =
            "34f36ee1e8ee298f1aa37b43afefc4e7ea56e36fd56f8bc62e9db932b03babc1".to_string();
        Ok(instance)
    }
    pub async fn get_instance_by_user(
        &self,
        user: &str,
        offset: u32,
        limit: u32,
    ) -> anyhow::Result<Vec<Instance>> {
        println!("query graph by {user}");
        let mut instance = Instance::default();
        let mut instance = self.get_instance("34f36ee1e8e34f36ee1e8e34f36e").await?;
        instance.from = user.to_string();
        Ok(vec![instance; limit as usize])
    }

    /// Update Instance
    pub async fn update_instance(&self, instance: Instance) {
        println!("update instance {:?}", instance);
        // TODO
    }

    /// Insert or update graph
    pub async fn update_graph(&self, graph: Graph) {
        println!("update graph {:?}", graph);
        // TODO
    }

    pub async fn get_graph(&self, graph_id: &str) -> anyhow::Result<Graph> {
        println!("query graph  by {graph_id}");
        let mut graph = Graph::default();
        graph.graph_id = graph_id.to_string();
        graph.instance_id = "34f36ee1e8e34f36ee1e8e34f36e".to_string();
        graph.amount = 10000;
        graph.status = GraphStatus::CommitteePresigned;
        graph.graph_ipfs_base_url =
            "https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH".to_string();
        graph.created_at = std::time::SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("duration time")
            .as_secs();
        graph.challenge_txid =
            Some("a73308fecf906f436583b30f8fd6ac56265fba90efb3f788d7c2d18b1ecfd8aa".to_string());
        graph.disprove_txid =
            Some("53b737e32d2a5ca18ebc5468b960f511acaab465f3f88f52f17a58404b7ec1ae".to_string());
        graph.peg_in_txid =
            "58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c".to_string();
        // TODO
        Ok(graph)
    }

    pub async fn filter_graphs(
        &self,
        filter_graphs_info: &FilterGraphsInfo,
    ) -> anyhow::Result<Vec<Graph>> {
        let mut grap = self.get_graph("eeeeeee34f36ee1e8e34f36").await?;
        grap.peg_in_txid = filter_graphs_info.pegin_txid.to_string();
        grap.status = GraphStatus::CommitteePresigned;
        Ok(vec![grap; filter_graphs_info.limit as usize])
    }

    pub async fn get_graphs(&self, graph_ids: &Vec<String>) -> anyhow::Result<Vec<Graph>> {
        println!("query graph  by {graph_ids:?}");
        let mut graphs = vec![];
        for id in graph_ids.into_iter() {
            let mut graph = self.get_graph(id).await?;
            graph.graph_id = id.to_string();
            graphs.push(graph)
        }
        // TODO
        Ok(graphs)
    }

    pub async fn get_graph_by_instance_id(&self, instance_id: &str) -> anyhow::Result<Vec<Graph>> {
        println!("query graph  by instance_id {instance_id}");
        let mut graph = self.get_graph(instance_id).await?;
        graph.instance_id = instance_id.to_string();
        // TODO
        Ok(vec![graph])
    }

    /// Insert or update node
    pub async fn update_node(&self, node: Node) {
        println!("update node {:?}", node);
        // TODO
    }

    /// Query node list
    pub async fn node_list(
        &self,
        role: &str,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<Vec<Node>> {
        println!("query  node list by {role}, {offset}, {limit}");
        Ok(vec![
            Node {
                peer_id: "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".to_string(),
                actor: role.to_string(),
                update_at: std::time::SystemTime::now(),
            };
            limit
        ])

        // //TODO
        // Ok(Vec::new())
    }
}
