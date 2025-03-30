use crate::{Covenant, Node, Transaction};
use sqlx::{FromRow, Row, Sqlite, SqlitePool, migrate::MigrateDatabase};
use std::path::PathBuf;

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
    pub async fn create_covenant(&self, covenant: Covenant) {
        println!("save covenant {:?}", covenant);
        // TODO
    }

    /// Insert or update node
    pub async fn update_node(&self, node: Node) {
        println!("update node {:?}", node);
        // TODO
    }
    /// Insert or update node
    pub async fn create_transaction(&self, tx: Transaction) {
        println!("create tx {:?}", tx);
        // TODO
    }
    pub async fn get_transaction(&self, tx: Transaction) {
        println!("get tx {:?}", tx);
        // TODO
    }
}