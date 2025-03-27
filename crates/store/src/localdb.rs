use sqlx::{migrate::MigrateDatabase, FromRow, Row, Sqlite, SqlitePool, Pool, Sqlite};
use std::path::PathBuf;

pub struct LocalDB {
    path: String,
    is_mem: bool,
    conn: Pool<Sqlite>,
}

impl LocalDB {
    async fn new (path: &str, is_mem: bool) -> LocalDB {
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
        Self{
            path: path.to_string(),
            is_mem,
            conn,
        }
    }

    async fn migrate(&self) {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let migrations = std::path::Path::new(&crate_dir).join("./migrations");

        let migration_results = sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&self.conn)
            .await;

        match migration_results {
            Ok(_) => println!("Migration success"),
            Err(error) => {
                panic!("error: {}", error);
            }
        }
    }

    // TODO define sql for table in schema
}