pub mod action;
pub mod env;
pub mod metrics_service;
pub mod middleware;
pub mod p2p_msg_handler;

pub mod rpc_service;
mod scheduled_tasks;
pub mod utils;
pub use scheduled_tasks::{run_maintenance_tasks, run_watch_event_task};
mod error;

mod vk;

mod dbg {
    #[tokio::test]
    async fn dbg_serde() {
        let dbg_path = "/home/ubuntu/bitvm2-nodes-test/operator_0/bitvm2-node.db";
        let instance_id = uuid::Uuid::parse_str("c41d4b7c967f4e4d975853723571bd7f").unwrap();
        let graph_id = uuid::Uuid::parse_str("c35914b88d7f4670a75aa7d91b855439").unwrap();
        let local_db = store::create_local_db(dbg_path).await;
    }
}
