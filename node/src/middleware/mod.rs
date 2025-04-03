use std::error::Error;

use futures::stream::StreamExt;
use tokio::io::AsyncBufReadExt;
use tracing_subscriber::EnvFilter;
pub mod behaviour;

pub use behaviour::AllBehaviours;
