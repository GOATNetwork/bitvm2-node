use std::error::Error;

use futures::stream::StreamExt;
use tokio::io::AsyncBufReadExt;
use tracing_subscriber::EnvFilter;
pub mod authenticator;
pub mod behaviour;
mod actors;

pub use behaviour::AllBehaviours;