use std::error::Error;

use futures::stream::StreamExt;
use tokio::io::AsyncBufReadExt;
use tracing_subscriber::EnvFilter;
mod actors;
pub mod authenticator;
pub mod behaviour;

pub use behaviour::AllBehaviours;
