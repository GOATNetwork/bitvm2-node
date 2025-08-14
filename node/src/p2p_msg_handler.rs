use crate::action::{GOATMessage, GOATMessageContent, recv_and_dispatch, send_to_peer};
use crate::client::{btc_chain::BTCClient, goat_chain::GOATClient};
use crate::env::get_local_node_info;
use crate::middleware::swarm::{BitvmSwarmWrapper, P2pMessageHandler, TickMessageType};
use crate::utils::detect_heart_beat;
use bitvm2_lib::actors::Actor;
use libp2p::PeerId;
use libp2p::gossipsub::MessageId;
use store::ipfs::IPFS;
use store::localdb::LocalDB;

pub struct BitvmNodeProcessor {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub goat_client: GOATClient,
    pub ipfs: IPFS,
}
impl P2pMessageHandler for BitvmNodeProcessor {
    async fn recv_and_dispatch(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        from_peer_id: PeerId,
        id: MessageId,
        message: &[u8],
    ) -> anyhow::Result<()> {
        let res = recv_and_dispatch(
            swarm,
            &self.local_db,
            &self.btc_client,
            &self.goat_client,
            &self.ipfs,
            actor,
            from_peer_id,
            id,
            message,
        )
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(err) => Err(anyhow::Error::msg(err.to_string())),
        }
    }

    async fn handle_tick_message(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        peer_id: PeerId,
        actor: Actor,
        msg_type: TickMessageType,
    ) -> anyhow::Result<()> {
        match msg_type {
            TickMessageType::HeartBeat => {
                match detect_heart_beat(swarm).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("detect_heart_beat: {e}");
                    }
                }
                tracing::debug!("Handling heartbeat tick message");
                Ok(())
            }
            TickMessageType::RegularlyAction => {
                tracing::debug!("Handling regular action tick message");
                let tick_data = serde_json::to_vec(&GOATMessage {
                    actor: actor.clone(),
                    content: "tick".as_bytes().to_vec(),
                })?;

                match recv_and_dispatch(
                    swarm,
                    &self.local_db,
                    &self.btc_client,
                    &self.goat_client,
                    &self.ipfs,
                    actor,
                    peer_id,
                    GOATMessage::default_message_id(),
                    &tick_data,
                )
                .await
                {
                    Ok(_) => Ok(()),
                    Err(err) => Err(anyhow::Error::msg(err.to_string())),
                }
            }
        }
    }

    async fn finish_subscribe_topic(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        _actor: Actor,
        topic: &str,
    ) -> anyhow::Result<()> {
        if topic == Actor::All.to_string() {
            let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
            match send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?) {
                Ok(_) => {}
                Err(e) => {
                    println!("finish_subscribe_topic: send request NodeInfo {e}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::action::{GOATMessage, GOATMessageContent, NodeInfo, send_to_peer};
    use crate::env::get_rpc_support_actors;
    use crate::middleware::swarm::{
        Bitvm2SwarmConfig, BitvmNetworkManager, BitvmSwarmWrapper, P2pMessageHandler,
        TickMessageType,
    };
    use crate::utils::save_node_info;
    use bitvm2_lib::actors::Actor;
    use libp2p::PeerId;
    use libp2p::gossipsub::MessageId;
    use prometheus_client::registry::Registry;
    use store::localdb::LocalDB;
    use tokio_util::sync::CancellationToken;
    use tracing::Level;
    use tracing::warn;

    #[derive(Debug)]
    struct MockBitvmNodeProcessor {
        pub local_db: LocalDB,
    }
    pub async fn detect_heart_beat(
        swarm: &mut BitvmSwarmWrapper,
        node_info: NodeInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("start detect_heart_beat");
        let message_content = GOATMessageContent::RequestNodeInfo(node_info);
        // send to actor
        let actors = get_rpc_support_actors();
        for actor in actors {
            match send_to_peer(swarm, GOATMessage::from_typed(actor, &message_content)?) {
                Ok(_) => {}
                Err(err) => warn!("{err}"),
            }
        }
        Ok(())
    }
    impl P2pMessageHandler for MockBitvmNodeProcessor {
        #[tracing::instrument(level = Level::INFO)]
        async fn recv_and_dispatch(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            from_peer_id: PeerId,
            id: MessageId,
            message: &[u8],
        ) -> anyhow::Result<()> {
            if id == GOATMessage::default_message_id() {
                tracing::info!("recv_and_dispatch receive local message");
                return Ok(());
            }
            let message: GOATMessage = serde_json::from_slice(message)?;
            let content: GOATMessageContent = message.to_typed()?;
            if let (GOATMessageContent::RequestNodeInfo(node_info), _) = (content, actor) {
                save_node_info(&self.local_db, &node_info).await.expect("save_node_info");
            }
            Ok(())
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn handle_tick_message(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _peer_id: PeerId,
            actor: Actor,
            msg_type: TickMessageType,
        ) -> anyhow::Result<()> {
            match msg_type {
                TickMessageType::HeartBeat => {
                    detect_heart_beat(
                        swarm,
                        NodeInfo {
                            peer_id: "test".to_string(),
                            actor: actor.to_string(),
                            goat_addr: "test".to_string(),
                            btc_pub_key: "btc_pub_key_test".to_string(),
                            socket_addr: "test".to_string(),
                        },
                    )
                    .await
                    .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                    Ok(())
                }
                TickMessageType::RegularlyAction => Ok(()),
            }
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn finish_subscribe_topic(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            topic: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn init() {
        let _ = tracing_subscriber::fmt().try_init();
    }

    fn temp_file() -> String {
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        tmp_db.path().as_os_str().to_str().unwrap().to_string()
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_p2p_head_beat() {
        init();
        let local_db = crate::client::create_local_db(&temp_file()).await;
        let local_db_clone = local_db.clone();
        let cancellation_token = CancellationToken::new();
        let cancel_token_clone = cancellation_token.clone();
        let _handle = tokio::spawn(async {
            let mut metric_registry = Registry::default();
            let mut bitvm_network_manager =
                BitvmNetworkManager::new(Bitvm2SwarmConfig{
                    local_key: "CAESQA1AsvghB6dERoim0WwUHoAJ9u5UCv15O6gmMJpmjGU2aWWK4dC1lRrLt7oMrHezB7RWxuc5UdAfEhk+19lh7iA=".to_string(),
                    p2p_port: 9100,
                    bootnodes: vec![],
                    topic_names:vec![
                        Actor::Committee.to_string(),
                        Actor::Challenger.to_string(),
                        Actor::Operator.to_string(),
                        Actor::Relayer.to_string(),
                        Actor::All.to_string(),
                    ],
                    heartbeat_interval: 3,
                    regular_task_interval: 2,
                }, &mut metric_registry).expect("create bitvm2 swarm");
            bitvm_network_manager
                .run(Actor::Relayer, MockBitvmNodeProcessor { local_db }, cancel_token_clone)
                .await
                .expect("Failed to run bitvm swarm");
        });
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let cancel_token_clone = cancellation_token.clone();
        let _handle1 = tokio::spawn(async {
            let mut metric_registry = Registry::default();
            let mut bitvm_network_manager =
                BitvmNetworkManager::new(Bitvm2SwarmConfig{
                    local_key: "CAESQDBb9rRpYlgy8Wy6TjTqic8hd8e5kf0uak/ILeCexgG20mVpLyL7n/v5bjpZNOZ620m/cTzonnSh1l5WP1E/ri0=".to_string(),
                    p2p_port: 9101,
                    bootnodes: vec!["/ip4/127.0.0.1/tcp/9100/p2p/12D3KooWGunnJB9XxBNBcRqE4cyq9aHGD5GjTvsvQijn81Fjnfbm".to_string()],
                    topic_names:  vec![
                        Actor::Committee.to_string(),
                        Actor::Challenger.to_string(),
                        Actor::Operator.to_string(),
                        Actor::Relayer.to_string(),
                        Actor::All.to_string(),
                    ],
                    heartbeat_interval: 2,
                    regular_task_interval: 3,
                }, &mut metric_registry).expect("create bitvm2 swarm");
            let local_db = crate::client::create_local_db(&temp_file()).await;
            bitvm_network_manager
                .run(Actor::Operator, MockBitvmNodeProcessor { local_db }, cancel_token_clone)
                .await
                .expect("Failed to run bitvm swarm");
        });

        let mut index = 1;
        let mut success = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if index == 10 {
                break;
            }

            let mut storage_processor =
                local_db_clone.acquire().await.expect("Failed to acquire local db processor");
            if let Some(node) = storage_processor
                .get_node_by_btc_pub_key("btc_pub_key_test")
                .await
                .expect("Failed to get btc_pub_key")
            {
                success = node.actor == Actor::Operator.to_string();
                break;
            }
            index += 1;
        }
        cancellation_token.cancel();
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(success);
    }
}
