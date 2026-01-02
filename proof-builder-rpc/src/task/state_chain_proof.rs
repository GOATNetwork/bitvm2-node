use crate::task::{create_long_running_task, update_long_running_task};
use crate::{ProofBuilderConfig, task::fetch_latest_long_running_task};
use proof_builder::{ProofBuilder, ProofRequest};
use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

async fn spawn_state_chain_ctx_builder(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    init_interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let mut args = args;
    let mut interval = init_interval;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                let next_task = fetch_latest_long_running_task(
                    &local_db,
                    StateChainProofBuilder::name()
                ).await?;

                if let Some(next_task) = next_task {
                    args.start = next_task.block_end as u64;
                    args.input_proof = next_task.path_to_proof.unwrap();
                    args.output_proof = format!(
                        "{}/{}-{}.bin",
                        std::path::Path::new(&args.output_proof)
                            .parent().unwrap()
                            .to_str().unwrap(),
                        args.start,
                        args.batch_size
                    );
                    args.init_input = false;
                }

                tracing::info!("ctx builder: fetching blocks, args={args:?}");

                let blocks = match fetch_state_chain(
                    &args.l2_contract_address,
                    &args.proceed_withdraw_method_id,
                    args.start,
                    args.batch_size,
                    &args.execution_layer_rpc,
                    &args.blocks,
                    &args.goat_network,
                    &args.cosmos_rpc_url,
                ).await {
                    Ok(d) => d,
                    Err(e) => {
                        if let Some(proof_builder::ProofError::InputNotReady(ee)) = e.downcast_ref::<proof_builder::ProofError>() {
                            interval = *ee;
                            tracing::error!("fetch state chain: {e}, sleeping {interval}s");
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                };
                interval = init_interval;

                let ctx = ProofRequest::StateChainProofRequest {
                    init_input: args.init_input,
                    input_proof: args.input_proof.clone(),
                    output_proof: args.output_proof.clone(),
                    start: args.start,
                    l2_contract_address: args.l2_contract_address.clone(),
                    batch_size: args.batch_size,
                    blocks,
                };

                let snap_path = std::path::Path::new(&args.input_proof).parent().unwrap().to_str().unwrap();
                tracing::info!("fetch snap_path: {snap_path:?}");
                std::fs::write(&format!("{}/{}.args", snap_path, args.start), serde_json::to_string(&args)?)?;
                std::fs::write(&format!("{}/{}.ctx", snap_path, args.start), serde_json::to_string(&ctx)?)?;

                create_long_running_task(
                    &local_db,
                    args.start,
                    args.batch_size,
                    args.output_proof.clone(),
                    "".to_string(),
                    0,
                    0,
                    StateChainProofBuilder::name(),
                    0,
                    0,
                    store::ProofState::Proving,
                    "".to_string(),
                ).await?;

                args = ProofBuilderConfig::run_next(args, StateChainProofBuilder::name())?;
            }
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("ctx builder cancelled");
            }
        }
    }
}

async fn spawn_state_chain_prover(
    mut start_index: u64,
    batch_size: u64,
    input_proof: String,
    local_db: LocalDB,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let builder = StateChainProofBuilder::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                tracing::info!("prover: start proving");

                let snap_path = std::path::Path::new(&input_proof).parent().unwrap().to_str().unwrap();
                let args: state_chain_proof::Args = match std::fs::read(&format!("{}/{}.args", snap_path, start_index)) {
                    Ok(x) => serde_json::from_slice(&x)?,
                    Err(e) => {
                        tracing::error!("Read args: {snap_path}, {e:?}");
                        continue;
                    }
                }

                ;
                let ctx: ProofRequest = match &std::fs::read(&format!("{}/{}.ctx", snap_path, start_index)) {
                    Ok(x) => serde_json::from_slice(&x)?,
                    Err(e) => {
                        tracing::error!("Read ctx: {snap_path}/{start_index}.ctx, {e:?}");
                        continue;
                    }
                };

                let (input, proof, cycles, proving_time) =
                    match builder.build_proof(&ctx) {
                        Ok(d) => d,
                        Err(err) => {
                            tracing::error!("Build proof error: {err}");
                            continue;
                        }
                    };

                let zkm_version = proof.zkm_version.clone();
                let (public_value_hex, proof_size) =
                    builder.save_proof(&ctx, &input, cycles, proof)?;

                update_long_running_task(
                    &local_db,
                    start_index as i64,
                    batch_size as i64,
                    args.output_proof.clone(),
                    public_value_hex,
                    proof_size as i64,
                    cycles,
                    StateChainProofBuilder::name(),
                    proving_time as i64,
                    zkm_version,
                ).await?;
                start_index += batch_size;
            }
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("prover cancelled");
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(cancellation_token))]
pub(crate) fn spawn_state_chain_proof_task(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(initial_delay)).await;

        let ctx_builder = tokio::spawn(spawn_state_chain_ctx_builder(
            args.clone(),
            local_db.clone(),
            interval,
            cancellation_token.clone(),
        ));

        let input_proof = args.input_proof.clone();
        let prover = tokio::spawn(spawn_state_chain_prover(
            args.start,
            args.batch_size,
            input_proof,
            local_db.clone(),
            interval,
            cancellation_token.clone(),
        ));

        tokio::select! {
            res = ctx_builder => {
                res??;
            }
            res = prover => {
                res??;
            }
            _ = cancellation_token.cancelled() => {
                tracing::warn!("state chain proof task cancelled");
            }
        }

        Ok(())
    })
}
