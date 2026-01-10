use crate::env::*;
use anyhow::Result;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{Amount, Transaction, TxIn};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use tracing::warn;
use uuid::Uuid;

const ASSERT_COMMIT_CACHE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct CachedAssertCommitInput {
    txin: Vec<u8>,
    amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
struct CachedAssertCommitInputs {
    version: u32,
    inputs: Vec<CachedAssertCommitInput>,
}

fn embed_txin_into_dummy_tx(txin: &TxIn) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![txin.clone()],
        output: vec![],
    }
}

fn extract_txin_from_dummy_tx(tx: &Transaction) -> TxIn {
    tx.input[0].clone()
}

fn assert_commit_cache_path(graph_id: Uuid) -> PathBuf {
    Path::new(ASSERT_COMMITS_CACHE_DIR).join(format!("{graph_id}.json"))
}

pub(crate) fn load_assert_commit_inputs_from_cache(graph_id: Uuid) -> Option<Vec<(TxIn, Amount)>> {
    let path = assert_commit_cache_path(graph_id);
    if !path.exists() {
        return None;
    }
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            warn!("failed to open assert-commit cache {path:?}: {err:?}");
            return None;
        }
    };
    let reader = BufReader::new(file);
    let cached: CachedAssertCommitInputs = match serde_json::from_reader(reader) {
        Ok(data) => data,
        Err(err) => {
            warn!("failed to deserialize assert-commit cache {path:?}: {err:?}");
            return None;
        }
    };
    if cached.version != ASSERT_COMMIT_CACHE_VERSION {
        warn!(
            "assert-commit cache version mismatch for {path:?}, expecting {ASSERT_COMMIT_CACHE_VERSION}, got {}",
            cached.version
        );
        return None;
    }
    let mut inputs = Vec::with_capacity(cached.inputs.len());
    for item in cached.inputs {
        match deserialize::<Transaction>(&item.txin) {
            Ok(txin_embed_tx) => inputs.push((
                extract_txin_from_dummy_tx(&txin_embed_tx),
                Amount::from_sat(item.amount_sat),
            )),
            Err(err) => {
                warn!("failed to decode txin from cache {path:?}: {err:?}");
                return None;
            }
        }
    }
    Some(inputs)
}

pub(crate) fn store_assert_commit_inputs_in_cache(
    graph_id: Uuid,
    inputs: &[(TxIn, Amount)],
) -> Result<()> {
    fs::create_dir_all(ASSERT_COMMITS_CACHE_DIR)?;
    let path = assert_commit_cache_path(graph_id);
    let file = File::create(&path)?;
    let writer = BufWriter::new(file);
    let payload = CachedAssertCommitInputs {
        version: ASSERT_COMMIT_CACHE_VERSION,
        inputs: inputs
            .iter()
            .map(|(txin, amount)| CachedAssertCommitInput {
                txin: serialize(&embed_txin_into_dummy_tx(txin)),
                amount_sat: amount.to_sat(),
            })
            .collect(),
    };
    serde_json::to_writer(writer, &payload)?;
    Ok(())
}

pub(crate) fn cleanup_assert_commit_cache(graph_id: Uuid) -> Result<()> {
    let path = assert_commit_cache_path(graph_id);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
