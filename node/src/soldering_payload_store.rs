use anyhow::{Context, Result, anyhow, bail};
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

pub(crate) fn is_soldering_proof_s3_path(path: &str) -> bool {
    path.trim().starts_with("s3://")
}

pub(crate) fn soldering_proof_payload_store_path(
    base_path: &str,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
    payload_hash: &[u8; 32],
) -> Result<String> {
    let base_path = base_path.trim();
    if base_path.is_empty() {
        bail!("soldering proof payload store path cannot be empty");
    }
    let payload_name = format!("{graph_id}-{verifier_index}-{}.bin", hex::encode(payload_hash));
    if is_soldering_proof_s3_path(base_path) {
        Ok(format!("{}/{}/{}", base_path.trim_end_matches('/'), instance_id, payload_name))
    } else {
        Ok(PathBuf::from(base_path)
            .join(instance_id.to_string())
            .join(payload_name)
            .to_string_lossy()
            .to_string())
    }
}

fn parse_soldering_proof_s3_path(path: &str) -> Result<(String, String)> {
    let path = path.trim();
    let path = path
        .strip_prefix("s3://")
        .ok_or_else(|| anyhow!("soldering proof payload path is not an s3 path"))?;
    let (bucket, key) = path
        .split_once('/')
        .ok_or_else(|| anyhow!("soldering proof s3 path must include bucket and key"))?;
    if bucket.is_empty() {
        bail!("soldering proof s3 path bucket cannot be empty");
    }
    if key.is_empty() {
        bail!("soldering proof s3 path key cannot be empty");
    }
    Ok((bucket.to_string(), key.to_string()))
}

pub(crate) async fn write_soldering_proof_store_payload(path: &str, payload: &[u8]) -> Result<()> {
    let result = write_soldering_proof_store_payload_inner(path, payload).await;
    if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
        metrics_state.record_soldering_payload_io(result.is_ok());
    }
    result
}

async fn write_soldering_proof_store_payload_inner(path: &str, payload: &[u8]) -> Result<()> {
    if is_soldering_proof_s3_path(path) {
        let (bucket, key) = parse_soldering_proof_s3_path(path)?;
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_s3::Client::new(&config);
        client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .body(ByteStream::from(payload.to_vec()))
            .send()
            .await
            .with_context(|| format!("write soldering proof payload to {path}"))?;
        return Ok(());
    }

    let path = Path::new(path.trim());
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create soldering proof payload dir {}", parent.display()))?;
    }
    let mut temp_path = path.as_os_str().to_os_string();
    temp_path.push(".tmp");
    let temp_path = PathBuf::from(temp_path);
    tokio::fs::write(&temp_path, payload)
        .await
        .with_context(|| format!("write soldering proof payload {}", temp_path.display()))?;
    tokio::fs::rename(&temp_path, path).await.with_context(|| {
        format!("move soldering proof payload {} to {}", temp_path.display(), path.display())
    })?;
    Ok(())
}

pub(crate) async fn read_soldering_proof_store_payload(path: &str) -> Result<Vec<u8>> {
    let result = read_soldering_proof_store_payload_inner(path).await;
    if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
        metrics_state.record_soldering_payload_io(result.is_ok());
    }
    result
}

async fn read_soldering_proof_store_payload_inner(path: &str) -> Result<Vec<u8>> {
    if is_soldering_proof_s3_path(path) {
        let (bucket, key) = parse_soldering_proof_s3_path(path)?;
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_s3::Client::new(&config);
        let object = client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("read soldering proof payload from {path}"))?;
        let mut reader = object.body.into_async_read();
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .with_context(|| format!("read soldering proof s3 body from {path}"))?;
        return Ok(payload);
    }

    tokio::fs::read(path.trim())
        .await
        .with_context(|| format!("read soldering proof payload {}", path.trim()))
}

pub(crate) async fn delete_soldering_proof_store_payload(path: &str) -> Result<()> {
    if is_soldering_proof_s3_path(path) {
        bail!("S3 soldering proof cleanup is not supported");
    }
    match tokio::fs::remove_file(path.trim()).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("delete soldering proof payload {}", path.trim()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_test_ids() -> (Uuid, Uuid, [u8; 32]) {
        (
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            [0xabu8; 32],
        )
    }

    #[test]
    fn soldering_payload_store_detects_s3_paths() {
        assert!(is_soldering_proof_s3_path("s3://bucket/prefix"));
        assert!(!is_soldering_proof_s3_path("/tmp/soldering"));
        assert!(!is_soldering_proof_s3_path("relative/soldering"));
    }

    #[test]
    fn soldering_payload_store_builds_deterministic_paths() {
        let (instance_id, graph_id, payload_hash) = store_test_ids();
        let s3_path = soldering_proof_payload_store_path(
            "s3://bucket/prefix/",
            instance_id,
            graph_id,
            7,
            &payload_hash,
        )
        .unwrap();
        assert_eq!(
            s3_path,
            "s3://bucket/prefix/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222-7-abababababababababababababababababababababababababababababababab.bin"
        );

        let local_path = soldering_proof_payload_store_path(
            "/tmp/soldering/",
            instance_id,
            graph_id,
            7,
            &payload_hash,
        )
        .unwrap();
        assert_eq!(
            local_path,
            "/tmp/soldering/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222-7-abababababababababababababababababababababababababababababababab.bin"
        );
    }

    #[tokio::test]
    async fn soldering_payload_store_local_write_read_round_trip() {
        let (instance_id, graph_id, payload_hash) = store_test_ids();
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path().to_string_lossy();
        let path =
            soldering_proof_payload_store_path(&base, instance_id, graph_id, 0, &payload_hash)
                .unwrap();
        let payload = b"compact soldering proof".to_vec();

        write_soldering_proof_store_payload(&path, &payload).await.unwrap();
        let restored = read_soldering_proof_store_payload(&path).await.unwrap();
        assert_eq!(restored, payload);
    }
}
