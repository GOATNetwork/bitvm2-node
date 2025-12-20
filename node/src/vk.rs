use anyhow::Result;
use bitvm2_lib::types::VerifyingKey;
use std::fs;
use std::path::PathBuf;
use zkm_sdk::install::CIRCUIT_ARTIFACTS_URL_BASE;
use zkm_verifier::load_ark_groth16_verifying_key_from_bytes;

use {
    futures::StreamExt,
    indicatif::{ProgressBar, ProgressStyle},
    std::{cmp::min, process::Command},
};

pub(crate) fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    use tokio::task::block_in_place;

    // Handle case if we're already in a tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

pub async fn get_vk(zkm_version: &str) -> Result<VerifyingKey> {
    let build_dir = try_install_circuit_artifacts(zkm_version);
    let vk_file = build_dir.join("groth16_vk.bin");
    let content = fs::read(&vk_file)?;
    Ok(load_ark_groth16_verifying_key_from_bytes(&content)?)
}

#[must_use]
pub fn groth16_circuit_artifacts_dir(zkm_version: &str) -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits/groth16").join(zkm_version)
}

/// Tries to install the groth16 circuit artifacts if they are not already installed.
#[must_use]
pub fn try_install_circuit_artifacts(zkm_version: &str) -> PathBuf {
    let artifacts_type = "groth16";
    let build_dir = groth16_circuit_artifacts_dir(zkm_version);

    if build_dir.exists() {
        println!(
            "[ziren] {} circuit artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            artifacts_type,
            build_dir.display()
        );
    } else {
        install_circuit_artifacts(build_dir.clone(), artifacts_type, zkm_version);
    }
    build_dir
}

#[allow(clippy::needless_pass_by_value)]
pub fn install_circuit_artifacts(build_dir: PathBuf, artifacts_type: &str, zkm_version: &str) {
    // Create the build directory.
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url =
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{zkm_version}-{artifacts_type}.tar.gz");
    let mut artifacts_tar_gz_file =
        tempfile::NamedTempFile::new().expect("failed to create tempfile");
    let client = reqwest::Client::builder().build().expect("failed to create reqwest client");
    block_on(download_file(&client, &download_url, &mut artifacts_tar_gz_file))
        .expect("failed to download file");

    // Extract the tarball to the build directory.
    let mut res = Command::new("tar")
        .args([
            "-Pxzf",
            artifacts_tar_gz_file.path().to_str().unwrap(),
            "-C",
            build_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("failed to extract tarball");
    res.wait().unwrap();

    println!("[zkm] downloaded {} to {:?}", download_url, build_dir.to_str().unwrap(),);
}

pub async fn download_file(
    client: &reqwest::Client,
    url: &str,
    file: &mut impl std::io::Write,
) -> std::result::Result<(), String> {
    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", &url)))?;

    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk).or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_get_vk() {
        let latest = zkm_sdk::ZKM_CIRCUIT_VERSION;
        get_vk(latest).await.unwrap();

        let older = "v1.2.2";
        get_vk(older).await.unwrap();
    }
}
