use anyhow::{Result, bail};
use futures::TryStreamExt;
use reqwest::Client;
use reqwest::multipart::{Form, Part};
use serde::Deserialize;
use std::path::Path;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
use walkdir::WalkDir;

pub struct IPFS {
    pub endpoint: String,
    pub client: Client,
}

#[derive(Deserialize, Debug, PartialEq, Hash)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    hash: String,
    mod_time: String,
    mode: u32,
    name: String,
    size: u32,
    target: String,
    #[serde(rename = "Type")]
    type_: u32,
}

#[derive(Deserialize, Debug, PartialEq, Hash)]
#[serde(rename_all = "PascalCase")]
pub struct Object {
    hash: String,
    links: Vec<Link>,
}

#[derive(Deserialize, Debug, PartialEq, Hash)]
#[serde(rename_all = "PascalCase")]
pub struct Objects {
    objects: Vec<Object>,
}

/// If the name is empty, it's the directory name
#[derive(Deserialize, Debug, PartialEq, Hash)]
#[serde(rename_all = "PascalCase")]
pub struct AddedFile {
    name: String,
    hash: String,
    size: String,
}

// Collects all files and returns relative + absolute paths
async fn collect_files(base_path: &Path) -> Result<Form> {
    let mut form = Form::new();

    for entry in
        WalkDir::new(base_path).into_iter().filter_map(Result::ok).filter(|e| e.path().is_file())
    {
        let rel_path = entry.path().strip_prefix(base_path)?.to_str().unwrap().replace("\\", "/");
        let file = File::open(entry.path()).await?;
        let stream = FramedRead::new(file, BytesCodec::new())
            .map_ok(|b| b.freeze())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
        let body = reqwest::Body::wrap_stream(stream);
        let part = Part::stream(body).file_name(rel_path.clone());
        form = form.part("file", part);
    }
    Ok(form)
}

impl IPFS {
    pub fn new(endpoint: &str) -> Self {
        let client = Client::new();
        let endpoint = endpoint.to_string();
        Self { endpoint, client }
    }

    // list directory
    // API: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-ls
    pub async fn ls(&self, hash: &str) -> Result<Objects> {
        let url = format!("{}/api/v0/ls", self.endpoint);
        let form = reqwest::multipart::Form::new().text("arg", hash.to_owned());
        let response = self.client.post(url).multipart(form).send().await?;
        if response.status().is_success() {
            let response_body = response.text().await?;
            Ok(serde_json::from_str(&response_body)?)
        } else {
            bail!("IPFS read failed, {:?}", response)
        }
    }

    // Read the content
    // API: https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-cat
    pub async fn cat(&self, hash: &str) -> Result<String> {
        let url = format!("{}/api/v0/cat", self.endpoint);
        let form = reqwest::multipart::Form::new().text("arg", hash.to_owned());
        let response = self.client.post(url).multipart(form).send().await?;
        if response.status().is_success() {
            let response_body = response.text().await?;
            Ok(response_body.to_string())
        } else {
            bail!("IPFS read failed, {:?}", response)
        }
    }

    /// Add file to IPFS and return its ipfs url
    pub async fn add(&self, base_path: &Path) -> Result<Vec<AddedFile>> {
        let url = format!("{}/api/v0/add?recursive=true&wrap-with-directory=true", self.endpoint);

        let form = collect_files(base_path).await?;
        let response = self.client.post(url).multipart(form).send().await?;
        if response.status().is_success() {
            let response_body = response.text().await?;
            println!("add: {:?}", response_body);

            let shares = response_body.trim().split("\n").collect::<Vec<_>>();

            println!("add: {:?}", shares);

            let added_files =
                shares.iter().map(|f| serde_json::from_str(f).unwrap()).collect::<Vec<AddedFile>>();

            Ok(added_files)
        } else {
            bail!("IPFS upload failed, {:?}", response)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;
    #[tokio::test]
    async fn test_ipfs_add_and_get() {
        println!("connecting to localhost:5001...");
        let client = IPFS::new("http://44.229.236.82:5001");
        //let client = IPFS::new("http://localhost:5001");

        // Read single file
        match client.cat("QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH/assert-commit0.hex").await
        {
            Ok(res) => {
                println!("cat: {:?}", res);
            }
            Err(e) => panic!("{}", e),
        }

        // list directory
        match client.ls("QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH").await {
            Ok(res) => {
                println!("ls: {:?}", res);
            }
            Err(e) => panic!("{}", e),
        }

        // it works, but skip for avoiding creating too much garbage
        // let base_dir = tempfile::tempdir().unwrap();
        // vec!["1.txt", "2.txt"].iter().for_each(|name| {
        //     let mut file = std::fs::File::create(
        //         base_dir.path().join(name)
        //     ).unwrap();
        //     let _ = writeln!(file, "GOAT Network").unwrap();
        // });
        // match client.add(base_dir.path()).await {
        //     Ok(hash) => {
        //         println!("add hash: {:?}", hash);
        //         // FIXME: can not read immidately.
        //     }
        //     Err(e) => panic!("error adding file: {}", e),
        // }
    }
}
