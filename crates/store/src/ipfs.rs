use anyhow::{Result, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

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
    pub async fn add(&self, file_bytes: Vec<u8>) -> Result<String> {
        let url = format!("{}/api/v0/add", self.endpoint);

        // Read file bytes
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(file_bytes));

        let response = self.client.post(url).multipart(form).send().await?;

        if response.status().is_success() {
            let response_body = response.text().await?;

            let ipfs_response: Value = serde_json::from_str(&response_body)?;

            Ok(ipfs_response["Hash"].to_string())
        } else {
            bail!("IPFS upload failed")
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[tokio::test]
    async fn test_ipfs_add_and_get() {
        println!("connecting to localhost:5001...");
        //let client = IPFS::new("http://44.229.236.82:5001");
        let client = IPFS::new("http://localhost:5001");

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

        let content = "!!! hello, world!";
        match client.add(content.as_bytes().to_vec()).await {
            Ok(hash) => {
                println!("add hash: {}", hash);
                // FIXME: can not read immidately.
            }
            Err(e) => panic!("error adding file: {}", e),
        }
    }
}
