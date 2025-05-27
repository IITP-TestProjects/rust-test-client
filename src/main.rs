pub mod client_helper;
pub mod client_network;
pub mod vrfs;

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use crate::client_network::{TransferServer, run_client, start_client_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let node_id = args.iter()
        .find(|s| s.starts_with("--node="))
        .map(|s| s[7..].to_string())
        .unwrap_or_else(|| "node1".into());

    let ts = Arc::new(TransferServer::new());
    if node_id == "node1" {
        let ts_clone = ts.clone();
        tokio::spawn(async move {
            start_client_server(ts_clone).await.unwrap();
        });
        sleep(Duration::from_millis(200)).await;
    }

    run_client(node_id, ts).await
}