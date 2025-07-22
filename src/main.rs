mod client;
mod config;
mod tls;

use anyhow::Result;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let config = tls::create_ssl_connector()?;

    println!("Performing full handshake...");
    client::perform_full_handshake(config.clone()).await?;
    println!("Session obtained.");

    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("\nPerforming resumed handshake...");
    client::perform_resumed_handshake(config).await?;
    println!("Resumed handshake completed.");

    Ok(())
}
