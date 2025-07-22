use crate::config::{EARLY_REQUEST, HOST, IP_ADDR, REQUEST};
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::sync::Arc;

async fn read_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<()> {
    let mut buf = vec![0; 8192];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => print!("{}", String::from_utf8_lossy(&buf[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Many servers (like google) drop the TCP connection without a TLS close_notify
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub async fn perform_full_handshake(config: Arc<ClientConfig>) -> Result<()> {
    let stream = TcpStream::connect(IP_ADDR).await?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let domain = ServerName::try_from(HOST)?.to_owned();

    let mut tls_stream = connector.connect(domain, stream).await?;

    tls_stream.write_all(REQUEST.as_bytes()).await?;
    read_response(&mut tls_stream).await?;

    let _ = tls_stream.shutdown().await; // Ignore shutdown errors (like UnexpectedEof)
    Ok(())
}

pub async fn perform_resumed_handshake(config: Arc<ClientConfig>) -> Result<()> {
    let stream = TcpStream::connect(IP_ADDR).await?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let domain = ServerName::try_from(HOST)?.to_owned();

    // Enable early data for this connection
    let mut tls_stream = connector.early_data(true).connect(domain, stream).await?;
    
    // Write early data directly! tokio-rustls handles this transparently.
    tls_stream.write_all(EARLY_REQUEST.as_bytes()).await?;
    
    // Read response
    read_response(&mut tls_stream).await?;

    let _ = tls_stream.shutdown().await; // Ignore shutdown errors
    Ok(())
}
