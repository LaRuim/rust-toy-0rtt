use anyhow::{Context, Result};
use rustls::{ClientConfig, HandshakeKind};
use rustls_pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
pub struct Report {
    pub handshake_kind: Option<HandshakeKind>,
    pub early_data_accepted: bool,
    pub response: Vec<u8>,
    pub reset_after_response: bool,
}

pub async fn fetch(
    config: Arc<ClientConfig>,
    host: &str,
    port: u16,
    path: &str,
    early_data: bool,
    limit: Duration,
) -> Result<Report> {
    let stream = timeout(limit, TcpStream::connect((host, port)))
        .await
        .context("tcp connect timed out")??;
    let name = ServerName::try_from(host.to_string())?;
    let connector = TlsConnector::from(config).early_data(early_data);
    let mut tls = timeout(limit, connector.connect(name, stream))
        .await
        .context("tls connect timed out")??;

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    timeout(limit, tls.write_all(request.as_bytes()))
        .await
        .context("write timed out")??;
    timeout(limit, tls.flush())
        .await
        .context("flush timed out")??;

    let (_, conn) = tls.get_ref();
    let handshake_kind = conn.handshake_kind();
    let early_data_accepted = conn.is_early_data_accepted();

    let (response, reset_after_response) = timeout(limit, read_to_end(&mut tls))
        .await
        .context("read timed out")?
        .context("read failed")?;
    let _ = timeout(limit, tls.shutdown()).await;

    Ok(Report {
        handshake_kind,
        early_data_accepted,
        response,
        reset_after_response,
    })
}

async fn read_to_end<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut buf = vec![0; 8192];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok((out, false)),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if is_complete(&out) {
                    return Ok((out, false));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok((out, false)),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && !out.is_empty() => {
                return Ok((out, true));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn is_complete(response: &[u8]) -> bool {
    let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&response[..head_end]).to_ascii_lowercase();
    let body = &response[head_end + 4..];
    for line in head.lines() {
        if let Some(length) = line.strip_prefix("content-length:") {
            return length
                .trim()
                .parse::<usize>()
                .is_ok_and(|n| body.len() >= n);
        }
        if line.starts_with("transfer-encoding:") && line.contains("chunked") {
            return body == b"0\r\n\r\n" || body.ends_with(b"\r\n0\r\n\r\n");
        }
    }
    false
}
