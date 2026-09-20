use anyhow::{Context, Result, bail};
use rust_toy_0rtt::{quic, tcp, tls};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// todo remove hardcode
const HOST: &str = "cloudflare-quic.com";
// todo remove hardcode
const PATH: &str = "/";
// todo remove hardcode
const CA_FILE: &str = "/etc/ssl/cert.pem";
// todo remove hardcode
const QLOG_DIR: &str = "qlogs";
// todo remove hardcode
const KEYLOG_FILE: &str = "keylog.txt";
// todo remove hardcode
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("tcp") => run_tcp().await,
        _ => run_quic().await,
    }
}

async fn run_quic() -> Result<()> {
    let addr = tokio::net::lookup_host((HOST, 443))
        .await?
        .find(|a| a.is_ipv4())
        .context("no ipv4 address for host")?;
    let target = quic::Target {
        host: HOST.to_string(),
        addr,
        path: PATH.to_string(),
        ca_file: PathBuf::from(CA_FILE),
        qlog_dir: PathBuf::from(QLOG_DIR),
    };
    let limits = quic::Limits {
        request: TIMEOUT,
        ..Default::default()
    };

    let full = quic::fetch(&target, None, true, &limits).await?;
    print_quic("full", &full);
    let ticket = full.ticket.context("server sent no session ticket")?;

    let resumed = quic::fetch(&target, Some(&ticket), true, &limits).await?;
    print_quic("resumed", &resumed);

    if resumed.outcome.is_failure() {
        bail!("early data accepted but the request did not leave in a 0rtt packet");
    }
    Ok(())
}

fn print_quic(label: &str, report: &quic::Report) {
    match &report.response {
        Ok(r) => println!(
            "quic {label} status={} body_bytes={}",
            r.status,
            r.body.len()
        ),
        Err(e) => println!("quic {label} request failed {e}"),
    }
    println!(
        "quic {label} outcome={:?} resumed={} early_reason={} ticket_bytes={}",
        report.outcome,
        report.resumed,
        report.early_reason,
        report.ticket.as_ref().map_or(0, Vec::len),
    );
    match &report.packet {
        Some(p) => println!(
            "quic {label} request stream={} left in packet_type={} packet_number={}",
            p.stream_id, p.packet_type, p.packet_number
        ),
        None => println!("quic {label} request packet not found in qlog"),
    }
    println!("quic {label} qlog={}", report.qlog.display());
}

async fn run_tcp() -> Result<()> {
    let key_log = Arc::new(tls::FileKeyLog::create(KEYLOG_FILE)?);
    let config = tls::client_config(None, Some(key_log))?;

    for (label, early_data) in [("full", false), ("resumed", true)] {
        let report = tcp::fetch(config.clone(), HOST, 443, PATH, early_data, TIMEOUT).await?;
        let first_line = String::from_utf8_lossy(&report.response)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!(
            "tcp {label} handshake={:?} early_data_accepted={} response_bytes={} reset_after_response={} status_line={first_line:?}",
            report.handshake_kind,
            report.early_data_accepted,
            report.response.len(),
            report.reset_after_response,
        );
    }
    Ok(())
}
