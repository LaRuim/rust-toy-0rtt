use futures::{SinkExt, StreamExt};
use rust_toy_0rtt::outcome::Outcome;
use rust_toy_0rtt::quic::{self, Limits, Report, Target};
use rust_toy_0rtt::verify;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::task::JoinHandle;
use tokio_quiche::http3::driver::{OutboundFrame, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{ConnectionParams, ServerH3Driver};

const TLS_ALERT_UNKNOWN_CA: u64 = 0x100 + 48;

fn certs_dir() -> PathBuf {
    static CERTS: OnceLock<PathBuf> = OnceLock::new();
    CERTS
        .get_or_init(|| {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs");
            if !dir.join("leaf.crt").exists() {
                let status = Command::new("sh").arg(dir.join("gen.sh")).status().unwrap();
                assert!(status.success(), "certs/gen.sh failed");
            }
            dir
        })
        .clone()
}

struct Server {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<bool>>>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    fn start() -> Server {
        let certs = certs_dir();
        let cert = certs.join("leaf.crt").to_str().unwrap().to_string();
        let key = certs.join("leaf.key").to_str().unwrap().to_string();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();

        let mut settings = QuicSettings::default();
        settings.enable_early_data = true;
        settings.disable_client_ip_validation = true;
        let params = ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: &cert,
                private_key: &key,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );
        let mut listener = tokio_quiche::listen([socket], params, DefaultMetrics)
            .unwrap()
            .remove(0);

        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            while let Some(Ok(connection)) = listener.next().await {
                let (driver, mut controller) = ServerH3Driver::new(Http3Settings::default());
                let _connection = connection.start(driver);
                let seen = seen.clone();
                tokio::spawn(async move {
                    while let Some(event) = controller.event_receiver_mut().recv().await {
                        if let ServerH3Event::Headers {
                            incoming_headers,
                            is_in_early_data,
                            ..
                        } = event
                        {
                            seen.lock().unwrap().push(*is_in_early_data);
                            let mut send = incoming_headers.send;
                            let _ = send
                                .send(OutboundFrame::Headers(
                                    vec![Header::new(b":status", b"200")],
                                    None,
                                ))
                                .await;
                            let _ = send
                                .send(OutboundFrame::Body(Default::default(), true))
                                .await;
                        }
                    }
                });
            }
        });

        Server {
            addr,
            requests,
            task,
        }
    }

    fn early_flags(&self) -> Vec<bool> {
        self.requests.lock().unwrap().clone()
    }

    fn target(&self, scenario: &str) -> Target {
        let qlog_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("qlogs")
            .join(scenario);
        let _ = std::fs::remove_dir_all(&qlog_dir);
        Target {
            host: "localhost".to_string(),
            addr: self.addr,
            path: "/".to_string(),
            ca_file: certs_dir().join("ca.crt"),
            qlog_dir,
        }
    }
}

fn status(report: &Report) -> &str {
    &report.response.as_ref().expect("request failed").status
}

fn packet_type(report: &Report) -> &str {
    &report
        .packet
        .as_ref()
        .expect("request packet not in qlog")
        .packet_type
}

async fn ticket_from(target: &Target) -> Vec<u8> {
    let full = quic::fetch(target, None, true, &Limits::default())
        .await
        .unwrap();
    full.ticket.expect("no ticket from full handshake")
}

#[tokio::test]
async fn full_handshake_sends_request_in_1rtt() {
    let server = Server::start();
    let target = server.target("full_handshake");

    let report = quic::fetch(&target, None, true, &Limits::default())
        .await
        .unwrap();

    assert_eq!(status(&report), "200");
    assert_eq!(report.outcome, Outcome::NoTicket);
    assert!(!report.resumed);
    assert_eq!(packet_type(&report), "1RTT");
    assert!(report.ticket.is_some());
    assert_eq!(server.early_flags(), vec![false]);
}

#[tokio::test]
async fn resumed_with_early_data_sends_request_in_0rtt() {
    let server = Server::start();
    let target = server.target("resumed_early");

    let ticket = ticket_from(&target).await;
    let report = quic::fetch(&target, Some(&ticket), true, &Limits::default())
        .await
        .unwrap();

    assert_eq!(status(&report), "200");
    assert!(report.resumed);
    assert_eq!(
        report.outcome,
        Outcome::EarlyAccepted {
            request_in_0rtt: true
        }
    );
    assert_eq!(packet_type(&report), "0RTT");
    assert_eq!(server.early_flags(), vec![false, true]);
}

#[tokio::test]
async fn resumed_without_early_data_sends_request_in_1rtt() {
    let server = Server::start();
    let target = server.target("resumed_no_early");

    let ticket = ticket_from(&target).await;
    let report = quic::fetch(&target, Some(&ticket), false, &Limits::default())
        .await
        .unwrap();

    assert_eq!(status(&report), "200");
    assert!(report.resumed);
    assert_eq!(report.outcome, Outcome::ResumedNoEarly);
    assert_eq!(packet_type(&report), "1RTT");
    assert_eq!(verify::count_sent(&report.qlog, "0RTT").unwrap(), 0);
    assert_eq!(server.early_flags(), vec![false, false]);
}

#[tokio::test]
async fn invalid_ticket_falls_back_to_full_handshake() {
    let server = Server::start();
    let target = server.target("invalid_ticket");

    let report = quic::fetch(&target, Some(b"not a ticket"), true, &Limits::default())
        .await
        .unwrap();

    assert_eq!(status(&report), "200");
    assert!(!report.offered_ticket);
    assert!(!report.resumed);
    assert_eq!(report.outcome, Outcome::NoTicket);
    assert_eq!(packet_type(&report), "1RTT");
    assert_eq!(verify::count_sent(&report.qlog, "0RTT").unwrap(), 0);
    assert_eq!(server.early_flags(), vec![false]);
}

#[tokio::test]
async fn ticket_from_another_server_is_rejected() {
    let first = Server::start();
    let second = Server::start();

    let ticket = ticket_from(&first.target("other_server_a")).await;
    let report = quic::fetch(
        &second.target("other_server_b"),
        Some(&ticket),
        true,
        &Limits::default(),
    )
    .await
    .unwrap();

    assert!(!report.resumed);
    assert_eq!(report.outcome, Outcome::EarlyRejected);
}

#[tokio::test]
async fn wrong_ca_is_refused() {
    let server = Server::start();
    let mut target = server.target("wrong_ca");
    target.ca_file = certs_dir().join("leaf.crt");

    quic::fetch(&target, None, true, &Limits::default())
        .await
        .unwrap_err();

    let qlog = std::fs::read_dir(&target.qlog_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        verify::sent_close_code(&qlog).unwrap(),
        Some(TLS_ALERT_UNKNOWN_CA)
    );
    assert!(server.early_flags().is_empty());
}
