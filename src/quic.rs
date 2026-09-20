use crate::outcome::Outcome;
use crate::verify::{self, RequestPacket};
use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tokio_quiche::http3::driver::{ClientH3Event, H3Event, InboundFrame, NewClientRequest};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::{DefaultMetrics, Metrics};
use tokio_quiche::quic::raw::wrap_quiche_conn;
use tokio_quiche::quic::{
    ConnectionShutdownBehaviour, HandshakeInfo, Incoming, QuicCommand, QuicheConnection,
    SimpleConnectionIdGenerator,
};
use tokio_quiche::quiche;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::socket::Socket;
use tokio_quiche::{
    ApplicationOverQuic, ClientH3Controller, ClientH3Driver, ConnectionIdGenerator, QuicConnection,
    QuicResult,
};

const H3_NO_ERROR: u64 = 0x100;

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub addr: SocketAddr,
    pub path: String,
    pub ca_file: PathBuf,
    pub qlog_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub request: Duration,
    pub ticket: Duration,
    pub close: Duration,
    pub total: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            ticket: Duration::from_secs(2),
            close: Duration::from_secs(2),
            total: Duration::from_secs(15),
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: String,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Report {
    pub response: Result<Response, String>,
    pub ticket: Option<Vec<u8>>,
    pub offered_ticket: bool,
    pub early_data: bool,
    pub established: bool,
    pub resumed: bool,
    pub early_reason: u32,
    pub packet: Option<RequestPacket>,
    pub outcome: Outcome,
    pub qlog: PathBuf,
}

pub async fn fetch(
    target: &Target,
    session: Option<&[u8]>,
    early_data: bool,
    limits: &Limits,
) -> Result<Report> {
    timeout(limits.total, run(target, session, early_data, limits))
        .await
        .context("quic run timed out")?
}

async fn run(
    target: &Target,
    session: Option<&[u8]>,
    early_data: bool,
    limits: &Limits,
) -> Result<Report> {
    let mut conn = connect(target, session, early_data).await?;

    let response = match timeout(limits.request, request(&mut conn.controller)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("request timed out".to_string()),
    };

    let ticket_limit = if response.is_ok() {
        limits.ticket
    } else {
        Duration::ZERO
    };
    let state = wait_for_ticket(&conn.controller, ticket_limit).await;
    let offered_ticket = conn.offered_ticket;
    let qlog = conn.qlog.clone();
    conn.close(limits.close).await;
    let state = match state {
        Ok(state) => state,
        Err(e) => {
            let request = response.as_ref().err().map_or("request ok", String::as_str);
            bail!(
                "connection failed ({request} then {e}) {}",
                close_summary(&qlog)
            )
        }
    };

    let packet = verify::request_packet(&qlog).ok();
    let request_in_0rtt = packet.as_ref().is_some_and(RequestPacket::is_0rtt);
    let outcome = Outcome::classify(
        offered_ticket,
        early_data,
        state.resumed,
        state.early_reason,
        request_in_0rtt,
    );

    Ok(Report {
        response,
        ticket: state.session,
        offered_ticket,
        early_data,
        established: state.established,
        resumed: state.resumed,
        early_reason: state.early_reason,
        packet,
        outcome,
        qlog,
    })
}

fn close_summary(qlog: &Path) -> String {
    let local = verify::sent_close_code(qlog).ok().flatten();
    let peer = verify::received_close_code(qlog).ok().flatten();
    format!(
        "local_close={} peer_close={} qlog={}",
        describe_close(local),
        describe_close(peer),
        qlog.display()
    )
}

fn describe_close(code: Option<u64>) -> String {
    match code {
        Some(code) if (0x100..0x200).contains(&code) => {
            format!("{code:#x} tls_alert_{}", code - 0x100)
        }
        Some(code) => format!("{code:#x}"),
        None => "none".to_string(),
    }
}

struct SendQueuedOnStart(ClientH3Driver);

impl ApplicationOverQuic for SendQueuedOnStart {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.0.on_conn_established(qconn, handshake_info)?;
        let mut queued = pin!(self.0.wait_for_data(qconn));
        if let Poll::Ready(result) = queued
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
        {
            result?;
        }
        Ok(())
    }

    fn should_act(&self) -> bool {
        self.0.should_act()
    }

    fn wait_for_data(
        &mut self,
        qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        self.0.wait_for_data(qconn)
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.0.process_reads(qconn)
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.0.process_writes(qconn)
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        qconn: &mut QuicheConnection,
        metrics: &M,
        work_loop_result: &QuicResult<()>,
    ) {
        self.0.on_conn_close(qconn, metrics, work_loop_result)
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Conn {
    controller: ClientH3Controller,
    shutdown_rx: mpsc::Receiver<()>,
    qlog: PathBuf,
    offered_ticket: bool,
    _connection: QuicConnection,
    _recv_task: AbortOnDrop,
}

impl Conn {
    async fn close(mut self, limit: Duration) {
        let _ = self
            .controller
            .cmd_sender()
            .send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
                send_application_close: true,
                error_code: H3_NO_ERROR,
                reason: Vec::new(),
            }));
        let _ = timeout(limit, self.shutdown_rx.recv()).await;
    }
}

async fn connect(target: &Target, session: Option<&[u8]>, early_data: bool) -> Result<Conn> {
    let (driver, controller) = ClientH3Driver::new(Http3Settings::default());
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 1,
            headers: vec![
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", target.host.as_bytes()),
                Header::new(b":path", target.path.as_bytes()),
                Header::new(b"user-agent", b"rust-toy-0rtt"),
            ],
            body_writer: None,
        })
        .map_err(|_| anyhow!("driver request channel closed"))?;

    let bind_addr: SocketAddr = if target.addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(target.addr).await?;
    let socket = Socket::try_from(socket)?;
    let recv_socket = socket.recv.clone();
    let local = socket.local_addr;
    let peer = socket.peer_addr;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(true);
    config
        .load_verify_locations_from_file(target.ca_file.to_str().context("ca path is not utf8")?)?;
    config.set_application_protos(&[b"h3"])?;
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_max_idle_timeout(5_000);
    if early_data {
        config.enable_early_data();
    }

    let scid = SimpleConnectionIdGenerator.new_connection_id();
    let mut qconn =
        quiche::connect_with_buffer_factory(Some(&target.host), &scid, local, peer, &mut config)?;
    let offered_ticket = match session {
        Some(ticket) => qconn.set_session(ticket).is_ok(),
        None => false,
    };

    std::fs::create_dir_all(&target.qlog_dir)?;
    let qlog = target.qlog_dir.join(format!("{scid:?}.sqlog"));
    qconn.set_qlog(
        Box::new(File::create(&qlog)?),
        "rust-toy-0rtt".into(),
        format!("early_data={early_data} offered_ticket={offered_ticket}"),
    );

    let wrapped = wrap_quiche_conn(qconn, socket, DefaultMetrics);
    let incoming_tx = wrapped.incoming_tx;
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, from)) = recv_socket.recv_from(&mut buf).await {
            let packet = Incoming {
                peer_addr: from,
                local_addr: local,
                rx_time: None,
                buf: buf[..len].to_vec(),
                gro: None,
                #[cfg(target_os = "linux")]
                so_mark_data: None,
            };
            if incoming_tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    let connection = wrapped.conn.start(SendQueuedOnStart(driver));

    Ok(Conn {
        controller,
        shutdown_rx: wrapped.worker_shutdown_rx,
        qlog,
        offered_ticket,
        _connection: connection,
        _recv_task: AbortOnDrop(recv_task),
    })
}

async fn request(controller: &mut ClientH3Controller) -> Result<Response> {
    let events = controller.event_receiver_mut();
    while let Some(event) = events.recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(mut headers)) => {
                let status = headers
                    .headers
                    .iter()
                    .find(|h| h.name() == b":status")
                    .map(|h| String::from_utf8_lossy(h.value()).into_owned())
                    .unwrap_or_default();
                let mut body = Vec::new();
                if !headers.read_fin {
                    while let Some(frame) = headers.recv.recv().await {
                        if let InboundFrame::Body(bytes, fin) = frame {
                            body.extend_from_slice(&bytes);
                            if fin {
                                break;
                            }
                        }
                    }
                }
                return Ok(Response { status, body });
            }
            ClientH3Event::Core(H3Event::ConnectionError(e)) => bail!("h3 connection error {e:?}"),
            ClientH3Event::Core(H3Event::ConnectionShutdown(e)) => {
                bail!("connection shut down {e:?}")
            }
            ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                bail!("stream {stream_id} reset")
            }
            _ => {}
        }
    }
    bail!("driver event channel closed")
}

struct State {
    session: Option<Vec<u8>>,
    established: bool,
    resumed: bool,
    early_reason: u32,
}

async fn snapshot(controller: &ClientH3Controller) -> Result<State> {
    let (tx, rx) = oneshot::channel();
    controller
        .cmd_sender()
        .send(QuicCommand::Custom(Box::new(move |q| {
            let _ = tx.send(State {
                session: q.session().map(<[u8]>::to_vec),
                established: q.is_established(),
                resumed: q.is_resumed(),
                early_reason: q.early_data_reason(),
            });
        })))
        .map_err(|_| anyhow!("driver command channel closed"))?;
    timeout(Duration::from_secs(1), rx)
        .await
        .context("connection did not answer")?
        .context("connection closed before it answered")
}

async fn wait_for_ticket(controller: &ClientH3Controller, limit: Duration) -> Result<State> {
    let deadline = Instant::now() + limit;
    loop {
        let state = snapshot(controller).await?;
        if state.session.is_some() || Instant::now() >= deadline {
            return Ok(state);
        }
        sleep(Duration::from_millis(10)).await;
    }
}
