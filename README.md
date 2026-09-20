# rust-toy-0rtt

An HTTP/3 client in Rust that resumes a QUIC session and sends its first request as 0-RTT early data. The client uses quiche and tokio-quiche and the tests read the qlog of each connection.

This crate also has a small TCP mode. It does the same test with TLS 1.3 early data over tokio-rustls. With early data, a server can reply and close before the client Finished arrives. The server then resets the connection and some of the response is lost. So the client reads the Content-Length or chunked framing to find the end of the response, and then it closes the connection.

## Role of each library

quiche does QUIC and TLS 1.3 with BoringSSL. tokio-quiche runs the quiche connection on tokio and gives the HTTP/3 driver. rustls and tokio-rustls do the TCP mode. This project specifically does the following:

- It makes the quiche client connection directly, with the session ticket and early data on. Then it wraps the connection with the raw API of tokio-quiche (`quic::raw::wrap_quiche_conn`) and keeps the stock HTTP/3 driver.
- It puts the GET into the driver queue before the connection starts. A small wrapper around the driver (`SendQueuedOnStart`) writes the queued GET when the 0-RTT keys become available (because the driver reads its queue only in a later pass of the worker loop, and on fast links, the handshake was completing first and the GET left in 1-RTT).
- It reads the UDP socket and gives each packet to the wrapped connection.
- It gets the new session ticket from the connection after the response.
- It reads the qlog and finds the packet that carried the start of the request stream. Then it gives a result for the connection.

The tokio-quiche docs for `QuicSettings.enable_early_data` say:

> Configures whether to enable early data (0-RTT) support. Currently only supported for servers.

The docs for `connect_with_config` say:

> When the future resolves, the connection has completed its handshake

Thus the application gets the connection only after the handshake. A resumed connection can report that the server accepted early data, but the request still leaves in a 1-RTT packet.

## Requirements

- Rust stable
- cmake, because tokio-quiche builds BoringSSL (`brew install cmake` on macOS)
- openssl, for the test certificates

## Run it

```sh
cargo run            # quic mode
cargo run -- tcp     # tcp mode
```

Each mode connects to one host two times. The first connection does a full handshake and gets a ticket. The second connection uses the ticket and sends the GET as early data. QUIC mode writes a qlog for each connection to `qlogs/`. TCP mode writes TLS keys to `keylog.txt` for Wireshark.

The host, path, CA file and time limits are constants at the top of `src/main.rs`. The CA file is `/etc/ssl/cert.pem`, which is for macOS. On Linux, change it to `/etc/ssl/certs/ca-certificates.crt`.

## Sample output

QUIC mode against cloudflare-quic.com.

```text
quic full status=200 body_bytes=125959
quic full outcome=NoTicket resumed=false early_reason=5 ticket_bytes=2965
quic full request stream=0 left in packet_type=1RTT packet_number=7
quic full qlog=qlogs/03a9103267a40b05f923cf8cc1f67938d3b27cc6.sqlog
quic resumed status=200 body_bytes=125959
quic resumed outcome=EarlyAccepted { request_in_0rtt: true } resumed=true early_reason=2 ticket_bytes=2965
quic resumed request stream=0 left in packet_type=0RTT packet_number=5
quic resumed qlog=qlogs/9f5f6df4dce4517865056652b16f033466160f9c.sqlog
```

TCP mode against the same host.

```text
tcp full handshake=Some(Full) early_data_accepted=false response_bytes=126188 reset_after_response=false status_line="HTTP/1.1 200 OK"
tcp resumed handshake=Some(Resumed) early_data_accepted=true response_bytes=126188 reset_after_response=false status_line="HTTP/1.1 200 OK"
```

## Packet timeline of the resumed connection

This is from the resumed qlog above, with some ack lines removed. The GET is on stream 0. It leaves in a 0RTT packet at 4.64 ms. The first handshake packet from the server arrives at 10.94 ms.

```text
    0.53 ms send initial   pn=0   crypto
    2.70 ms send initial   pn=1   crypto
    2.70 ms send 0RTT      pn=2   stream s2@0     (h3 control stream)
    2.70 ms send 0RTT      pn=3   stream s6@0     (qpack encoder)
    2.70 ms send 0RTT      pn=4   stream s10@0    (qpack decoder)
    4.64 ms send 0RTT      pn=5   stream s0@0     (GET request)
    6.10 ms recv initial   pn=0   ack
    9.94 ms recv initial   pn=2   crypto
   10.94 ms recv handshake pn=4   crypto
   11.31 ms recv 1RTT      pn=5   ack,crypto,padding
   11.88 ms send handshake pn=7   ack,crypto
```

## Results

Each QUIC connection gives one `Outcome`.

| Outcome | Meaning |
| --- | --- |
| `NoTicket` | The client did not offer a usable ticket and did a full handshake. |
| `ResumedNoEarly` | The session resumed, but the client did not send early data. |
| `EarlyRejected` | The client offered early data and the server did not accept it. The client reports this and does not try again. |
| `EarlyAccepted { request_in_0rtt }` | The server accepted early data. The qlog gives `request_in_0rtt`. A `false` value is a failure. |

## Tests

```sh
cargo test
```

The tests start a tokio-quiche server in the same process, with early data on. `certs/gen.sh` makes a test CA and a `localhost` certificate the first time the tests run. The file `tests/scenarios.rs` has these scenarios.

| Scenario | Expected result |
| --- | --- |
| Full handshake | Not resumed. The request leaves in 1RTT. The server sends a ticket. |
| Resumed with early data | `EarlyAccepted`. The request leaves in 0RTT. The server sees the request as early data and sends 200. |
| Resumed without early data | `ResumedNoEarly`. The request leaves in 1RTT. The client sends no 0RTT packets. |
| Ticket that is not valid | Full handshake. The client sends no 0RTT packets. |
| Ticket from a different server | `EarlyRejected`. The session does not resume. |
| CA that is not correct | The client refuses the server certificate and closes with the unknown_ca alert. |

## Layout

| File | Contents |
| --- | --- |
| `src/main.rs` | Runs QUIC mode or TCP mode against the hardcoded host. |
| `src/quic.rs` | The QUIC client with the raw wrapper, ticket in and out, time limits and close. |
| `src/verify.rs` | Reads a qlog and finds the packet that carried the request. |
| `src/outcome.rs` | Outcome of a connection. |
| `src/tcp.rs` | The TCP client with tokio-rustls. |
| `src/tls.rs` | The rustls config and the key log file. |
| `tests/scenarios.rs` | The in-process server and the test scenarios. |
| `certs/gen.sh` | Makes the test CA and the `localhost` certificate. |

## Limits

- The client does not recover from rejected early data. It reports the rejection.
- The client sends only GET requests as early data, because a replay of a GET is safe.
