# rust-toy-0rtt

A simple project exploring how to perform a TLS 1.3 full handshake and a subsequent resumed handshake with early data (0-RTT) using the `openssl` crate in Rust.

## What it does

- **Full Handshake**: Hooks up to a target server, does a standard TLS 1.3 handshake, and grabs the session info.
- **Resumed Handshake (0-RTT)**: Reconnects using that saved session and fires off early data before the handshake even finishes to save a round trip.

## Code Layout

- `src/main.rs`: Where it all starts and coordinates the handshakes.
- `src/config.rs`: Just some hardcoded constants (Host, IP, HTTP requests).
- `src/tls.rs`: TLS config junk, like setting up the `SslConnector` and logging keys.
- `src/client.rs`: The actual network and client stuff, wrapping up the handshake and reading data.

## Stuff you need

- Rust (I'm using stable)
- OpenSSL installed on the system
- A `ca.pem` file in the root for cert verification (or just hack `src/tls.rs` to use default CA certs).

## Running it

```bash
cargo run
```

This will log TLS session keys to `keylog.txt` (useful for Wireshark inspection) and print the HTTP response to the console.

## Things I might add later

Some ideas to make this less of a hack if I ever come back to it:
- **CLI Arguments**: Pull in `clap` so I don't have to hardcode `HOST`, `IP`, and the CA path.
- **Better Certs**: Use `openssl-probe` to just find system certs instead of expecting `./ca.pem`.
- **Actual HTTP Requests**: Construct proper HTTP requests instead of relying on raw string constants.
