use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPacket {
    pub stream_id: u64,
    pub packet_type: String,
    pub packet_number: u64,
}

impl RequestPacket {
    pub fn is_0rtt(&self) -> bool {
        self.packet_type == "0RTT"
    }
}

fn events(qlog: &Path) -> Result<Vec<Value>> {
    let text = std::fs::read_to_string(qlog)
        .with_context(|| format!("cannot read qlog {}", qlog.display()))?;
    Ok(text
        .split('\u{1e}')
        .map(str::trim)
        .filter(|record| !record.is_empty())
        .filter_map(|record| serde_json::from_str(record).ok())
        .collect())
}

fn sent_packets(events: &[Value]) -> impl Iterator<Item = &Value> {
    events.iter().filter(|e| e["name"] == "quic:packet_sent")
}

pub fn request_packet(qlog: &Path) -> Result<RequestPacket> {
    let events = events(qlog)?;

    let stream_id = events
        .iter()
        .filter(|e| e["name"] == "http3:frame_created")
        .find(|e| e["data"]["frame"]["frame_type"] == "headers")
        .and_then(|e| e["data"]["stream_id"].as_u64())
        .context("no request headers in qlog")?;

    for packet in sent_packets(&events) {
        let carries_start = packet["data"]["frames"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|f| {
                f["frame_type"] == "stream"
                    && f["stream_id"].as_u64() == Some(stream_id)
                    && f["offset"].as_u64() == Some(0)
            });
        if carries_start {
            let header = &packet["data"]["header"];
            return Ok(RequestPacket {
                stream_id,
                packet_type: header["packet_type"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                packet_number: header["packet_number"]
                    .as_u64()
                    .context("no packet number")?,
            });
        }
    }
    bail!("no sent packet carried offset 0 of stream {stream_id}")
}

pub fn count_sent(qlog: &Path, packet_type: &str) -> Result<usize> {
    let events = events(qlog)?;
    Ok(sent_packets(&events)
        .filter(|p| p["data"]["header"]["packet_type"] == packet_type)
        .count())
}

pub fn sent_close_code(qlog: &Path) -> Result<Option<u64>> {
    close_code(qlog, "quic:packet_sent")
}

pub fn received_close_code(qlog: &Path) -> Result<Option<u64>> {
    close_code(qlog, "quic:packet_received")
}

fn close_code(qlog: &Path, event_name: &str) -> Result<Option<u64>> {
    let events = events(qlog)?;
    Ok(events
        .iter()
        .filter(|e| e["name"] == event_name)
        .flat_map(|p| p["data"]["frames"].as_array().into_iter().flatten())
        .find(|f| f["frame_type"] == "connection_close")
        .and_then(|f| f["error_code"].as_u64()))
}
