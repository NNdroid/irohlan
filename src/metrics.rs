//! Prometheus text exposition for relay accounting, link quality and routes.
//!
//! Two independent consumers share the same renderer: a `metrics.prom` file
//! in the state directory (for node_exporter's textfile collector or ad-hoc
//! inspection) and an optional loopback-only HTTP endpoint at `/metrics`.
//! Both are read-only views of in-memory counters — they never affect
//! forwarding, quotas or routing.
//!
//! The endpoint is deliberately restricted to a loopback bind address:
//! these counters expose the mesh topology and per-peer traffic volumes.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::mesh::MeshSnapshot;
use crate::proto::{IdBytes, LinkMetric};
use crate::relay::{PeerStats, RelaySnapshot};

/// Everything one scrape needs. Borrowed so rendering allocates only the
/// output string and never clones the per-peer ledger.
pub struct MetricsInput<'a> {
    pub relay: &'a RelaySnapshot,
    /// Smoothed quality of our direct mesh links.
    pub links: &'a [LinkMetric],
    /// `(destination, first hop, weighted cost)`.
    pub routes: &'a [(IdBytes, IdBytes, u64)],
    /// How payloads actually travelled (QUIC datagram vs uni-stream).
    pub mesh: MeshSnapshot,
    pub frames_from_tap: u64,
    pub frames_to_tap: u64,
    pub frames_dropped: u64,
    pub started_at_unix: u64,
    pub updated_at_unix: u64,
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn sample(out: &mut String, name: &str, value: impl std::fmt::Display, labels: &[(&str, &str)]) {
    let _ = write!(out, "{name}");
    if !labels.is_empty() {
        out.push('{');
        for (i, (key, value)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{key}=\"{}\"", escape_label(value));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Short, stable label value. Full hex ids are too noisy on dashboards, but
/// a prefix is still unique enough for a small overlay.
fn peer_label(id: &IdBytes) -> String {
    let hex = id.hex();
    hex[..12.min(hex.len())].to_string()
}

/// Render one scrape in Prometheus text format (version 0.0.4).
pub fn render(input: &MetricsInput<'_>) -> String {
    let r = input.relay;
    let mut out = String::new();

    header(
        &mut out,
        "irohlan_up",
        "gauge",
        "Whether the irohlan node loop is running.",
    );
    sample(&mut out, "irohlan_up", 1, &[]);
    header(
        &mut out,
        "irohlan_started_at_unix",
        "gauge",
        "Unix timestamp of node startup.",
    );
    sample(
        &mut out,
        "irohlan_started_at_unix",
        input.started_at_unix,
        &[],
    );
    header(
        &mut out,
        "irohlan_last_status_unix",
        "gauge",
        "Unix timestamp of the last status snapshot.",
    );
    sample(
        &mut out,
        "irohlan_last_status_unix",
        input.updated_at_unix,
        &[],
    );
    header(
        &mut out,
        "irohlan_tap_frames_total",
        "counter",
        "Ethernet frames read from or written to the TAP device.",
    );
    sample(
        &mut out,
        "irohlan_tap_frames_total",
        input.frames_from_tap,
        &[("direction", "from_tap")],
    );
    sample(
        &mut out,
        "irohlan_tap_frames_total",
        input.frames_to_tap,
        &[("direction", "to_tap")],
    );
    header(
        &mut out,
        "irohlan_frames_dropped_total",
        "counter",
        "Frames dropped by the switch (unknown MAC, no route, full relay queue).",
    );
    sample(
        &mut out,
        "irohlan_frames_dropped_total",
        input.frames_dropped,
        &[],
    );

    // Wire-path split. A high `path="stream"` share means full-size frames no
    // longer fit a QUIC datagram, so each one costs a stream slot that the
    // peer only returns after a round trip — the usual cause of throughput far
    // below the link capacity.
    header(
        &mut out,
        "irohlan_mesh_frames_total",
        "counter",
        "Payloads sent or received, split by QUIC path (datagram vs per-frame uni-stream).",
    );
    for (direction, tx) in [("tx", true), ("rx", false)] {
        let (datagram, stream) = if tx {
            (input.mesh.tx_datagram_frames, input.mesh.tx_stream_frames)
        } else {
            (input.mesh.rx_datagram_frames, input.mesh.rx_stream_frames)
        };
        sample(
            &mut out,
            "irohlan_mesh_frames_total",
            datagram,
            &[("direction", direction), ("path", "datagram")],
        );
        sample(
            &mut out,
            "irohlan_mesh_frames_total",
            stream,
            &[("direction", direction), ("path", "stream")],
        );
    }
    header(
        &mut out,
        "irohlan_mesh_bytes_total",
        "counter",
        "Bytes sent or received, split by QUIC path (datagram vs per-frame uni-stream).",
    );
    for (direction, tx) in [("tx", true), ("rx", false)] {
        let (datagram, stream) = if tx {
            (input.mesh.tx_datagram_bytes, input.mesh.tx_stream_bytes)
        } else {
            (input.mesh.rx_datagram_bytes, input.mesh.rx_stream_bytes)
        };
        sample(
            &mut out,
            "irohlan_mesh_bytes_total",
            datagram,
            &[("direction", direction), ("path", "datagram")],
        );
        sample(
            &mut out,
            "irohlan_mesh_bytes_total",
            stream,
            &[("direction", direction), ("path", "stream")],
        );
    }
    header(
        &mut out,
        "irohlan_mesh_stream_fallbacks_total",
        "counter",
        "Datagram sends that failed (e.g. path-MTU shrink) and were retried as a uni-stream.",
    );
    sample(
        &mut out,
        "irohlan_mesh_stream_fallbacks_total",
        input.mesh.tx_stream_fallbacks,
        &[],
    );

    header(
        &mut out,
        "irohlan_relay_limit_kib_per_sec",
        "gauge",
        "Configured total relay cap in KiB/s; 0 means accounting only.",
    );
    sample(
        &mut out,
        "irohlan_relay_limit_kib_per_sec",
        r.limit_kib_per_sec,
        &[],
    );
    header(
        &mut out,
        "irohlan_relay_active_peers",
        "gauge",
        "Source peers currently sharing the relay cap.",
    );
    sample(&mut out, "irohlan_relay_active_peers", r.active_peers, &[]);
    header(
        &mut out,
        "irohlan_relay_active_flows",
        "gauge",
        "Non-empty flow queues across all peers.",
    );
    sample(&mut out, "irohlan_relay_active_flows", r.active_flows, &[]);
    header(
        &mut out,
        "irohlan_relay_per_peer_kib_per_sec",
        "gauge",
        "Derived per-peer share of the relay cap in KiB/s.",
    );
    sample(
        &mut out,
        "irohlan_relay_per_peer_kib_per_sec",
        r.per_peer_kib_per_sec,
        &[],
    );

    for (name, help, frames, bytes) in [
        (
            "irohlan_relay_relayed",
            "Frames forwarded for other members.",
            r.relayed_frames,
            r.relayed_bytes,
        ),
        (
            "irohlan_relay_limited",
            "Frames dropped by a full queue or queue expiry.",
            r.limited_frames,
            r.limited_bytes,
        ),
        (
            "irohlan_relay_codel",
            "Frames dropped proactively by CoDel.",
            r.codel_frames,
            r.codel_bytes,
        ),
    ] {
        let frames_name = format!("{name}_frames_total");
        let bytes_name = format!("{name}_bytes_total");
        header(&mut out, &frames_name, "counter", help);
        sample(&mut out, &frames_name, frames, &[]);
        header(&mut out, &bytes_name, "counter", help);
        sample(&mut out, &bytes_name, bytes, &[]);
    }
    header(
        &mut out,
        "irohlan_relay_queued_frames",
        "gauge",
        "Frames currently waiting in relay queues.",
    );
    sample(
        &mut out,
        "irohlan_relay_queued_frames",
        r.queued_frames,
        &[],
    );
    header(
        &mut out,
        "irohlan_relay_queued_bytes",
        "gauge",
        "Bytes currently waiting in relay queues.",
    );
    sample(&mut out, "irohlan_relay_queued_bytes", r.queued_bytes, &[]);

    type PeerGet = fn(&PeerStats) -> u64;
    let peer_metrics: [(&str, &str, &str, PeerGet); 10] = [
        (
            "irohlan_relay_peer_in_frames_total",
            "counter",
            "Frames received from this peer for relaying.",
            |p| p.in_frames,
        ),
        (
            "irohlan_relay_peer_in_bytes_total",
            "counter",
            "Bytes received from this peer for relaying.",
            |p| p.in_bytes,
        ),
        (
            "irohlan_relay_peer_out_frames_total",
            "counter",
            "Frames forwarded to this peer.",
            |p| p.out_frames,
        ),
        (
            "irohlan_relay_peer_out_bytes_total",
            "counter",
            "Bytes forwarded to this peer.",
            |p| p.out_bytes,
        ),
        (
            "irohlan_relay_peer_limited_frames_total",
            "counter",
            "Frames from this peer dropped by a full queue or expiry.",
            |p| p.limited_frames,
        ),
        (
            "irohlan_relay_peer_limited_bytes_total",
            "counter",
            "Bytes from this peer dropped by a full queue or expiry.",
            |p| p.limited_bytes,
        ),
        (
            "irohlan_relay_peer_codel_frames_total",
            "counter",
            "Frames from this peer dropped by CoDel.",
            |p| p.codel_frames,
        ),
        (
            "irohlan_relay_peer_codel_bytes_total",
            "counter",
            "Bytes from this peer dropped by CoDel.",
            |p| p.codel_bytes,
        ),
        (
            "irohlan_relay_peer_queued_frames",
            "gauge",
            "Frames from this peer currently queued.",
            |p| p.queued_frames,
        ),
        (
            "irohlan_relay_peer_queued_bytes",
            "gauge",
            "Bytes from this peer currently queued.",
            |p| p.queued_bytes,
        ),
    ];
    for (name, kind, help, get) in peer_metrics {
        header(&mut out, name, kind, help);
        for (id, stats) in &r.peers {
            let peer = peer_label(id);
            sample(&mut out, name, get(stats), &[("peer", &peer)]);
        }
    }

    type LinkGet = fn(&LinkMetric) -> u64;
    let link_metrics: [(&str, &str, LinkGet); 4] = [
        (
            "irohlan_link_rtt_ms",
            "Smoothed QUIC round-trip time in milliseconds.",
            |m| u64::from(m.rtt_ms),
        ),
        (
            "irohlan_link_loss_permille",
            "Windowed packet loss in permille.",
            |m| u64::from(m.loss_permille),
        ),
        (
            "irohlan_link_tx_kbps",
            "Observed QUIC send throughput in kbit/s.",
            |m| u64::from(m.tx_kbps),
        ),
        (
            "irohlan_link_bw_kbps",
            "Estimated sustainable bandwidth in kbit/s; 0 means unknown.",
            |m| u64::from(m.bw_kbps),
        ),
    ];
    for (name, help, get) in link_metrics {
        header(&mut out, name, "gauge", help);
        for m in input.links {
            let peer = peer_label(&m.neighbor);
            sample(&mut out, name, get(m), &[("peer", &peer)]);
        }
    }

    header(
        &mut out,
        "irohlan_route_cost",
        "gauge",
        "Weighted cost of the chosen path (equivalent milliseconds).",
    );
    for (dest, hop, cost) in input.routes {
        let dest_label = peer_label(dest);
        let hop_label = peer_label(hop);
        sample(
            &mut out,
            "irohlan_route_cost",
            *cost,
            &[("dest", &dest_label), ("next_hop", &hop_label)],
        );
    }
    out
}

/// Serve the rendered exposition over a minimal HTTP/1.1 endpoint.
///
/// `addr` must be a loopback address; binding to a routable interface would
/// expose the mesh topology and per-peer traffic volumes to the network.
/// Each connection is handled in its own task with a short read timeout so a
/// slow or idle client cannot hold resources.
pub async fn serve(
    addr: SocketAddr,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "metrics endpoint must bind to a loopback address (got {addr})"
    );
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics endpoint listening on /metrics (loopback only)");
    loop {
        let (mut stream, _) = listener.accept().await?;
        let render = render.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or("");
            let (status, body) = if path == "/metrics" || path.starts_with("/metrics?") {
                ("200 OK", render())
            } else {
                ("404 Not Found", "not found\n".to_string())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(err) = stream.write_all(response.as_bytes()).await {
                tracing::debug!("metrics response failed: {err}");
            }
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        relay: &'a RelaySnapshot,
        links: &'a [LinkMetric],
        routes: &'a [(IdBytes, IdBytes, u64)],
    ) -> MetricsInput<'a> {
        MetricsInput {
            relay,
            links,
            routes,
            mesh: MeshSnapshot {
                tx_datagram_frames: 100,
                tx_datagram_bytes: 9_000,
                tx_stream_frames: 7,
                tx_stream_bytes: 10_500,
                tx_stream_fallbacks: 2,
                rx_datagram_frames: 50,
                rx_datagram_bytes: 4_000,
                rx_stream_frames: 1,
                rx_stream_bytes: 1_500,
            },
            frames_from_tap: 10,
            frames_to_tap: 8,
            frames_dropped: 1,
            started_at_unix: 100,
            updated_at_unix: 200,
        }
    }

    #[test]
    fn render_emits_help_types_and_labelled_samples() {
        let relay = RelaySnapshot {
            limit_kib_per_sec: 64,
            active_peers: 1,
            relayed_frames: 3,
            relayed_bytes: 4500,
            peers: vec![(
                IdBytes([7; 32]),
                PeerStats {
                    in_frames: 3,
                    in_bytes: 4500,
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let links = vec![LinkMetric::unknown(IdBytes([7; 32]), 12)];
        let routes = vec![(IdBytes([8; 32]), IdBytes([7; 32]), 42)];
        let text = render(&input(&relay, &links, &routes));

        assert!(text.contains("# HELP irohlan_up "));
        assert!(text.contains("# TYPE irohlan_up gauge"));
        assert!(text.contains("irohlan_up 1"));
        assert!(text.contains("irohlan_started_at_unix 100"));
        assert!(text.contains("irohlan_relay_relayed_frames_total 3"));
        assert!(text.contains("irohlan_relay_relayed_bytes_total 4500"));
        assert!(text.contains("irohlan_relay_peer_in_frames_total{peer=\"070707070707\"} 3"));
        assert!(text.contains("irohlan_link_rtt_ms{peer=\"070707070707\"} 12"));
        assert!(
            text.contains("irohlan_route_cost{dest=\"080808080808\",next_hop=\"070707070707\"} 42")
        );
        assert!(!text.contains("\r\n"), "text exposition uses LF only");
        // Every HELP/TYPE pair appears exactly once, even with many samples.
        assert_eq!(text.matches("# TYPE irohlan_up gauge").count(), 1);
    }

    #[test]
    fn render_splits_the_wire_path_by_direction_and_path() {
        let relay = RelaySnapshot::default();
        let text = render(&input(&relay, &[], &[]));

        assert!(text.contains("# TYPE irohlan_mesh_frames_total counter"));
        assert!(text.contains("irohlan_mesh_frames_total{direction=\"tx\",path=\"datagram\"} 100"));
        assert!(text.contains("irohlan_mesh_frames_total{direction=\"tx\",path=\"stream\"} 7"));
        assert!(text.contains("irohlan_mesh_frames_total{direction=\"rx\",path=\"datagram\"} 50"));
        assert!(text.contains("irohlan_mesh_frames_total{direction=\"rx\",path=\"stream\"} 1"));
        assert!(text.contains("irohlan_mesh_bytes_total{direction=\"tx\",path=\"stream\"} 10500"));
        assert!(text.contains("irohlan_mesh_bytes_total{direction=\"rx\",path=\"datagram\"} 4000"));
        assert!(text.contains("irohlan_mesh_stream_fallbacks_total 2"));
        // One HELP/TYPE pair per metric, shared by all four labelled samples.
        assert_eq!(
            text.matches("# TYPE irohlan_mesh_frames_total counter")
                .count(),
            1
        );
        assert_eq!(
            text.matches("# TYPE irohlan_mesh_bytes_total counter")
                .count(),
            1
        );
    }

    #[test]
    fn render_handles_empty_ledger_and_topology() {
        let relay = RelaySnapshot::default();
        let text = render(&input(&relay, &[], &[]));
        assert!(text.contains("irohlan_relay_active_peers 0"));
        assert!(text.contains("# TYPE irohlan_route_cost gauge"));
        assert!(!text.contains("{peer="));
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }

    #[test]
    fn non_loopback_bind_is_rejected_before_opening_a_socket() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let render: Arc<dyn Fn() -> String + Send + Sync> = Arc::new(String::new as fn() -> String);
        let err = rt
            .block_on(serve("0.0.0.0:9090".parse().unwrap(), render))
            .unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }
}
