//! Node identity and on-disk state.
//!
//! Layout (one virtual network per host):
//! ```text
//! <state_dir>/irohlan/
//!   identity.key    32-byte ed25519 seed (the iroh endpoint identity)
//!   network.json    current network parameters
//!   secret.txt      network passphrase (0600)
//!   ticket.txt      last generated/used join ticket
//!   leases.json     (creator) granted virtual addresses
//!   status.json     periodically written live status for `irohlan status`
//!   relay-ledger.json cumulative relay counters, restored on restart
//!   metrics.prom    Prometheus text exposition for the textfile collector
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::netaddr::{ula_prefix, AddrPlan, V4Net, VirtualAddrs};
use crate::proto::IdBytes;
use crate::ticket::JoinTicket;

/// All persistent parameters of the joined/created network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub net_id: IdBytes,
    /// IPv4 subnet; `None` when the IPv4 family is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<V4Net>,
    /// IPv6 prefix; `None` when the IPv6 family is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<crate::netaddr::V6Net>,
    /// v1 state files stored the IPv4 subnet as a bare u32/prefix pair. They
    /// are migrated to an IPv4 + derived-ULA dual stack on read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<u8>,
    pub topic_id: IdBytes,
    /// Endpoint id of the creator; `None` when we are the creator.
    pub creator: Option<IdBytes>,
    pub is_creator: bool,
    /// Our pinned virtual addresses, if set via `--ip` / `--ip6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ip6: Option<[u8; 16]>,
    /// Mesh topology chosen at create/join time ("full" | "partial").
    #[serde(default)]
    pub topology: Option<String>,
    /// Target neighbor count for the partial topology.
    #[serde(default)]
    pub mesh_links: Option<u32>,
    /// Relay rate limit in KiB/s; `None` or 0 means accounting only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_limit_kib: Option<u32>,
    /// Optional loopback address for the Prometheus `/metrics` endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_addr: Option<String>,
}

impl NetworkConfig {
    /// Effective address plan, including transparent migration of v1 state.
    pub fn plan(&self) -> AddrPlan {
        if self.v4.is_none() && self.v6.is_none() {
            if let (Some(base), Some(prefix)) = (self.subnet, self.prefix) {
                return AddrPlan::new(
                    Some(V4Net { base, prefix }),
                    Some(ula_prefix(self.net_id.as_bytes())),
                );
            }
        }
        AddrPlan::new(self.v4, self.v6)
    }

    pub fn static_addrs(&self) -> VirtualAddrs {
        VirtualAddrs {
            v4: self.static_ip,
            v6: self.static_ip6,
        }
    }
}

/// Handle on `<state_dir>/irohlan/`.
#[derive(Clone, Debug)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Resolve and create the state directory.
    pub fn open() -> anyhow::Result<Self> {
        let base = base_state_dir();
        let root = base.join("irohlan");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn identity_path(&self) -> PathBuf {
        self.root.join("identity.key")
    }

    pub fn network_path(&self) -> PathBuf {
        self.root.join("network.json")
    }

    pub fn secret_path(&self) -> PathBuf {
        self.root.join("secret.txt")
    }

    pub fn ticket_path(&self) -> PathBuf {
        self.root.join("ticket.txt")
    }

    pub fn leases_path(&self) -> PathBuf {
        self.root.join("leases.json")
    }

    pub fn status_path(&self) -> PathBuf {
        self.root.join("status.json")
    }

    pub fn relay_ledger_path(&self) -> PathBuf {
        self.root.join("relay-ledger.json")
    }

    pub fn metrics_path(&self) -> PathBuf {
        self.root.join("metrics.prom")
    }

    /// Persist cumulative relay counters. Instantaneous queue/active state is
    /// deliberately excluded: it is meaningless after a restart.
    pub fn save_relay_ledger(&self, ledger: &RelayLedger) -> anyhow::Result<()> {
        write_atomic(
            &self.relay_ledger_path(),
            &serde_json::to_vec_pretty(ledger)?,
        )
    }

    /// Restore cumulative counters. A missing or damaged file is not fatal:
    /// accounting simply starts from zero again.
    pub fn load_relay_ledger(&self) -> anyhow::Result<RelayLedger> {
        let path = self.relay_ledger_path();
        if !path.exists() {
            return Ok(RelayLedger::default());
        }
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(err) => {
                tracing::warn!("ignoring unreadable relay ledger {}: {err}", path.display());
                return Ok(RelayLedger::default());
            }
        };
        match serde_json::from_slice::<RelayLedger>(&raw) {
            Ok(ledger) => Ok(ledger),
            Err(err) => {
                tracing::warn!("ignoring corrupt relay ledger {}: {err}", path.display());
                Ok(RelayLedger::default())
            }
        }
    }

    /// Write the Prometheus text file consumed by node_exporter's textfile
    /// collector (or by any ad-hoc scrape of the state directory).
    pub fn write_metrics(&self, text: &str) -> anyhow::Result<()> {
        write_atomic(&self.metrics_path(), text.as_bytes())
    }

    /// Load or create the endpoint identity (32-byte ed25519 seed).
    pub fn load_or_create_identity(&self) -> anyhow::Result<iroh::SecretKey> {
        let path = self.identity_path();
        if path.exists() {
            let bytes: [u8; 32] = std::fs::read(&path)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity.key has wrong length"))?;
            Ok(iroh::SecretKey::from_bytes(&bytes))
        } else {
            let key = iroh::SecretKey::generate();
            write_private(&path, &key.to_bytes())?;
            Ok(key)
        }
    }

    pub fn save_network(&self, net: &NetworkConfig) -> anyhow::Result<()> {
        std::fs::write(self.network_path(), serde_json::to_vec_pretty(net)?)?;
        Ok(())
    }

    pub fn load_network(&self) -> anyhow::Result<NetworkConfig> {
        let raw = std::fs::read(self.network_path())?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub fn has_network(&self) -> bool {
        self.network_path().exists()
    }

    /// Store the passphrase with restrictive permissions.
    pub fn save_secret(&self, secret: &str) -> anyhow::Result<()> {
        write_private(&self.secret_path(), secret.as_bytes())
    }

    pub fn load_secret(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(self.secret_path())?;
        Ok(raw.trim().to_string())
    }

    pub fn save_ticket(&self, ticket: &JoinTicket) -> anyhow::Result<()> {
        std::fs::write(self.ticket_path(), ticket.encode()?)?;
        Ok(())
    }

    pub fn load_ticket(&self) -> anyhow::Result<JoinTicket> {
        let raw = std::fs::read_to_string(self.ticket_path())?;
        JoinTicket::decode(raw.trim())
    }
}

/// `XDG_STATE_HOME` on Linux, local data dir elsewhere.
fn base_state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        dirs::state_dir().unwrap_or_else(|| dirs::data_local_dir().unwrap_or_default())
    }
    #[cfg(not(target_os = "linux"))]
    {
        dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
    }
}

/// Write a file that only the owner may read (unix 0600, best effort).
fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}

/// Write via a temporary file + rename so a reader never observes a partially
/// written ledger or metrics file. Falls back to a direct write on platforms
/// where replacing an existing target is not allowed.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    if std::fs::rename(&tmp, path).is_err() {
        std::fs::write(path, data)?;
    }
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

/// Read the hostname from the kernel (no extra dependency).
pub fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            let h = h.trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Measured quality of one direct mesh link, as reported by `irohlan status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkMetricReport {
    /// Short endpoint id of the neighbor.
    pub peer: String,
    /// EWMA-smoothed QUIC round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Windowed packet loss in permille (0..=1000).
    #[serde(default)]
    pub loss_permille: u32,
    /// EWMA-smoothed observed QUIC send throughput in kbit/s.
    #[serde(default)]
    pub tx_kbps: u32,
    /// Estimated sustainable bandwidth in kbit/s; 0 means unknown.
    #[serde(default)]
    pub bw_kbps: u32,
}

/// One path chosen by the link-quality-weighted routing table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteReport {
    /// Short endpoint id of the destination.
    pub dest: String,
    /// Short endpoint id of the first hop.
    pub next_hop: String,
    /// Weighted path cost (RTT + per-hop + quality penalties, equivalent ms).
    pub cost: u64,
}

/// Relay accounting for one peer, exposed through `irohlan status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPeerReport {
    pub peer: String,
    /// Frames received from this peer that we were asked to relay.
    pub in_frames: u64,
    pub in_bytes: u64,
    /// Frames we actually forwarded to this peer.
    pub out_frames: u64,
    pub out_bytes: u64,
    /// Frames from this peer dropped by a full queue or by queue expiry.
    pub limited_frames: u64,
    pub limited_bytes: u64,
    /// Frames from this peer dropped proactively by CoDel.
    pub codel_frames: u64,
    pub codel_bytes: u64,
    /// Frames from this peer still waiting in its flow queues.
    pub queued_frames: u64,
    pub queued_bytes: u64,
}

/// Relay accounting / scheduler summary, exposed through `irohlan status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReport {
    /// Total cap in KiB/s; 0 means accounting only, no queueing or dropping.
    pub limit_kib_per_sec: u32,
    /// Source peers currently sharing the cap.
    pub active_peers: usize,
    /// Non-empty flow queues across all peers.
    pub active_flows: usize,
    /// Derived per-peer share, KiB/s.
    pub per_peer_kib_per_sec: u32,
    pub relayed_frames: u64,
    pub relayed_bytes: u64,
    /// Frames dropped by a full queue or by queue expiry.
    pub limited_frames: u64,
    pub limited_bytes: u64,
    /// Frames dropped proactively by CoDel (AQM).
    pub codel_frames: u64,
    pub codel_bytes: u64,
    /// Frames currently waiting in all queues.
    pub queued_frames: u64,
    pub queued_bytes: u64,
    pub peers: Vec<RelayPeerReport>,
}

/// Cumulative counters for one peer, persisted across restarts.
///
/// `queued_frames` / `queued_bytes` are intentionally absent: they are
/// instantaneous backlog, not a total, and must not survive a restart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPeerLedger {
    /// Full hex endpoint id (64 characters).
    pub peer: String,
    #[serde(default)]
    pub in_frames: u64,
    #[serde(default)]
    pub in_bytes: u64,
    #[serde(default)]
    pub out_frames: u64,
    #[serde(default)]
    pub out_bytes: u64,
    #[serde(default)]
    pub limited_frames: u64,
    #[serde(default)]
    pub limited_bytes: u64,
    #[serde(default)]
    pub codel_frames: u64,
    #[serde(default)]
    pub codel_bytes: u64,
}

/// On-disk relay ledger: cumulative totals only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLedger {
    #[serde(default)]
    pub relayed_frames: u64,
    #[serde(default)]
    pub relayed_bytes: u64,
    #[serde(default)]
    pub limited_frames: u64,
    #[serde(default)]
    pub limited_bytes: u64,
    #[serde(default)]
    pub codel_frames: u64,
    #[serde(default)]
    pub codel_bytes: u64,
    #[serde(default)]
    pub peers: Vec<RelayPeerLedger>,
}

/// Live status written periodically while the node runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub endpoint_id: Option<String>,
    pub device: Option<String>,
    /// Virtual IPv4 address (absent in IPv6-only networks).
    pub ip: Option<String>,
    /// Virtual IPv6 address (absent in IPv4-only networks).
    #[serde(default)]
    pub ip6: Option<String>,
    /// Address plan, e.g. `10.13.37.0/24, fd42::/64`.
    #[serde(default)]
    pub subnets: Option<String>,
    pub is_creator: bool,
    pub started_at_unix: Option<u64>,
    pub updated_at_unix: u64,
    pub gossip_joined: bool,
    /// Connected mesh peers (endpoint id hex, short).
    pub connected_peers: Vec<String>,
    /// Known LAN members.
    pub members: Vec<crate::proto::MemberRecord>,
    pub frames_from_tap: u64,
    pub frames_to_tap: u64,
    pub frames_dropped: u64,
    /// Unicast frames relayed for other members (partial mesh).
    #[serde(default)]
    pub frames_relayed: u64,
    /// Destinations with a known route in the link-state table.
    #[serde(default)]
    pub routed_destinations: usize,
    /// Link-state advertisements currently in the database.
    #[serde(default)]
    pub lsdb_entries: usize,
    /// Smoothed quality of our direct links, used as routing weights.
    /// `link_rtts` is the v4 field name, kept as an alias so an old
    /// status.json still deserializes (its extra fields default to zero).
    #[serde(default, alias = "link_rtts")]
    pub link_metrics: Vec<LinkMetricReport>,
    /// Paths chosen by the weighted shortest-path computation.
    #[serde(default)]
    pub routes: Vec<RouteReport>,
    /// Per-peer relay accounting and rate-limit summary.
    #[serde(default)]
    pub relay: RelayReport,
    /// Loopback address of the Prometheus endpoint, when enabled.
    #[serde(default)]
    pub metrics_addr: Option<String>,
}

impl StatusReport {
    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)?;
        Ok(serde_json::from_slice(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn atomic_write_replaces_an_existing_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "irohlan-atomic-{}-{unique}.json",
            std::process::id()
        ));
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn relay_ledger_tolerates_partial_json() {
        // Old/partial ledger files must not abort node startup.
        let raw = br#"{"relayed_frames": 5, "peers": [{"peer": "abc", "in_frames": 2}]}"#;
        let ledger: RelayLedger = serde_json::from_slice(raw).unwrap();
        assert_eq!(ledger.relayed_frames, 5);
        assert_eq!(ledger.relayed_bytes, 0);
        assert_eq!(ledger.peers.len(), 1);
        assert_eq!(ledger.peers[0].in_frames, 2);
        assert_eq!(ledger.peers[0].codel_bytes, 0);
    }

    #[test]
    fn status_report_reads_v4_link_field_name() {
        let raw = br#"{"is_creator": false, "updated_at_unix": 0, "gossip_joined": false,
                       "connected_peers": [], "members": [], "frames_from_tap": 0,
                       "frames_to_tap": 0, "frames_dropped": 0,
                       "link_rtts": [{"peer": "abc", "rtt_ms": 12}]}"#;
        let report: StatusReport = serde_json::from_slice(raw).unwrap();
        assert_eq!(report.link_metrics.len(), 1);
        assert_eq!(report.link_metrics[0].rtt_ms, 12);
        assert_eq!(report.link_metrics[0].loss_permille, 0);
    }
}
