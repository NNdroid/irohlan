//! Node identity and on-disk state.
//!
//! Layout (one virtual network per host, v1):
//! ```text
//! <state_dir>/irohlan/
//!   identity.key    32-byte ed25519 seed (the iroh endpoint identity)
//!   network.json    current network parameters
//!   secret.txt      network passphrase (0600)
//!   ticket.txt      last generated/used join ticket
//!   leases.json     (creator) granted virtual IPs
//!   status.json     periodically written live status for `irohlan status`
//! ```

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::proto::IdBytes;
use crate::ticket::JoinTicket;

/// All persistent parameters of the joined/created network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub net_id: IdBytes,
    /// Subnet base address as u32.
    pub subnet: u32,
    pub prefix: u8,
    pub topic_id: IdBytes,
    /// Endpoint id of the creator; `None` when we are the creator.
    pub creator: Option<IdBytes>,
    pub is_creator: bool,
    /// Our static virtual IP, if it was pinned via `--ip`.
    pub static_ip: Option<u32>,
    /// Mesh topology chosen at create/join time ("full" | "partial").
    #[serde(default)]
    pub topology: Option<String>,
    /// Target neighbor count for the partial topology.
    #[serde(default)]
    pub mesh_links: Option<u32>,
}

impl NetworkConfig {
    pub fn subnet(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.subnet)
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

/// Live status written periodically while the node runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub endpoint_id: Option<String>,
    pub device: Option<String>,
    pub ip: Option<String>,
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
