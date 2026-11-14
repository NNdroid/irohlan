//! `--config <PATH>`: the one place every setting lives.
//!
//! The command line stays deliberately tiny — `create`/`join`/`run` accept
//! nothing but a config path (`join` also takes the ticket) — so this module
//! owns the whole settings surface. Keys are the kebab-case form of the
//! historic long flags (`relay-limit-kib`, `no-relay`, …), which keeps old
//! runbooks and issue reports readable and makes the schema easy to remember.
//!
//! Every key is optional and falls back to the value an empty file would give,
//! i.e. the same defaults the engine uses.
//!
//! A file is strictly validated: unknown keys are an error, because a typo in
//! something like `relay-limit-kib` would otherwise silently fall back to the
//! default and quietly change how the node behaves.
//!
//! ```json
//! {
//!   "subnet": "10.13.37.0/24",
//!   "secret": "correct horse battery staple",
//!   "dev": "irohlan0",
//!   "no-relay": true,
//!   "topology": "partial",
//!   "mesh-links": 4,
//!   "relay-limit-kib": 2048,
//!   "metrics-addr": "127.0.0.1:9090"
//! }
//! ```
//!
//! Nothing is written back: `create`/`join` still persist the resulting network
//! parameters into `network.json`, so one file can be kept under version
//! control and reused for every node of a template.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::bus::BusMode;
use crate::netaddr::DEFAULT_V4_CIDR;
use crate::node::Topology;
use crate::tap::DEFAULT_MTU;

/// Default broadcast bus, taken from the engine so the two cannot diverge.
fn default_bus() -> String {
    BusMode::default().as_str().to_string()
}

/// Default topology name, taken from the engine so the two cannot diverge.
fn default_topology() -> String {
    Topology::default().as_str().to_string()
}

/// Read and strictly parse a config file.
fn load<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let raw = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("invalid config file {}: {e}", path.display()))
}

/// Load a config file when one was given, otherwise use all-defaults.
pub fn load_or_default<T: DeserializeOwned + Default>(path: Option<&Path>) -> anyhow::Result<T> {
    match path {
        Some(path) => load(path),
        None => Ok(T::default()),
    }
}

/// Settings a `create` invocation reads.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", default)]
pub struct CreateConfig {
    /// Virtual IPv4 subnet in CIDR notation.
    pub subnet: String,
    /// Virtual IPv6 prefix in CIDR notation (default: ULA /64 from the net id).
    pub subnet6: Option<String>,
    /// Disable the IPv4 address family.
    pub no_ipv4: bool,
    /// Disable the IPv6 address family.
    pub no_ipv6: bool,
    /// Network secret; generated and printed when omitted.
    pub secret: Option<String>,
    /// TAP device name (e.g. `irohlan0` or `irohlan%d`).
    pub dev: Option<String>,
    /// TAP MTU (IPv6 requires at least 1280).
    pub mtu: u16,
    /// Disable the public iroh relay infrastructure.
    pub no_relay: bool,
    /// Disable LAN mDNS discovery.
    pub no_mdns: bool,
    /// Broadcast bus implementation: `gossip` or `flood`.
    pub bus: String,
    /// Mesh topology: `partial` (k neighbors + multi-hop relay) or `full`.
    pub topology: String,
    /// Target neighbor count in partial topology.
    pub mesh_links: usize,
    /// Cap forwarded (relayed) traffic in KiB/s; 0 keeps accounting only.
    pub relay_limit_kib: u32,
    /// Loopback address for the Prometheus `/metrics` endpoint.
    pub metrics_addr: Option<SocketAddr>,
}

impl Default for CreateConfig {
    fn default() -> Self {
        Self {
            subnet: DEFAULT_V4_CIDR.to_string(),
            subnet6: None,
            no_ipv4: false,
            no_ipv6: false,
            secret: None,
            dev: None,
            mtu: DEFAULT_MTU,
            no_relay: false,
            no_mdns: false,
            bus: default_bus(),
            topology: default_topology(),
            mesh_links: 8,
            relay_limit_kib: 0,
            metrics_addr: None,
        }
    }
}

/// Settings a `join` invocation reads.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", default)]
pub struct JoinConfig {
    /// The join ticket; lets a template carry everything.
    pub ticket: Option<String>,
    /// Network secret (the creator printed it next to the ticket).
    pub secret: Option<String>,
    /// Request this specific virtual IPv4 address.
    pub ip: Option<Ipv4Addr>,
    /// Request this specific virtual IPv6 address (same host index as `ip`).
    pub ip6: Option<Ipv6Addr>,
    /// TAP device name (e.g. `irohlan0` or `irohlan%d`).
    pub dev: Option<String>,
    /// TAP MTU (IPv6 requires at least 1280).
    pub mtu: u16,
    /// Disable the public iroh relay infrastructure.
    pub no_relay: bool,
    /// Disable LAN mDNS discovery.
    pub no_mdns: bool,
    /// Broadcast bus implementation: `gossip` or `flood`.
    pub bus: String,
    /// Mesh topology: `partial` (k neighbors + multi-hop relay) or `full`.
    pub topology: String,
    /// Target neighbor count in partial topology.
    pub mesh_links: usize,
    /// Cap forwarded (relayed) traffic in KiB/s; 0 keeps accounting only.
    pub relay_limit_kib: u32,
    /// Loopback address for the Prometheus `/metrics` endpoint.
    pub metrics_addr: Option<SocketAddr>,
}

impl Default for JoinConfig {
    fn default() -> Self {
        Self {
            ticket: None,
            secret: None,
            ip: None,
            ip6: None,
            dev: None,
            mtu: DEFAULT_MTU,
            no_relay: false,
            no_mdns: false,
            bus: default_bus(),
            topology: default_topology(),
            mesh_links: 8,
            relay_limit_kib: 0,
            metrics_addr: None,
        }
    }
}

/// Settings a `run` invocation reads.
///
/// Everything here is an override. A key left out means "use whatever
/// `network.json` persisted" (`create`/`join` store the MTU, relay, mDNS and
/// bus choices too), and only a network saved by an older version — which has
/// none of them — falls through to the built-in default.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", default)]
pub struct RunConfig {
    /// TAP device name override.
    pub dev: Option<String>,
    /// TAP MTU override (IPv6 requires at least 1280).
    pub mtu: Option<u16>,
    /// Disable the public iroh relay infrastructure.
    pub no_relay: Option<bool>,
    /// Disable LAN mDNS discovery.
    pub no_mdns: Option<bool>,
    /// Broadcast bus implementation: `gossip` or `flood`.
    pub bus: Option<String>,
    /// Mesh topology override (defaults to the persisted choice).
    pub topology: Option<String>,
    /// Target neighbor count override (defaults to the persisted choice).
    pub mesh_links: Option<usize>,
    /// Relay cap override in KiB/s (defaults to the persisted value).
    pub relay_limit_kib: Option<u32>,
    /// Loopback address override for the Prometheus `/metrics` endpoint.
    pub metrics_addr: Option<SocketAddr>,
    /// Disable the metrics endpoint for this run (ignores the persisted value).
    pub no_metrics: bool,
}

#[cfg(test)]
mod tests {
    use super::{load_or_default, CreateConfig, JoinConfig, RunConfig};
    use crate::bus::BusMode;
    use crate::netaddr::DEFAULT_V4_CIDR;
    use crate::node::{RunOptions, Topology};
    use crate::tap::DEFAULT_MTU;
    use std::path::Path;

    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> anyhow::Result<T> {
        Ok(serde_json::from_str(json)?)
    }

    #[test]
    fn create_config_uses_the_old_flag_names() {
        let cfg: CreateConfig = parse(
            r#"{
                "subnet": "10.13.37.0/24",
                "no-relay": true,
                "no-ipv6": true,
                "mesh-links": 4,
                "relay-limit-kib": 2048,
                "metrics-addr": "127.0.0.1:9090"
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.subnet, "10.13.37.0/24");
        assert!(cfg.no_relay);
        assert!(cfg.no_ipv6);
        assert_eq!(cfg.mesh_links, 4);
        assert_eq!(cfg.relay_limit_kib, 2048);
        assert_eq!(cfg.metrics_addr.unwrap().to_string(), "127.0.0.1:9090");
        // Keys the file is silent about keep the engine defaults.
        assert!(cfg.dev.is_none());
        assert_eq!(cfg.mtu, DEFAULT_MTU);
        assert_eq!(cfg.topology, "partial");
    }

    #[test]
    fn unknown_key_is_an_error() {
        // A typo must not silently fall back to the default.
        let err = parse::<CreateConfig>(r#"{"relay-limit-kibs": 2048}"#).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn keys_belonging_to_another_subcommand_are_rejected() {
        // `ip` is a join-only setting; accepting it in a create file would
        // mean silently ignoring what the operator asked for.
        let err = parse::<CreateConfig>(r#"{"ip": "10.13.37.7"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let err = parse::<RunConfig>(r#"{"subnet": "10.13.37.0/24"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let err = parse::<JoinConfig>(r#"{"subnet6": "fd00::/64"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn join_config_accepts_a_ticket() {
        let cfg: JoinConfig =
            parse(r#"{"ticket": "irohlan1_abc", "ip": "10.13.37.7", "ip6": "fd00::7"}"#).unwrap();
        assert_eq!(cfg.ticket.as_deref(), Some("irohlan1_abc"));
        assert_eq!(cfg.ip.unwrap().to_string(), "10.13.37.7");
        assert!(cfg.ip6.is_some());
    }

    #[test]
    fn empty_object_keeps_every_default() {
        let cfg: RunConfig = parse("{}").unwrap();
        // Every `run` key is an override: unset means "keep what network.json
        // stored", never "reset to the built-in default".
        assert!(cfg.dev.is_none());
        assert!(cfg.mtu.is_none());
        assert!(cfg.no_relay.is_none());
        assert!(cfg.no_mdns.is_none());
        assert!(cfg.bus.is_none());
        assert!(cfg.metrics_addr.is_none());
        assert!(cfg.topology.is_none());
        assert!(cfg.mesh_links.is_none());
        assert!(cfg.relay_limit_kib.is_none());

        let create: CreateConfig = parse("{}").unwrap();
        assert_eq!(create.subnet, CreateConfig::default().subnet);
        assert_eq!(create.bus, CreateConfig::default().bus);
        let join: JoinConfig = parse("{}").unwrap();
        assert_eq!(join.mtu, JoinConfig::default().mtu);
        assert!(join.ticket.is_none());
    }

    /// The file's defaults must be the engine's defaults, otherwise
    /// `irohlan create` without a file would behave differently from
    /// `irohlan create --config empty.json`.
    #[test]
    fn defaults_match_the_engine() {
        let engine = RunOptions::default();
        let cfg = CreateConfig::default();
        assert_eq!(cfg.mtu, engine.mtu);
        assert_eq!(cfg.mesh_links, engine.mesh_links);
        assert_eq!(cfg.relay_limit_kib, engine.relay_limit_kib);
        assert_eq!(cfg.no_relay, !engine.use_relay);
        assert_eq!(cfg.no_mdns, !engine.use_mdns);
        assert_eq!(cfg.topology, engine.topology.as_str());
        assert_eq!(cfg.topology, Topology::default().as_str());
        assert_eq!(BusMode::parse(&cfg.bus).unwrap(), engine.bus_mode);
        assert_eq!(cfg.subnet, DEFAULT_V4_CIDR);
        assert!(cfg.subnet6.is_none());
    }

    /// The examples in `example/` are copy-paste material. A renamed key
    /// would otherwise only be noticed by whoever copied the broken file.
    #[test]
    fn shipped_examples_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));

        let create: CreateConfig =
            super::load(&root.join("example").join("create.example.json")).unwrap();
        // No `secret` on purpose: the creator generates one and prints it.
        assert!(create.secret.is_none());
        assert_eq!(create.subnet, "10.13.37.0/24");
        // Ship the engine defaults, not bench-tuning: an example that quietly
        // lowers the MTU (1400) or turns on relay shaping (2048) changes the
        // data plane for everyone who copies it.
        assert_eq!(create.mtu, DEFAULT_MTU);
        assert_eq!(create.relay_limit_kib, 0);

        let join: JoinConfig =
            super::load(&root.join("example").join("join.example.json")).unwrap();
        // No `ticket` on purpose: it is passed as the positional argument.
        assert!(join.ticket.is_none());
        // The examples are a matched pair: `ip` sits in the subnet `create`
        // pins, `ip6` in the prefix it pins, and both name the same host
        // index (7). Editing one file without the other breaks this, which is
        // exactly what a copy-paste user would hit.
        let ip = join.ip.expect("join example pins a v4 address");
        let ip6 = join.ip6.expect("join example pins a v6 address");
        assert_eq!(create.subnet6.as_deref(), Some("fd00:1234:5678::/64"));
        assert_eq!(ip.octets()[..3], [10, 13, 37]);
        assert_eq!(&ip6.segments()[..3], &[0xfd00, 0x1234, 0x5678]);
        assert_eq!(ip.octets()[3], ip6.segments()[7] as u8);
        assert_eq!(join.mtu, DEFAULT_MTU);
        assert_eq!(join.relay_limit_kib, 0);

        let run: RunConfig = super::load(&root.join("example").join("run.example.json")).unwrap();

        // The throughput workflow (`.github/workflows/test.yml`) boots both
        // nodes straight from these two files. If a key drifts or a pinned
        // address leaves the subnet, `cargo test` must fail here — long
        // before a red CI job has to explain itself from an artifact.
        let bench_creator: CreateConfig =
            super::load(&root.join("example").join("bench-creator.json")).unwrap();
        assert_eq!(bench_creator.subnet, "10.13.37.0/24");
        assert!(bench_creator.no_ipv6, "bench network is IPv4-only");
        assert!(bench_creator.no_relay, "an isolated netns has no relay path");
        assert!(bench_creator.no_mdns);
        assert_eq!(
            crate::bus::BusMode::parse(&bench_creator.bus).unwrap(),
            crate::bus::BusMode::Flood,
            "gossip needs address lookup that an isolated netns cannot provide"
        );
        assert_eq!(bench_creator.mtu, 1400);
        assert!(bench_creator.secret.is_some(), "both nodes share one secret");

        let bench_joiner: JoinConfig =
            super::load(&root.join("example").join("bench-joiner.json")).unwrap();
        assert_eq!(
            bench_joiner.ip.map(|a| a.to_string()).as_deref(),
            Some("10.13.37.2"),
            "the workflow pings and drives iperf3 against this pinned address"
        );
        assert!(
            bench_joiner.ip6.is_none(),
            "the creator runs IPv4-only; a pinned ip6 would be rejected at join time"
        );
        assert_eq!(
            bench_joiner.secret.as_deref(),
            bench_creator.secret.as_deref(),
            "the pair must share the network secret"
        );
        assert_eq!(run.dev.as_deref(), Some("irohlan0"));
        // `run` only shows an override: the cap persists in network.json, this
        // file turns it off for one boot. Keys it omits keep the persisted
        // value instead of a default.
        assert_eq!(run.relay_limit_kib, Some(0));
        assert!(run.topology.is_none());
    }

    /// The benchmark harness generates exactly these documents. Renaming a key
    /// would otherwise only surface as a red CI job ~30 minutes in, so pin the
    /// shape here.
    #[test]
    fn benchmark_configs_parse() {
        let creator: CreateConfig = parse(
            r#"{
              "dev": "tap-a", "secret": "irohlan-benchmark-only-secret",
              "mtu": 1400, "no-relay": true, "bus": "flood",
              "topology": "partial", "mesh-links": 1, "relay-limit-kib": 2048,
              "subnet": "10.13.37.0/24", "no-ipv6": true,
              "metrics-addr": "127.0.0.1:9090"
            }"#,
        )
        .unwrap();
        assert!(creator.no_relay && creator.no_ipv6);
        assert_eq!(creator.mesh_links, 1);
        assert_eq!(creator.topology, "partial");

        let member: JoinConfig = parse(
            r#"{
              "dev": "tap-b", "secret": "irohlan-benchmark-only-secret",
              "mtu": 1400, "no-relay": true, "bus": "flood",
              "topology": "full", "relay-limit-kib": 0, "ip": "10.13.37.1",
              "metrics-addr": "127.0.0.1:9090"
            }"#,
        )
        .unwrap();
        assert_eq!(member.ip.unwrap().to_string(), "10.13.37.1");
        assert_eq!(member.topology, "full");
        assert_eq!(member.mtu, 1400);
    }

    #[test]
    fn missing_file_reports_its_path() {
        let err = load_or_default::<RunConfig>(Some(Path::new("does/not/exist.json"))).unwrap_err();
        assert!(err.to_string().contains("cannot read config file"), "{err}");
        // No path at all is not an error: `run` behaves as if the file were
        // empty, i.e. it inherits everything from network.json.
        let cfg = load_or_default::<RunConfig>(None).unwrap();
        assert!(cfg.mtu.is_none());
        assert!(cfg.no_relay.is_none());
    }
}
