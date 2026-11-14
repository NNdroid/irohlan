//! Command line interface.
//!
//! The surface is intentionally tiny: every setting lives in the `--config`
//! JSON file (see [`crate::filecfg`]), so the three long-running subcommands
//! take nothing but a path. Adding a knob used to mean touching `cli.rs`, its
//! tests and the README; now it is one field plus one `Default` line.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgAction, Parser, Subcommand};

use crate::bus::BusMode;
use crate::config::{NetworkConfig, StateDir, StatusReport};
use crate::filecfg;
use crate::netaddr::VirtualAddrs;
use crate::node::{self, NetworkSpec, RunOptions, V6Choice};
use crate::ticket::JoinTicket;

/// Keys `create` accepts in its config file.
const CREATE_KEYS: &str = "Config keys (all optional):
  subnet, subnet6, no-ipv4, no-ipv6, secret, dev, mtu, no-relay, no-mdns,
  bus, topology, mesh-links, relay-limit-kib, metrics-addr

Example (see also create.example.json):
  {\"subnet\": \"10.13.37.0/24\", \"dev\": \"irohlan0\", \"mtu\": 1500,
   \"metrics-addr\": \"127.0.0.1:9090\"}

Without a \"secret\" key the creator generates one and prints it.";

/// Keys `join` accepts in its config file.
const JOIN_KEYS: &str = "Config keys (all optional):
  ticket, secret, ip, ip6, dev, mtu, no-relay, no-mdns, bus, topology,
  mesh-links, relay-limit-kib, metrics-addr

Example (see also join.example.json; the ticket stays on the command line):
  {\"secret\": \"ABCD2345...\", \"ip\": \"10.13.37.7\",
   \"ip6\": \"fd00:1234:5678::7\", \"dev\": \"irohlan0\"}

The ticket may be given as the positional argument or as the \"ticket\" key.
Without a secret the node prompts for one.";

/// Keys `run` accepts in its config file.
const RUN_KEYS: &str = "Config keys (all optional):
  dev, mtu, no-relay, no-mdns, bus, topology, mesh-links, relay-limit-kib,
  metrics-addr, no-metrics

Example (see also run.example.json; turn off a persisted relay cap):
  {\"dev\": \"irohlan0\", \"relay-limit-kib\": 0}

Every key is an override: whatever you leave out is restored from
network.json, including the addresses and the network secret.";

#[derive(Parser)]
#[command(
    name = "irohlan",
    version,
    about = "P2P Layer-2 VPN for Linux built on iroh — a dual-stack virtual ethernet LAN between your machines",
    after_help = "Typical flow:
  machine A:  irohlan create --config creator.json
  machine B:  irohlan join <ticket> --config member.json

Every setting lives in the config file, named after the historic long flags
(e.g. \"no-relay\": true, \"relay-limit-kib\": 2048). Run
`irohlan <command> --help` for the keys each command accepts."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Increase verbosity: -v debug, -vv trace (default: info)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new virtual LAN; this node becomes the creator and address allocator
    ///
    /// Prints the join ticket and the network secret, then runs until stopped.
    /// Omitting --config creates a network with all defaults.
    #[command(after_help = CREATE_KEYS)]
    Create {
        /// JSON settings file
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Join a virtual LAN using a join ticket from the creator
    ///
    /// The ticket comes from the positional argument or from the config file's
    /// "ticket" key; the network secret is prompted for when not configured.
    #[command(after_help = JOIN_KEYS)]
    Join {
        /// The join ticket printed by `irohlan create`
        ticket: Option<String>,
        /// JSON settings file
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Resume the previously created/joined network from local state
    /// (used with systemd or after a reboot)
    #[command(after_help = RUN_KEYS)]
    Run {
        /// JSON settings file with overrides for this run
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Print the join ticket stored by a previous `create`
    Show,
    /// Show the last known status of the local node (written while running)
    Status,
}

/// Assemble engine options from the settings three subcommands share.
///
/// `desired` addresses, the relay cap and the metrics address are set by each
/// caller afterwards, because they differ per subcommand (`create`/`join` use
/// the configured values, `run` falls back to the persisted ones).
fn run_options(
    dev: Option<String>,
    mtu: u16,
    use_relay: bool,
    use_mdns: bool,
    bus: &str,
    topology: &str,
    mesh_links: usize,
) -> anyhow::Result<RunOptions> {
    Ok(RunOptions {
        dev,
        mtu,
        use_relay,
        use_mdns,
        bus_mode: BusMode::parse(bus)?,
        desired: VirtualAddrs::default(),
        topology: node::Topology::parse(topology)?,
        mesh_links,
        // Like `desired`, the relay cap and the metrics address are set by each
        // subcommand afterwards (create/join use the configured values, run
        // falls back to the persisted ones).
        relay_limit_kib: 0,
        metrics_addr: None,
    })
}

/// Merge `run` settings over the saved network: config file > network.json >
/// built-in default.
///
/// `network.json` holds the data-plane choices made at create/join time, so a
/// node set up for an isolated network keeps its `no-relay` / `flood` shape
/// across a reboot instead of silently reverting to the public relay.
fn run_options_for_existing(
    net: &NetworkConfig,
    cfg: &filecfg::RunConfig,
) -> anyhow::Result<RunOptions> {
    let engine = RunOptions::default();

    let use_relay = match cfg.no_relay {
        Some(disabled) => !disabled,
        None => net.use_relay.unwrap_or(engine.use_relay),
    };
    let use_mdns = match cfg.no_mdns {
        Some(disabled) => !disabled,
        None => net.use_mdns.unwrap_or(engine.use_mdns),
    };
    let bus = cfg.bus.clone().unwrap_or_else(|| {
        net.bus
            .clone()
            .unwrap_or_else(|| engine.bus_mode.as_str().to_string())
    });
    let mtu = cfg.mtu.or(net.mtu).unwrap_or(engine.mtu);
    let topology = cfg.topology.clone().unwrap_or_else(|| {
        net.topology
            .clone()
            .unwrap_or_else(|| engine.topology.as_str().to_string())
    });
    let mesh_links = cfg
        .mesh_links
        .or_else(|| net.mesh_links.map(|n| n as usize))
        .unwrap_or(engine.mesh_links);

    let mut opts = run_options(
        cfg.dev.clone(),
        mtu,
        use_relay,
        use_mdns,
        &bus,
        &topology,
        mesh_links,
    )?;
    opts.desired = net.static_addrs();
    opts.relay_limit_kib = cfg
        .relay_limit_kib
        .or(net.relay_limit_kib)
        .unwrap_or(engine.relay_limit_kib);
    opts.metrics_addr = if cfg.no_metrics {
        None
    } else {
        cfg.metrics_addr.or_else(|| {
            net.metrics_addr
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok())
        })
    };
    Ok(opts)
}

fn network_spec(
    subnet: String,
    subnet6: Option<String>,
    no_ipv4: bool,
    no_ipv6: bool,
) -> NetworkSpec {
    let v4 = (!no_ipv4).then_some(subnet);
    let v6 = if no_ipv6 {
        V6Choice::Disabled
    } else {
        match subnet6 {
            Some(cidr) => V6Choice::Custom(cidr),
            None => V6Choice::Auto,
        }
    };
    NetworkSpec { v4, v6 }
}

/// Human readable byte count for status output.
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let filter = match std::env::var("RUST_LOG") {
        Ok(env) => EnvFilter::new(env),
        Err(_) => match verbose {
            0 => EnvFilter::new("info"),
            1 => EnvFilter::new("debug"),
            _ => EnvFilter::new("trace"),
        },
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Prompt for the secret on stdin (used by `join` when the config file has no
/// `secret` key).
fn prompt_secret() -> anyhow::Result<String> {
    eprint!("network secret: ");
    use std::io::Write;
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let secret = line.trim().to_string();
    anyhow::ensure!(!secret.is_empty(), "empty secret");
    Ok(secret)
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    init_tracing(cli.verbose);
    let state = StateDir::open()?;

    match cli.command {
        Command::Create { config } => {
            let cfg = filecfg::load_or_default::<filecfg::CreateConfig>(config.as_deref())?;
            let spec = network_spec(cfg.subnet, cfg.subnet6, cfg.no_ipv4, cfg.no_ipv6);
            let mut opts = run_options(
                cfg.dev,
                cfg.mtu,
                !cfg.no_relay,
                !cfg.no_mdns,
                &cfg.bus,
                &cfg.topology,
                cfg.mesh_links,
            )?;
            opts.relay_limit_kib = cfg.relay_limit_kib;
            opts.metrics_addr = cfg.metrics_addr;
            node::create_network(&state, spec, cfg.secret, opts).await
        }
        Command::Join { ticket, config } => {
            let cfg = filecfg::load_or_default::<filecfg::JoinConfig>(config.as_deref())?;
            let raw = ticket.or(cfg.ticket).ok_or_else(|| {
                anyhow::anyhow!(
                    "join needs a ticket: pass it as an argument or set the \"ticket\" key in the config file"
                )
            })?;
            let ticket = JoinTicket::decode(&raw)
                .map_err(|e| anyhow::anyhow!("invalid join ticket: {e}"))?;
            let secret = match cfg.secret {
                Some(secret) => secret,
                None => prompt_secret()?,
            };
            let mut opts = RunOptions {
                desired: VirtualAddrs {
                    v4: cfg.ip.map(u32::from),
                    v6: cfg.ip6.map(|a| a.octets()),
                },
                ..run_options(
                    cfg.dev,
                    cfg.mtu,
                    !cfg.no_relay,
                    !cfg.no_mdns,
                    &cfg.bus,
                    &cfg.topology,
                    cfg.mesh_links,
                )?
            };
            opts.relay_limit_kib = cfg.relay_limit_kib;
            opts.metrics_addr = cfg.metrics_addr;
            node::join_network(&state, &ticket, secret, opts).await
        }
        Command::Run { config } => {
            let cfg = filecfg::load_or_default::<filecfg::RunConfig>(config.as_deref())?;
            let net = state.load_network()?;
            let secret = state.load_secret()?;
            let opts = run_options_for_existing(&net, &cfg)?;
            node::run_node(&state, net, secret, opts).await
        }

        Command::Show => {
            let ticket = state.load_ticket()?;
            println!("{}", ticket.encode()?);
            Ok(())
        }
        Command::Status => {
            let path = state.status_path();
            if !path.exists() {
                anyhow::bail!("no status file at {} — is a node running?", path.display());
            }
            let report = StatusReport::read(&path)?;
            // `updated_at_unix` is an absolute timestamp; the reader wants
            // the age, so subtract it from now (0 if the clock is behind).
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            println!(
                "updated   : {} s ago",
                now.saturating_sub(report.updated_at_unix)
            );
            println!(
                "endpoint  : {}",
                report.endpoint_id.as_deref().unwrap_or("-")
            );
            println!("device    : {}", report.device.as_deref().unwrap_or("-"));
            println!("ipv4      : {}", report.ip.as_deref().unwrap_or("-"));
            println!("ipv6      : {}", report.ip6.as_deref().unwrap_or("-"));
            println!("subnets   : {}", report.subnets.as_deref().unwrap_or("-"));
            println!(
                "role      : {}",
                if report.is_creator {
                    "creator"
                } else {
                    "member"
                }
            );
            println!("bus joined: {}", report.gossip_joined);
            if let Some(addr) = &report.metrics_addr {
                println!("metrics   : http://{addr}/metrics (metrics.prom in state dir)");
            }
            println!("peers     : {} connected", report.connected_peers.len());
            for p in &report.connected_peers {
                println!("  - {p}");
            }
            println!(
                "routing   : {} destinations known, {} link-state entries (quality-weighted)",
                report.routed_destinations, report.lsdb_entries
            );
            println!("links     : {} direct links", report.link_metrics.len());
            for l in &report.link_metrics {
                println!(
                    "  - {} {} ms, loss {}‰, tx {} kbps, bw {}",
                    l.peer,
                    l.rtt_ms,
                    l.loss_permille,
                    l.tx_kbps,
                    if l.bw_kbps == 0 {
                        "unknown".to_string()
                    } else {
                        format!("{} kbps", l.bw_kbps)
                    }
                );
            }
            println!("routes    : {} chosen paths", report.routes.len());
            for r in &report.routes {
                println!("  - {} via {} (cost {})", r.dest, r.next_hop, r.cost);
            }
            println!("members   : {}", report.members.len());
            for m in &report.members {
                println!(
                    "  - {} {} {}",
                    m.hostname,
                    m.display_addrs(),
                    crate::crypto::format_mac(&crate::crypto::mac_from_id(m.id.as_bytes()))
                );
            }
            println!(
                "frames    : {} from tap, {} to tap, {} relayed, {} dropped",
                report.frames_from_tap,
                report.frames_to_tap,
                report.frames_relayed,
                report.frames_dropped
            );
            let relay = &report.relay;
            let limit = if relay.limit_kib_per_sec == 0 {
                "off (accounting only)".to_string()
            } else {
                format!(
                    "{} KiB/s total / {} active peers => {} KiB/s each",
                    relay.limit_kib_per_sec, relay.active_peers, relay.per_peer_kib_per_sec
                )
            };
            println!(
                "relay     : {} frames / {} forwarded, {} frames / {} dropped (limit {})",
                relay.relayed_frames,
                format_bytes(relay.relayed_bytes),
                relay.limited_frames,
                format_bytes(relay.limited_bytes),
                limit
            );
            println!(
                "            {} frames / {} queued, {} active flows, {} frames / {} CoDel-dropped",
                relay.queued_frames,
                format_bytes(relay.queued_bytes),
                relay.active_flows,
                relay.codel_frames,
                format_bytes(relay.codel_bytes)
            );
            println!("relay peer: {} peers", relay.peers.len());
            for p in &relay.peers {
                println!(
                    "  - {} in {} / {}, out {} / {}, queued {} / {}, dropped {} / {}, codel {} / {}",
                    p.peer,
                    p.in_frames,
                    format_bytes(p.in_bytes),
                    p.out_frames,
                    format_bytes(p.out_bytes),
                    p.queued_frames,
                    format_bytes(p.queued_bytes),
                    p.limited_frames,
                    format_bytes(p.limited_bytes),
                    p.codel_frames,
                    format_bytes(p.codel_bytes)
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_bytes, run_options_for_existing, Cli, Command, NetworkConfig, RunOptions};
    use crate::filecfg::RunConfig;
    use crate::netaddr::V4Net;
    use crate::proto::IdBytes;
    use clap::{error::ErrorKind, CommandFactory, Parser};

    /// Minimal saved network: only what the `run` merge actually reads.
    fn saved_network() -> NetworkConfig {
        NetworkConfig {
            net_id: IdBytes([7; 32]),
            v4: Some(V4Net::parse_cidr("10.13.37.0/24").expect("valid cidr")),
            v6: None,
            subnet: None,
            prefix: None,
            topic_id: IdBytes([9; 32]),
            creator: None,
            is_creator: true,
            static_ip: None,
            static_ip6: None,
            topology: Some("partial".into()),
            mesh_links: Some(3),
            relay_limit_kib: Some(2048),
            metrics_addr: Some("127.0.0.1:9090".into()),
            mtu: Some(1400),
            use_relay: Some(false),
            use_mdns: Some(false),
            bus: Some("flood".into()),
        }
    }

    /// The reboot path: `irohlan run` with no config file must reproduce the
    /// node that `create` set up, instead of re-enabling the public relay.
    #[test]
    fn run_restores_the_persisted_data_plane() {
        let opts = run_options_for_existing(&saved_network(), &RunConfig::default())
            .expect("valid settings");
        assert!(!opts.use_relay, "no-relay must survive a reboot");
        assert!(!opts.use_mdns);
        assert_eq!(opts.bus_mode.as_str(), "flood");
        assert_eq!(opts.mtu, 1400);
        assert_eq!(opts.mesh_links, 3);
        assert_eq!(opts.relay_limit_kib, 2048);
        assert_eq!(opts.topology.as_str(), "partial");
        assert_eq!(
            opts.metrics_addr.expect("persisted address").to_string(),
            "127.0.0.1:9090"
        );
    }

    /// A config file beats what was saved, and only for the keys it names.
    #[test]
    fn run_file_wins_over_the_persisted_values() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{"no-relay": false, "relay-limit-kib": 0, "no-metrics": true, "mtu": 1300}"#,
        )
        .expect("valid config");
        let opts = run_options_for_existing(&saved_network(), &cfg).expect("valid settings");
        assert!(opts.use_relay, "no-relay:false re-enables the relay");
        assert_eq!(opts.relay_limit_kib, 0);
        assert!(opts.metrics_addr.is_none(), "no-metrics wins");
        assert_eq!(opts.mtu, 1300);
        // Keys the file is silent about still come from network.json.
        assert_eq!(opts.bus_mode.as_str(), "flood");
        assert!(!opts.use_mdns);
    }

    /// A `network.json` written before these settings existed has to keep
    /// loading, and its missing keys fall through to the engine defaults.
    #[test]
    fn run_handles_a_network_json_from_an_older_version() {
        let mut net = saved_network();
        net.mtu = None;
        net.use_relay = None;
        net.use_mdns = None;
        net.bus = None;
        net.topology = None;
        net.mesh_links = None;

        let engine = RunOptions::default();
        let opts = run_options_for_existing(&net, &RunConfig::default()).expect("valid settings");
        assert_eq!(opts.mtu, engine.mtu);
        assert_eq!(opts.use_relay, engine.use_relay);
        assert_eq!(opts.use_mdns, engine.use_mdns);
        assert_eq!(opts.bus_mode, engine.bus_mode);
        assert_eq!(opts.mesh_links, engine.mesh_links);
        assert_eq!(opts.topology, engine.topology);
    }

    /// The new fields are `skip_serializing_if = "Option::is_none"`, so old
    /// state files (which lack them entirely) deserialize to `None`.
    #[test]
    fn network_json_round_trips_and_tolerates_the_old_shape() {
        let mut value = serde_json::to_value(saved_network()).expect("serializable");
        let obj = value.as_object_mut().expect("object");
        for key in ["mtu", "use_relay", "use_mdns", "bus"] {
            assert!(obj.remove(key).is_some(), "{key} should be persisted");
        }
        let old: NetworkConfig = serde_json::from_value(value).expect("old state still loads");
        assert!(old.mtu.is_none());
        assert!(old.use_relay.is_none());
        assert!(old.use_mdns.is_none());
        assert!(old.bus.is_none());
    }

    #[test]
    fn byte_counts_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    /// Every subcommand must take a config path and nothing else (`join` also
    /// takes the ticket). A stray flag would mean a setting that only one code
    /// path honours, which is exactly what moving everything into the file was
    /// meant to prevent.
    #[test]
    fn subcommands_only_take_a_config_path() {
        let cmd = Cli::command();
        for sc in cmd.get_subcommands() {
            let mut ids: Vec<&str> = sc
                .get_arguments()
                // `--verbose` is global, so clap propagates it everywhere.
                .map(|a| a.get_id().as_str())
                .filter(|id| *id != "verbose")
                .collect();
            ids.sort_unstable();
            let mut expected: Vec<&str> = match sc.get_name() {
                "create" | "run" => vec!["config"],
                "join" => vec!["config", "ticket"],
                "show" | "status" => vec![],
                other => panic!("unexpected subcommand {other}"),
            };
            expected.sort_unstable();
            assert_eq!(ids, expected, "{}", sc.get_name());
        }
    }

    /// A bare command must work: `create` and `join` have real defaults, and
    /// `run` restores everything from `network.json` — the systemd unit
    /// depends on `ExecStart=irohlan run` staying valid.
    #[test]
    fn bare_commands_still_parse() {
        for argv in [
            vec!["irohlan", "create"],
            vec!["irohlan", "run"],
            vec!["irohlan", "join"],
            vec!["irohlan", "show"],
            vec!["irohlan", "status"],
        ] {
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let _ = cli;
        }
    }

    #[test]
    fn config_path_and_ticket_are_parsed() {
        let cli =
            Cli::try_parse_from(["irohlan", "join", "irohlan1_x", "--config", "b.json"]).unwrap();
        match cli.command {
            Command::Join { ticket, config } => {
                assert_eq!(ticket.as_deref(), Some("irohlan1_x"));
                assert_eq!(config.unwrap().to_str(), Some("b.json"));
            }
            _ => panic!("expected join"),
        }

        let cli = Cli::try_parse_from(["irohlan", "run", "--config", "c.json"]).unwrap();
        match cli.command {
            Command::Run { config } => assert_eq!(config.unwrap().to_str(), Some("c.json")),
            _ => panic!("expected run"),
        }
        let cli = Cli::try_parse_from(["irohlan", "run"]).unwrap();
        match cli.command {
            Command::Run { config } => assert!(config.is_none()),
            _ => panic!("expected run"),
        }
    }

    /// The key list printed by `--help` is hand-written, so it can drift from
    /// the parser. serde's "unknown field" error enumerates the real fields,
    /// which makes the two sets comparable.
    #[test]
    fn help_lists_exactly_the_accepted_keys() {
        use super::{CREATE_KEYS, JOIN_KEYS, RUN_KEYS};
        use crate::filecfg::{CreateConfig, JoinConfig, RunConfig};

        /// Words in the `Config keys` block of a help string.
        fn listed(help: &str) -> Vec<String> {
            let block = help
                .split("Config keys (all optional):")
                .nth(1)
                .expect("help has a key block")
                .split("\n\n")
                .next()
                .expect("key block is not empty");
            block
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }

        /// Fields serde accepts, taken from the error for an unknown key.
        fn accepted<T: serde::de::DeserializeOwned>() -> Vec<String> {
            let err = match serde_json::from_str::<T>(r#"{"nope": null}"#) {
                Ok(_) => panic!("an unknown key must be rejected"),
                Err(err) => err.to_string(),
            };
            // "... expected one of `subnet`, `subnet6`, ... at line 1 column N"
            err.split('`')
                .skip(1)
                .step_by(2)
                .skip(1) // the bogus key we just sent
                .map(str::to_string)
                .collect()
        }

        fn assert_same(help: &str, fields: Vec<String>, name: &str) {
            let mut from_help = listed(help);
            let mut from_serde = fields;
            from_help.sort();
            from_serde.sort();
            assert_eq!(from_help, from_serde, "{name} help lists stale keys");
        }

        assert_same(CREATE_KEYS, accepted::<CreateConfig>(), "create");
        assert_same(JOIN_KEYS, accepted::<JoinConfig>(), "join");
        assert_same(RUN_KEYS, accepted::<RunConfig>(), "run");
    }

    /// The flags that moved into the config file must not creep back: silently
    /// accepting one would mean the node ignores what the operator typed.
    #[test]
    fn settings_flags_are_gone() {
        for argv in [
            vec!["irohlan", "create", "--no-relay"],
            vec!["irohlan", "create", "--relay-limit-kib", "2048"],
            vec!["irohlan", "create", "--subnet", "10.13.37.0/24"],
            vec!["irohlan", "join", "--ip", "10.13.37.7"],
            vec!["irohlan", "run", "--metrics-addr", "127.0.0.1:9090"],
            vec!["irohlan", "run", "--no-metrics"],
        ] {
            match Cli::try_parse_from(&argv) {
                Ok(_) => panic!("{argv:?} was accepted"),
                Err(err) => assert_eq!(err.kind(), ErrorKind::UnknownArgument, "{argv:?}"),
            }
        }
    }
}
