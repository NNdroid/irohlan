//! Command line interface.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use clap::{ArgAction, Parser, Subcommand};

use crate::bus::BusMode;
use crate::config::{StateDir, StatusReport};
use crate::netaddr::{VirtualAddrs, DEFAULT_V4_CIDR};
use crate::node::{self, NetworkSpec, RunOptions, V6Choice};
use crate::tap::DEFAULT_MTU;
use crate::ticket::JoinTicket;

#[derive(Parser)]
#[command(
    name = "irohlan",
    version,
    about = "P2P Layer-2 VPN for Linux built on iroh — a dual-stack virtual ethernet LAN between your machines",
    after_help = "Typical flow:
  machine A:  irohlan create
  machine B:  irohlan join <ticket> --secret <network secret>"
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
    Create {
        /// Virtual IPv4 subnet in CIDR notation
        #[arg(long, default_value = DEFAULT_V4_CIDR)]
        subnet: String,
        /// Virtual IPv6 prefix in CIDR notation (default: ULA /64 derived from the network id)
        #[arg(long)]
        subnet6: Option<String>,
        /// Disable the IPv4 address family
        #[arg(long, default_value_t = false)]
        no_ipv4: bool,
        /// Disable the IPv6 address family
        #[arg(long, default_value_t = false)]
        no_ipv6: bool,
        /// Network secret (generated and printed when omitted)
        #[arg(long)]
        secret: Option<String>,
        /// TAP device name (e.g. irohlan0 or irohlan%d)
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU (IPv6 requires at least 1280)
        #[arg(long, default_value_t = DEFAULT_MTU)]
        mtu: u16,
        /// Disable the public iroh relay infrastructure
        #[arg(long, default_value_t = false)]
        no_relay: bool,
        /// Disable LAN mDNS discovery
        #[arg(long, default_value_t = false)]
        no_mdns: bool,
        /// Broadcast bus implementation: gossip or flood
        #[arg(long, default_value = "gossip")]
        bus: String,
        /// Mesh topology: partial (k neighbors + multi-hop relay) or full
        #[arg(long, default_value = "partial")]
        topology: String,
        /// Target neighbor count in partial topology
        #[arg(long, default_value_t = 8)]
        mesh_links: usize,
        /// Cap forwarded (relayed) traffic in KiB/s; 0 keeps accounting only
        #[arg(long, default_value_t = 0)]
        relay_limit_kib: u32,
        /// Loopback address for the Prometheus /metrics endpoint (e.g. 127.0.0.1:9090)
        #[arg(long)]
        metrics_addr: Option<SocketAddr>,
    },
    /// Join a virtual LAN using a join ticket from the creator
    Join {
        /// The join ticket printed by `irohlan create`
        ticket: String,
        /// Network secret (the creator printed it next to the ticket)
        #[arg(long)]
        secret: Option<String>,
        /// Request this specific virtual IPv4 address
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// Request this specific virtual IPv6 address (must share the host index with --ip)
        #[arg(long)]
        ip6: Option<Ipv6Addr>,
        /// TAP device name (e.g. irohlan0 or irohlan%d)
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU (IPv6 requires at least 1280)
        #[arg(long, default_value_t = DEFAULT_MTU)]
        mtu: u16,
        /// Disable the public iroh relay infrastructure
        #[arg(long, default_value_t = false)]
        no_relay: bool,
        /// Disable LAN mDNS discovery
        #[arg(long, default_value_t = false)]
        no_mdns: bool,
        /// Broadcast bus implementation: gossip or flood
        #[arg(long, default_value = "gossip")]
        bus: String,
        /// Mesh topology: partial (k neighbors + multi-hop relay) or full
        #[arg(long, default_value = "partial")]
        topology: String,
        /// Target neighbor count in partial topology
        #[arg(long, default_value_t = 8)]
        mesh_links: usize,
        /// Cap forwarded (relayed) traffic in KiB/s; 0 keeps accounting only
        #[arg(long, default_value_t = 0)]
        relay_limit_kib: u32,
        /// Loopback address for the Prometheus /metrics endpoint (e.g. 127.0.0.1:9090)
        #[arg(long)]
        metrics_addr: Option<SocketAddr>,
    },
    /// Resume the previously created/joined network from local state
    /// (used with systemd or after a reboot)
    Run {
        /// TAP device name override
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU override (IPv6 requires at least 1280)
        #[arg(long)]
        mtu: Option<u16>,
        /// Disable the public iroh relay infrastructure
        #[arg(long, default_value_t = false)]
        no_relay: bool,
        /// Disable LAN mDNS discovery
        #[arg(long, default_value_t = false)]
        no_mdns: bool,
        /// Broadcast bus implementation: gossip or flood
        #[arg(long, default_value = "gossip")]
        bus: String,
        /// Mesh topology override (defaults to the persisted choice)
        #[arg(long)]
        topology: Option<String>,
        /// Target neighbor count override (defaults to the persisted choice)
        #[arg(long)]
        mesh_links: Option<usize>,
        /// Relay cap override in KiB/s (defaults to the persisted value)
        #[arg(long)]
        relay_limit_kib: Option<u32>,
        /// Loopback address override for the Prometheus /metrics endpoint
        #[arg(long)]
        metrics_addr: Option<SocketAddr>,
        /// Disable the metrics endpoint for this run (ignores the persisted value)
        #[arg(long, default_value_t = false)]
        no_metrics: bool,
    },
    /// Print the join ticket stored by a previous `create`
    Show,
    /// Show the last known status of the local node (written while running)
    Status,
}

fn run_options(
    dev: Option<String>,
    mtu: u16,
    no_relay: bool,
    no_mdns: bool,
    bus: &str,
    topology: &str,
    mesh_links: usize,
) -> anyhow::Result<RunOptions> {
    Ok(RunOptions {
        dev,
        mtu,
        use_relay: !no_relay,
        use_mdns: !no_mdns,
        bus_mode: BusMode::parse(bus)?,
        desired: VirtualAddrs::default(),
        topology: node::Topology::parse(topology)?,
        mesh_links,
        // Like `desired`, the relay cap and metrics address are set by each
        // subcommand afterwards (create/join use the CLI value, run uses the
        // persisted value).
        relay_limit_kib: 0,
        metrics_addr: None,
    })
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

/// Prompt for the secret on stdin (used by `join` without --secret).
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
        Command::Create {
            subnet,
            subnet6,
            no_ipv4,
            no_ipv6,
            secret,
            dev,
            mtu,
            no_relay,
            no_mdns,
            bus,
            topology,
            mesh_links,
            relay_limit_kib,
            metrics_addr,
        } => {
            let spec = network_spec(subnet, subnet6, no_ipv4, no_ipv6);
            let mut opts = run_options(dev, mtu, no_relay, no_mdns, &bus, &topology, mesh_links)?;
            opts.relay_limit_kib = relay_limit_kib;
            opts.metrics_addr = metrics_addr;
            node::create_network(&state, spec, secret, opts).await
        }
        Command::Join {
            ticket,
            secret,
            ip,
            ip6,
            dev,
            mtu,
            no_relay,
            no_mdns,
            bus,
            topology,
            mesh_links,
            relay_limit_kib,
            metrics_addr,
        } => {
            let ticket = JoinTicket::decode(&ticket)
                .map_err(|e| anyhow::anyhow!("invalid join ticket: {e}"))?;
            let secret = match secret {
                Some(s) => s,
                None => prompt_secret()?,
            };
            let mut opts = RunOptions {
                desired: VirtualAddrs {
                    v4: ip.map(u32::from),
                    v6: ip6.map(|a| a.octets()),
                },
                ..run_options(dev, mtu, no_relay, no_mdns, &bus, &topology, mesh_links)?
            };
            opts.relay_limit_kib = relay_limit_kib;
            opts.metrics_addr = metrics_addr;
            node::join_network(&state, &ticket, secret, opts).await
        }
        Command::Run {
            dev,
            mtu,
            no_relay,
            no_mdns,
            bus,
            topology,
            mesh_links,
            relay_limit_kib,
            metrics_addr,
            no_metrics,
        } => {
            let net = state.load_network()?;
            let secret = state.load_secret()?;
            let persisted_topology = net.topology.clone().unwrap_or_else(|| "partial".into());
            let persisted_links = net.mesh_links.map(|n| n as usize).unwrap_or(8);
            let persisted_relay_limit = net.relay_limit_kib.unwrap_or(0);
            let persisted_metrics = net
                .metrics_addr
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok());
            let mut opts = run_options(
                dev,
                mtu.unwrap_or(DEFAULT_MTU),
                no_relay,
                no_mdns,
                &bus,
                topology.as_deref().unwrap_or(&persisted_topology),
                mesh_links.unwrap_or(persisted_links),
            )?;
            opts.desired = net.static_addrs();
            opts.relay_limit_kib = relay_limit_kib.unwrap_or(persisted_relay_limit);
            opts.metrics_addr = if no_metrics {
                None
            } else {
                metrics_addr.or(persisted_metrics)
            };
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
            println!("updated   : {} s ago", report.updated_at_unix);
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
    use super::format_bytes;

    #[test]
    fn byte_counts_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }
}
