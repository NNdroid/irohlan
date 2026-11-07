//! Command line interface.

use std::net::Ipv4Addr;

use clap::{ArgAction, Parser, Subcommand};

use crate::bus::BusMode;
use crate::config::{StateDir, StatusReport};
use crate::node::{self, RunOptions};
use crate::tap::DEFAULT_MTU;
use crate::ticket::JoinTicket;

#[derive(Parser)]
#[command(
    name = "irohlan",
    version,
    about = "P2P Layer-2 VPN for Linux built on iroh — a virtual ethernet LAN between your machines",
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
    /// Create a new virtual LAN; this node becomes the creator and IP allocator
    Create {
        /// Virtual subnet in CIDR notation
        #[arg(long, default_value = "10.13.37.0/24")]
        subnet: String,
        /// Network secret (generated and printed when omitted)
        #[arg(long)]
        secret: Option<String>,
        /// TAP device name (e.g. irohlan0 or irohlan%d)
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU
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
    },
    /// Join a virtual LAN using a join ticket from the creator
    Join {
        /// The join ticket printed by `irohlan create`
        ticket: String,
        /// Network secret (the creator printed it next to the ticket)
        #[arg(long)]
        secret: Option<String>,
        /// Request this specific virtual IP
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// TAP device name (e.g. irohlan0 or irohlan%d)
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU
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
    },
    /// Resume the previously created/joined network from local state
    /// (used with systemd or after a reboot)
    Run {
        /// TAP device name override
        #[arg(long)]
        dev: Option<String>,
        /// TAP MTU override
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
        desired_ip: None,
        topology: node::Topology::parse(topology)?,
        mesh_links,
    })
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
            secret,
            dev,
            mtu,
            no_relay,
            no_mdns,
            bus,
            topology,
            mesh_links,
        } => {
            let parsed = node::parse_cidr(&subnet)?;
            let opts = RunOptions {
                desired_ip: None,
                ..run_options(
                    dev,
                    mtu,
                    no_relay,
                    no_mdns,
                    &bus,
                    &topology,
                    mesh_links,
                )?
            };
            node::create_network(&state, parsed, secret, opts).await
        }
        Command::Join {
            ticket,
            secret,
            ip,
            dev,
            mtu,
            no_relay,
            no_mdns,
            bus,
            topology,
            mesh_links,
        } => {
            let ticket = JoinTicket::decode(&ticket)
                .map_err(|e| anyhow::anyhow!("invalid join ticket: {e}"))?;
            let secret = match secret {
                Some(s) => s,
                None => prompt_secret()?,
            };
            let opts = RunOptions {
                desired_ip: ip,
                ..run_options(
                    dev,
                    mtu,
                    no_relay,
                    no_mdns,
                    &bus,
                    &topology,
                    mesh_links,
                )?
            };
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
        } => {
            let net = state.load_network()?;
            let secret = state.load_secret()?;
            let persisted_topology = net.topology.clone().unwrap_or_else(|| "partial".into());
            let persisted_links = net.mesh_links.map(|n| n as usize).unwrap_or(8);
            let mut opts = run_options(
                dev,
                mtu.unwrap_or(DEFAULT_MTU),
                no_relay,
                no_mdns,
                &bus,
                topology.as_deref().unwrap_or(&persisted_topology),
                mesh_links.unwrap_or(persisted_links),
            )?;
            opts.desired_ip = net.static_ip.map(Ipv4Addr::from);
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
                anyhow::bail!(
                    "no status file at {} — is a node running?",
                    path.display()
                );
            }
            let report = StatusReport::read(&path)?;
            println!("updated   : {} s ago", report.updated_at_unix);
            println!("endpoint  : {}", report.endpoint_id.as_deref().unwrap_or("-"));
            println!("device    : {}", report.device.as_deref().unwrap_or("-"));
            println!("ip        : {}", report.ip.as_deref().unwrap_or("-"));
            println!("role      : {}", if report.is_creator { "creator" } else { "member" });
            println!("bus joined: {}", report.gossip_joined);
            println!("peers     : {} connected", report.connected_peers.len());
            for p in &report.connected_peers {
                println!("  - {p}");
            }
            println!(
                "routing   : {} destinations known, {} link-state entries",
                report.routed_destinations, report.lsdb_entries
            );
            println!("members   : {}", report.members.len());
            for m in &report.members {
                println!(
                    "  - {} {} {}",
                    m.hostname,
                    m.ip(),
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
            Ok(())
        }
    }
}
