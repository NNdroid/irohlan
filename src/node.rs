//! Node assembly: brings together TAP, mesh, bus, membership and the
//! creator-side IP allocator, and runs the main lifecycle.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_gossip::Gossip;
use rand::seq::SliceRandom;
use rand::RngCore;
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

use crate::allocator::Allocator;
use crate::bus::{BroadcastBus, BusEvent, BusMode};
use crate::config::{
    hostname, LinkMetricReport, NetworkConfig, RelayPeerReport, RelayReport, RouteReport, StateDir,
    StatusReport,
};
use crate::crypto;
use crate::membership::Membership;
use crate::mesh::{Mesh, MeshChannels, MeshConfig};
use crate::netaddr::{ula_prefix, AddrPlan, V4Net, V6Net, VirtualAddrs};
use crate::proto::{BusMsg, IdBytes, LinkMetric, LinkStateMsg};
use crate::relay::RelayControl;
use crate::routing::{LinkSmoother, RoutingTable, LSA_REFRESH_INTERVAL};
use crate::switch::{Counters, Switch};
use crate::tap::{TapDevice, DEFAULT_MTU};
use crate::ticket::JoinTicket;

/// How often each node announces itself on the broadcast bus.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(20);
/// How often the dialer looks for missing mesh connections.
const DIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Cooldown before re-dialing an endpoint that just failed.
const DIAL_RETRY_COOLDOWN: Duration = Duration::from_secs(30);
/// How often stale members are swept from the table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// How often the status file is written.
const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// How often the relay queues are drained by the fair scheduler.
const RELAY_DRAIN_INTERVAL: Duration = Duration::from_millis(5);
/// Read buffer for the TAP device.
const TAP_BUF_LEN: usize = 65_535;

/// Short, human readable endpoint id for status output.
fn short_id(id: IdBytes) -> String {
    EndpointId::try_from(id)
        .map(|p| p.fmt_short().to_string())
        .unwrap_or_else(|_| id.to_string())
}

/// Mesh topology: how many direct neighbors each node maintains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Topology {
    /// Connect to every member (O(N²) connections, zero-hop unicast).
    Full,
    /// Maintain about `mesh_links` neighbors and relay unicast frames across
    /// multiple hops via link-state routing.
    #[default]
    Partial,
}

impl Topology {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "full" => Ok(Self::Full),
            "partial" => Ok(Self::Partial),
            other => Err(anyhow::anyhow!(
                "unknown topology {other:?}, expected \"full\" or \"partial\""
            )),
        }
    }

    /// Canonical lowercase name, used for persistence and status output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
        }
    }
}

/// How the IPv6 prefix of a new network is chosen.
#[derive(Clone, Debug, Default)]
pub enum V6Choice {
    /// Derive a unique ULA /64 from the network id.
    #[default]
    Auto,
    /// Use a user supplied CIDR, e.g. `fd00:1234::/64`.
    Custom(String),
    /// Disable IPv6 entirely.
    Disabled,
}

/// Address parameters supplied by the CLI when creating a network.
#[derive(Clone, Debug)]
pub struct NetworkSpec {
    /// IPv4 CIDR; `None` disables IPv4.
    pub v4: Option<String>,
    pub v6: V6Choice,
}

impl NetworkSpec {
    /// Resolve the CLI input into a validated address plan.
    pub fn plan(&self, net_id: &[u8; 32]) -> anyhow::Result<AddrPlan> {
        let v4 = self.v4.as_deref().map(V4Net::parse_cidr).transpose()?;
        let v6 = match &self.v6 {
            V6Choice::Auto => Some(ula_prefix(net_id)),
            V6Choice::Custom(s) => Some(V6Net::parse_cidr(s)?),
            V6Choice::Disabled => None,
        };
        let plan = AddrPlan::new(v4, v6);
        plan.validate()?;
        Ok(plan)
    }
}

/// Runtime options shared by `create` and `join`.
#[derive(Clone, Debug)]
pub struct RunOptions {
    /// TAP device name (template or fixed name).
    pub dev: Option<String>,
    /// TAP MTU.
    pub mtu: u16,
    /// Use the n0 public relay infrastructure for NAT traversal fallback.
    pub use_relay: bool,
    /// Enable LAN mDNS discovery.
    pub use_mdns: bool,
    /// Broadcast bus implementation.
    pub bus_mode: BusMode,
    /// Request specific virtual addresses when joining (`--ip` / `--ip6`).
    pub desired: VirtualAddrs,
    /// Mesh topology.
    pub topology: Topology,
    /// Target neighbor count in [`Topology::Partial`] mode.
    pub mesh_links: usize,
    /// Cap relayed traffic in KiB/s; 0 means accounting only, no dropping.
    pub relay_limit_kib: u32,
    /// Optional loopback address for the Prometheus `/metrics` endpoint.
    pub metrics_addr: Option<SocketAddr>,
}

impl RunOptions {
    /// Canonical lowercase topology name for persistence and status output.
    pub fn topology_as_str(&self) -> &'static str {
        self.topology.as_str()
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            dev: None,
            mtu: DEFAULT_MTU,
            use_relay: true,
            use_mdns: true,
            bus_mode: BusMode::Gossip,
            desired: VirtualAddrs::default(),
            topology: Topology::default(),
            mesh_links: 8,
            relay_limit_kib: 0,
            metrics_addr: None,
        }
    }
}

/// Create a new virtual LAN and run the creator node.
///
/// The generated join ticket is printed and stored; `secret` is generated
/// when not provided. Returns once the node shuts down.
pub async fn create_network(
    state: &StateDir,
    spec: NetworkSpec,
    secret: Option<String>,
    opts: RunOptions,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !state.has_network(),
        "this node already belongs to a network ({}); remove it first to create a new one",
        state.network_path().display()
    );

    let secret = secret.unwrap_or_else(crypto::generate_secret);
    let mut net_id = [0u8; 32];
    rand::rng().fill_bytes(&mut net_id);
    let topic = blake3::hash(&[net_id.as_slice(), b"irohlan topic"].concat());
    let plan = spec.plan(&net_id)?;
    plan.offset_of(&opts.desired)
        .map_err(|e| anyhow::anyhow!("invalid requested address: {e}"))?;

    let net = NetworkConfig {
        net_id: IdBytes(net_id),
        v4: plan.v4,
        v6: plan.v6,
        subnet: None,
        prefix: None,
        topic_id: IdBytes(*topic.as_bytes()),
        creator: None,
        is_creator: true,
        // The creator always owns host index 1.
        static_ip: None,
        static_ip6: None,
        topology: Some(opts.topology_as_str().to_string()),
        mesh_links: Some(opts.mesh_links as u32),
        relay_limit_kib: Some(opts.relay_limit_kib),
        metrics_addr: opts.metrics_addr.map(|a| a.to_string()),
    };
    state.save_network(&net)?;
    state.save_secret(&secret)?;

    run_node(state, net, secret, opts).await
}

/// Join an existing virtual LAN using a join ticket, then run the node.
pub async fn join_network(
    state: &StateDir,
    ticket: &JoinTicket,
    secret: String,
    opts: RunOptions,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !state.has_network(),
        "this node already belongs to a network ({}); remove it first to join another",
        state.network_path().display()
    );
    // Fail fast on a wrong passphrase, before touching the network.
    let expected = crypto::ticket_verifier(ticket.net_id.as_bytes(), &secret);
    anyhow::ensure!(
        expected == ticket.verifier,
        "network secret does not match this ticket"
    );

    let plan = ticket.plan();
    plan.offset_of(&opts.desired)
        .map_err(|e| anyhow::anyhow!("invalid requested address: {e}"))?;

    let net = NetworkConfig {
        net_id: ticket.net_id,
        v4: plan.v4,
        v6: plan.v6,
        subnet: None,
        prefix: None,
        topic_id: ticket.topic_id,
        creator: Some(ticket.creator_id),
        is_creator: false,
        static_ip: opts.desired.v4,
        static_ip6: opts.desired.v6,
        topology: Some(opts.topology_as_str().to_string()),
        mesh_links: Some(opts.mesh_links as u32),
        relay_limit_kib: Some(opts.relay_limit_kib),
        metrics_addr: opts.metrics_addr.map(|a| a.to_string()),
    };
    state.save_network(&net)?;
    state.save_secret(&secret)?;
    state.save_ticket(ticket)?;

    run_node(state, net, secret, opts).await
}

/// The main node loop, shared by creator, joiner and `irohlan run`.
pub async fn run_node(
    state: &StateDir,
    net: NetworkConfig,
    secret: String,
    opts: RunOptions,
) -> anyhow::Result<()> {
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let my_hostname = hostname();
    let plan = net.plan();
    plan.validate()?;
    plan.validate_mtu(opts.mtu)?;

    // --- identity & endpoint -------------------------------------------------
    let secret_key = state.load_or_create_identity()?;
    let net_key = crypto::net_key(net.net_id.as_bytes(), &secret);

    let mut ep_builder = if opts.use_relay {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::N0DisableRelay)
    }
    .secret_key(secret_key);
    if opts.use_mdns {
        ep_builder = ep_builder.address_lookup(
            iroh_mdns_address_lookup::MdnsAddressLookup::builder()
                .service_name("irohlan")
                .advertise(true),
        );
    }
    let endpoint = ep_builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    let my_id = endpoint.id();

    // --- control plane state -------------------------------------------------
    let allocator = if net.is_creator {
        Some(Allocator::new(plan, Some(state.leases_path()))?)
    } else {
        None
    };
    let creator_addrs = allocator.as_ref().map(|a| a.creator_addrs());
    let membership = Arc::new(Membership::new());

    let gossip =
        (opts.bus_mode == BusMode::Gossip).then(|| Gossip::builder().spawn(endpoint.clone()));

    let (mesh, channels) = Mesh::new(MeshConfig {
        endpoint: endpoint.clone(),
        net_key,
        is_creator: net.is_creator,
        my_hostname: my_hostname.clone(),
        allocator,
        membership: membership.clone(),
        gossip: gossip.clone(),
    })?;

    let topic_id = iroh_gossip::TopicId::from_bytes(net.topic_id.0);
    let bootstrap: Vec<EndpointId> = match &net.creator {
        Some(c) => vec![EndpointId::try_from(*c).context("stored creator id is not a valid key")?],
        None => Vec::new(),
    };
    let MeshChannels {
        frame_rx,
        flood_rx,
        events,
    } = channels;
    let bus = BroadcastBus::start(
        opts.bus_mode,
        topic_id,
        bootstrap,
        mesh.clone(),
        flood_rx,
        gossip,
    )
    .await?;

    // --- routing -------------------------------------------------------------
    let routing = Arc::new(RwLock::new(RoutingTable::new(IdBytes::from(my_id))));
    let my_mac = crypto::mac_from_id(my_id.as_bytes());

    // Link-state driver: sample the QUIC quality of every direct link (RTT,
    // loss, throughput, bandwidth), smooth it with an EWMA, and publish the
    // weighted adjacency as an LSA whenever the neighbor set changes or the
    // refresh timer fires. Keeping our own links in the local routing table
    // means we can route before any remote LSA has arrived.
    tokio::spawn({
        let mesh = mesh.clone();
        let routing = routing.clone();
        let bus = bus.clone();
        let mut events = events;
        async move {
            let mut lsa_seq: u64 = 0;
            let mut smoother = LinkSmoother::new();
            let mut refresh = interval(LSA_REFRESH_INTERVAL);
            refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = refresh.tick() => {}
                    ev = events.recv() => match ev {
                        Ok(ev) => match ev {
                            crate::mesh::MeshEvent::PeerUp(id) => {
                                tracing::debug!(peer = %id.fmt_short(), "mesh event: peer up");
                            }
                            crate::mesh::MeshEvent::PeerDown(id) => {
                                tracing::debug!(peer = %id.fmt_short(), "mesh event: peer down");
                            }
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::debug!("mesh events lagged by {n}");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                let samples: Vec<LinkMetric> = mesh.neighbor_link_metrics();
                smoother.update(&samples);
                let links = smoother.snapshot();
                routing.write().expect("routing lock").set_my_links(&links);
                lsa_seq += 1;
                bus.publish(BusMsg::LinkState(LinkStateMsg {
                    origin: IdBytes::from(mesh.my_id()),
                    seq: lsa_seq,
                    links,
                }))
                .await;
            }
        }
    });

    // --- TAP device ----------------------------------------------------------
    let mac = crypto::mac_from_id(my_id.as_bytes());
    let tap = Arc::new(
        TapDevice::create(opts.dev.clone(), opts.mtu, mac)
            .await
            .context(
                "failed to create TAP device — this needs root or CAP_NET_ADMIN \
                 (try: sudo setcap cap_net_admin+ep $(readlink -f $(which irohlan)))",
            )?,
    );
    let (from_tap_tx, from_tap_rx) = mpsc::channel::<bytes::Bytes>(1024);
    let (to_tap_tx, mut to_tap_rx) = mpsc::channel::<bytes::Bytes>(1024);
    let counters = Arc::new(Counters::default());
    // One global relay budget for this node, plus a per-peer ledger. Restore
    // cumulative counters so a restart does not reset the traffic history.
    let relay = Arc::new(RelayControl::new(opts.relay_limit_kib));
    match state.load_relay_ledger() {
        Ok(saved) => relay.restore(&saved),
        Err(err) => tracing::warn!("failed to load relay ledger: {err}"),
    }

    // --- virtual addresses ---------------------------------------------------
    let my_addrs: VirtualAddrs = if net.is_creator {
        let addrs = creator_addrs.context("creator must have addresses")?;
        tap.configure(&addrs, &plan)?;
        addrs
    } else {
        let ticket = state
            .load_ticket()
            .context("join ticket missing from state dir")?;
        tracing::info!(creator = %ticket.creator_id, subnets = %ticket.subnet_cidr(), "joining: dialing creator");
        let desired = if opts.desired.is_empty() {
            net.static_addrs()
        } else {
            opts.desired
        };
        let outcome = mesh
            .dial(ticket.creator_addr(), desired)
            .await
            .context("failed to reach the creator; is it online?")?;
        let addrs = outcome.assigned_addrs;
        anyhow::ensure!(
            !addrs.is_empty(),
            "creator did not assign any virtual address"
        );
        tap.configure(&addrs, &plan)?;
        tracing::info!(addresses = %addrs.display(), creator_hostname = %outcome.remote.hostname, "assigned virtual addresses");
        addrs
    };
    mesh.set_my_addrs(my_addrs);

    // --- tasks ---------------------------------------------------------------
    // TAP reader: device -> switch
    tokio::spawn({
        let tap = tap.clone();
        async move {
            let mut buf = vec![0u8; TAP_BUF_LEN];
            loop {
                match tap.recv(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if from_tap_tx
                            .send(bytes::Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!("TAP read failed: {err}");
                        break;
                    }
                }
            }
            tracing::warn!("TAP reader stopped");
        }
    });

    // TAP writer: overlay -> device
    tokio::spawn({
        let tap = tap.clone();
        async move {
            while let Some(frame) = to_tap_rx.recv().await {
                if let Err(err) = tap.send(&frame).await {
                    tracing::debug!("TAP write failed: {err}");
                }
            }
            tracing::warn!("TAP writer stopped");
        }
    });

    // The L2 switch
    let switch = Switch::new(
        my_mac,
        membership.clone(),
        routing.clone(),
        mesh.clone(),
        bus.clone(),
        to_tap_tx,
        counters.clone(),
        relay.clone(),
    );
    let switch_bus_events = bus.subscribe();
    tokio::spawn(switch.run(from_tap_rx, frame_rx, switch_bus_events));

    // Relay queue pump: the switch only enqueues; DRR-selected frames are
    // handed back to the mesh here. Keeping `drain()` free of mesh access
    // leaves the scheduler pure and unit-testable.
    tokio::spawn({
        let relay = relay.clone();
        let mesh = mesh.clone();
        async move {
            let mut tick = interval(RELAY_DRAIN_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                for out in relay.drain() {
                    match EndpointId::try_from(out.to) {
                        Ok(id) => mesh.send_unicast(&id, out.hop, out.frame),
                        Err(err) => {
                            tracing::debug!("queued relay frame has invalid next hop: {err}")
                        }
                    }
                }
            }
        }
    });

    // One renderer shared by metrics.prom and the optional HTTP endpoint.
    // It reads live state on every scrape rather than caching a snapshot.
    let render_metrics: Arc<dyn Fn() -> String + Send + Sync> = Arc::new({
        let relay = relay.clone();
        let routing = routing.clone();
        let counters = counters.clone();
        move || {
            let (from_tap, to_tap, dropped) = counters.snapshot();
            let (links, routes) = {
                let rt = routing.read().expect("routing lock");
                (rt.my_link_metrics(), rt.routes())
            };
            let relay_snapshot = relay.snapshot();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            crate::metrics::render(&crate::metrics::MetricsInput {
                relay: &relay_snapshot,
                links: &links,
                routes: &routes,
                frames_from_tap: from_tap,
                frames_to_tap: to_tap,
                frames_dropped: dropped,
                started_at_unix: started_at,
                updated_at_unix: now,
            })
        }
    });
    let metrics_addr_label = opts.metrics_addr.map(|a| a.to_string());
    if let Some(addr) = opts.metrics_addr {
        tokio::spawn({
            let render = render_metrics.clone();
            async move {
                if let Err(err) = crate::metrics::serve(addr, render).await {
                    tracing::error!("metrics endpoint failed: {err:#}");
                }
            }
        });
    }

    // Node-level bus consumer: membership announcements, link-state
    // advertisements and gossip neighbor state
    let gossip_joined = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let membership = membership.clone();
        let gossip_joined = gossip_joined.clone();
        let routing = routing.clone();
        let my_id_bytes = *my_id.as_bytes();
        let mut events = bus.subscribe();
        async move {
            loop {
                match events.recv().await {
                    Ok(BusEvent::Announce(record)) => {
                        if record.id.as_bytes() == &my_id_bytes {
                            continue;
                        }
                        if membership.upsert(record.clone()) {
                            let mac =
                                crypto::format_mac(&crypto::mac_from_id(record.id.as_bytes()));
                            tracing::info!(
                                peer = %record.id,
                                addresses = %record.display_addrs(),
                                hostname = %record.hostname,
                                mac = %mac,
                                "member announced"
                            );
                        }
                    }
                    Ok(BusEvent::LinkState(ls)) => {
                        if routing
                            .write()
                            .expect("routing lock")
                            .apply(ls.origin, ls.seq, ls.links)
                        {
                            tracing::debug!("routing table updated from link-state advertisement");
                        }
                    }
                    Ok(BusEvent::NeighborUp(id)) => {
                        gossip_joined.store(true, Ordering::Relaxed);
                        tracing::debug!(peer = %id.fmt_short(), "bus neighbor up");
                    }
                    Ok(BusEvent::NeighborDown(id)) => {
                        tracing::debug!(peer = %id.fmt_short(), "bus neighbor down");
                    }
                    Ok(BusEvent::Frame(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("node fell behind the bus by {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    });

    // Periodic self-announcement
    tokio::spawn({
        let bus = bus.clone();
        let mesh = mesh.clone();
        async move {
            let mut tick = interval(ANNOUNCE_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                bus.publish(BusMsg::Announce(mesh.my_record())).await;
            }
        }
    });

    // Mesh dialer: keep the neighbor set stocked according to the topology.
    tokio::spawn({
        let mesh = mesh.clone();
        let membership = membership.clone();
        let creator = net.creator;
        let topology = opts.topology;
        let mesh_links = opts.mesh_links;
        async move {
            let my_bytes = *mesh.my_id().as_bytes();
            let mut failures: HashMap<EndpointId, Instant> = HashMap::new();
            let mut tick = interval(DIAL_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                failures.retain(|_, t| t.elapsed() < DIAL_RETRY_COOLDOWN);

                match topology {
                    Topology::Full => {
                        // Dial everyone we are not connected to yet.
                        for member in membership.all() {
                            let Ok(peer) = EndpointId::try_from(member.record.id) else {
                                continue;
                            };
                            if *peer.as_bytes() == my_bytes || mesh.is_connected(&peer) {
                                continue;
                            }
                            if failures.contains_key(&peer) {
                                continue;
                            }
                            match mesh
                                .dial(EndpointAddr::new(peer), VirtualAddrs::default())
                                .await
                            {
                                Ok(_) => {
                                    failures.remove(&peer);
                                    tracing::info!(peer = %peer.fmt_short(), "mesh connected");
                                }
                                Err(err) => {
                                    failures.insert(peer, Instant::now());
                                    tracing::debug!(peer = %peer.fmt_short(), "dial failed: {err:#}");
                                }
                            }
                        }
                    }
                    Topology::Partial => {
                        // Maintain ~mesh_links neighbors: dial half of the
                        // shortfall ourselves, expect the rest to dial us.
                        // The creator is always kept as an anchor link (it is
                        // the rendezvous point and typically always online).
                        let connected = mesh.connected_peers();
                        if connected.len() >= mesh_links {
                            continue;
                        }
                        let want = (mesh_links - connected.len()).div_ceil(2);
                        let connected_ids: HashSet<IdBytes> =
                            connected.iter().map(|p| IdBytes::from(*p)).collect();
                        let failed: HashSet<IdBytes> =
                            failures.keys().map(|k| IdBytes::from(*k)).collect();
                        let my_id_bytes = IdBytes::from(mesh.my_id());

                        let mut picks: Vec<IdBytes> = Vec::new();
                        if let Some(creator) = creator {
                            if my_id_bytes != creator
                                && !connected_ids.contains(&creator)
                                && !failed.contains(&creator)
                            {
                                picks.push(creator);
                            }
                        }

                        let mut candidates: Vec<IdBytes> = membership
                            .all()
                            .into_iter()
                            .map(|m| m.record.id)
                            .filter(|id| {
                                *id != my_id_bytes
                                    && !connected_ids.contains(id)
                                    && !picks.contains(id)
                                    && !failed.contains(id)
                            })
                            .collect();
                        let remaining = want.saturating_sub(picks.len());
                        if remaining > 0 && candidates.len() > remaining {
                            candidates.shuffle(&mut rand::rng());
                            candidates.truncate(remaining);
                        }
                        picks.extend(candidates);

                        for pick in picks {
                            let Ok(peer) = EndpointId::try_from(pick) else {
                                continue;
                            };
                            match mesh
                                .dial(EndpointAddr::new(peer), VirtualAddrs::default())
                                .await
                            {
                                Ok(_) => {
                                    failures.remove(&peer);
                                    tracing::info!(peer = %peer.fmt_short(), "mesh connected");
                                }
                                Err(err) => {
                                    failures.insert(peer, Instant::now());
                                    tracing::debug!(peer = %peer.fmt_short(), "dial failed: {err:#}");
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Membership & routing sweeper
    tokio::spawn({
        let membership = membership.clone();
        let routing = routing.clone();
        async move {
            let mut tick = interval(SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                for record in membership.expire() {
                    tracing::info!(peer = %record.id, "member expired");
                }
                if routing.write().expect("routing lock").expire() {
                    tracing::debug!("stale link-state advertisements expired");
                }
            }
        }
    });

    // Status file writer
    tokio::spawn({
        let state = state.clone();
        let mesh = mesh.clone();
        let membership = membership.clone();
        let routing = routing.clone();
        let counters = counters.clone();
        let relay = relay.clone();
        let gossip_joined = gossip_joined.clone();
        let render = render_metrics.clone();
        let metrics_addr_label = metrics_addr_label.clone();
        let device_name = tap.name().to_string();
        async move {
            let mut tick = interval(STATUS_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let (from_tap, to_tap, dropped) = counters.snapshot();
                let relay_snapshot = relay.snapshot();
                let (routed, lsdb, link_metrics, routes) = {
                    let rt = routing.read().expect("routing lock");
                    (
                        rt.known_destinations(),
                        rt.lsdb_size(),
                        rt.my_link_metrics(),
                        rt.routes(),
                    )
                };
                let report = StatusReport {
                    endpoint_id: Some(mesh.my_id().to_string()),
                    device: Some(device_name.clone()),
                    ip: mesh.my_record().ipv4().map(|a| a.to_string()),
                    ip6: mesh.my_record().ipv6().map(|a| a.to_string()),
                    subnets: Some(plan.describe()),
                    is_creator: mesh.is_creator(),
                    started_at_unix: Some(started_at),
                    updated_at_unix: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    gossip_joined: gossip_joined.load(Ordering::Relaxed),
                    connected_peers: mesh
                        .connected_peers()
                        .iter()
                        .map(|p| p.fmt_short().to_string())
                        .collect(),
                    members: membership.all().into_iter().map(|m| m.record).collect(),
                    frames_from_tap: from_tap,
                    frames_to_tap: to_tap,
                    frames_dropped: dropped,
                    frames_relayed: relay_snapshot.relayed_frames,
                    routed_destinations: routed,
                    lsdb_entries: lsdb,
                    link_metrics: link_metrics
                        .iter()
                        .map(|m| LinkMetricReport {
                            peer: short_id(m.neighbor),
                            rtt_ms: m.rtt_ms,
                            loss_permille: m.loss_permille,
                            tx_kbps: m.tx_kbps,
                            bw_kbps: m.bw_kbps,
                        })
                        .collect(),
                    routes: routes
                        .iter()
                        .map(|(dest, hop, cost)| RouteReport {
                            dest: short_id(*dest),
                            next_hop: short_id(*hop),
                            cost: *cost,
                        })
                        .collect(),
                    relay: RelayReport {
                        limit_kib_per_sec: relay_snapshot.limit_kib_per_sec,
                        active_peers: relay_snapshot.active_peers,
                        active_flows: relay_snapshot.active_flows,
                        per_peer_kib_per_sec: relay_snapshot.per_peer_kib_per_sec,
                        relayed_frames: relay_snapshot.relayed_frames,
                        relayed_bytes: relay_snapshot.relayed_bytes,
                        limited_frames: relay_snapshot.limited_frames,
                        limited_bytes: relay_snapshot.limited_bytes,
                        codel_frames: relay_snapshot.codel_frames,
                        codel_bytes: relay_snapshot.codel_bytes,
                        queued_frames: relay_snapshot.queued_frames,
                        queued_bytes: relay_snapshot.queued_bytes,
                        peers: relay_snapshot
                            .peers
                            .iter()
                            .map(|(id, stats)| RelayPeerReport {
                                peer: short_id(*id),
                                in_frames: stats.in_frames,
                                in_bytes: stats.in_bytes,
                                out_frames: stats.out_frames,
                                out_bytes: stats.out_bytes,
                                limited_frames: stats.limited_frames,
                                limited_bytes: stats.limited_bytes,
                                codel_frames: stats.codel_frames,
                                codel_bytes: stats.codel_bytes,
                                queued_frames: stats.queued_frames,
                                queued_bytes: stats.queued_bytes,
                            })
                            .collect(),
                    },
                    metrics_addr: metrics_addr_label.clone(),
                };
                if let Err(err) = report.write(&state.status_path()) {
                    tracing::debug!("failed to write status: {err}");
                }
                // Cumulative counters and the text exposition live in their
                // own files so a reader never sees a partially written blob.
                if let Err(err) = state.save_relay_ledger(&relay.ledger()) {
                    tracing::debug!("failed to persist relay ledger: {err}");
                }
                if let Err(err) = state.write_metrics(&render()) {
                    tracing::debug!("failed to write metrics.prom: {err}");
                }
            }
        }
    });

    // --- banner & run --------------------------------------------------------
    let ticket_hint = if net.is_creator {
        format!("join ticket stored at {}", state.ticket_path().display())
    } else {
        "joined via ticket".to_string()
    };
    println!("irohlan node running");
    println!("  endpoint  : {}", my_id);
    println!("  identity  : {}", my_id.fmt_short());
    println!("  addresses : {}", my_addrs.display());
    println!("  subnets   : {}", plan.describe());
    println!(
        "  device    : {} (mtu {}, mac {})",
        tap.name(),
        opts.mtu,
        crypto::format_mac(&crypto::mac_from_id(my_id.as_bytes()))
    );
    println!(
        "  role      : {}",
        if net.is_creator { "creator" } else { "member" }
    );
    println!("  bus       : {:?}", opts.bus_mode);
    println!(
        "  topology : {} (links {})",
        opts.topology.as_str(),
        opts.mesh_links
    );
    println!(
        "  relay    : {}",
        if relay.limit_kib_per_sec() == 0 {
            "accounting only (no limit)".to_string()
        } else {
            format!(
                "{} KiB/s total, split across active peers",
                relay.limit_kib_per_sec()
            )
        }
    );
    if let Some(addr) = opts.metrics_addr {
        println!("  metrics  : http://{addr}/metrics (loopback only; metrics.prom in state dir)");
    }
    println!("  {ticket_hint}");

    // If we are the creator, print the ticket once (it was built below).
    if net.is_creator {
        let ticket = build_creator_ticket(&net, &endpoint, &secret)?;
        state.save_ticket(&ticket)?;
        println!();
        println!("network secret: {secret}");
        println!("join ticket   :");
        println!("{}", ticket.encode()?);
    }

    // Wait for shutdown.
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    // The status writer is an infinite task; flush the final totals before
    // the runtime tears it down (Ctrl-C / SIGTERM via systemd).
    if let Err(err) = state.save_relay_ledger(&relay.ledger()) {
        tracing::debug!("failed to persist relay ledger on shutdown: {err}");
    }
    bus.publish(BusMsg::Announce(mesh.my_record())).await; // best-effort final announce
    mesh.shutdown().await;
    endpoint.close().await;
    Ok(())
}

/// Build the join ticket for the network (creator only).
fn build_creator_ticket(
    net: &NetworkConfig,
    endpoint: &Endpoint,
    secret: &str,
) -> anyhow::Result<JoinTicket> {
    let addr = endpoint.addr();
    let mut creator_relay = None;
    let mut creator_direct = Vec::new();
    for t in addr.addrs.iter() {
        match t {
            iroh::TransportAddr::Relay(url) => creator_relay = Some(url.to_string()),
            iroh::TransportAddr::Ip(sock) => creator_direct.push(*sock),
            _ => {}
        }
    }
    let plan = net.plan();
    Ok(JoinTicket {
        version: crate::ticket::TICKET_VERSION,
        net_id: net.net_id,
        v4: plan.v4,
        v6: plan.v6,
        topic_id: net.topic_id,
        creator_id: IdBytes::from(endpoint.id()),
        creator_relay,
        creator_direct,
        verifier: crypto::ticket_verifier(net.net_id.as_bytes(), secret),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netaddr::DEFAULT_V4_CIDR;

    fn plan(v4: Option<&str>, v6: V6Choice) -> anyhow::Result<AddrPlan> {
        NetworkSpec {
            v4: v4.map(str::to_string),
            v6,
        }
        .plan(&[1; 32])
    }

    #[test]
    fn default_spec_builds_a_dual_stack_plan() {
        let p = plan(Some(DEFAULT_V4_CIDR), V6Choice::Auto).unwrap();
        assert_eq!(p.v4.unwrap().cidr(), DEFAULT_V4_CIDR);
        assert_eq!(p.v6.unwrap(), ula_prefix(&[1; 32]));
        assert_eq!(p.v6.unwrap().prefix, 64);
    }

    #[test]
    fn both_single_stack_modes_are_supported() {
        let v6_only = plan(None, V6Choice::Auto).unwrap();
        assert!(v6_only.v4.is_none() && v6_only.v6.is_some());

        let v4_only = plan(Some("192.168.50.7/24"), V6Choice::Disabled).unwrap();
        assert_eq!(v4_only.v4.unwrap().cidr(), "192.168.50.0/24");
        assert!(v4_only.v6.is_none());
    }

    #[test]
    fn disabling_both_families_is_rejected() {
        assert!(plan(None, V6Choice::Disabled).is_err());
    }

    #[test]
    fn custom_v6_cidr_is_normalized_and_validated() {
        let p = plan(
            Some(DEFAULT_V4_CIDR),
            V6Choice::Custom("fd12:3456:789a::99/64".into()),
        )
        .unwrap();
        assert_eq!(p.v6.unwrap().cidr(), "fd12:3456:789a::/64");
        assert!(plan(Some(DEFAULT_V4_CIDR), V6Choice::Custom("fd00::/120".into())).is_err());
        assert!(plan(Some("10.13.37.0/31"), V6Choice::Disabled).is_err());
    }
}
