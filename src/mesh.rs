//! Mesh data plane: one iroh (QUIC) connection between every pair of
//! members, carrying unicast ethernet frames plus the control handshake.
//!
//! Channel layout per connection:
//! * **datagrams** — hot path; payload prefixed with a [`tag`] byte.
//!   `FRAME` = raw ethernet frame, `FLOOD` = postcard-encoded
//!   [`FloodEnvelope`].
//! * **uni-directional streams** — overflow path for payloads that do not fit
//!   into a datagram (same tag byte as datagrams).
//! * **bi-directional streams** — the first one carries the auth handshake
//!   (length-prefixed [`CtrlMsg`]), later ones carry control requests
//!   (`RequestIp` …), also length-prefixed.
//!
//! Authorization: the QUIC/TLS layer authenticates the peer's EndpointId.
//! On top of that, both sides must prove knowledge of the network key
//! (passphrase) before the connection is registered for data forwarding.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use iroh::endpoint::Connection;
use iroh::endpoint::VarInt;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

use crate::allocator::Allocator;
use crate::crypto;
use crate::membership::Membership;
use crate::netaddr::VirtualAddrs;
use crate::proto::{
    lenframe, tag, CtrlMsg, FloodEnvelope, IdBytes, LinkMetric, MemberRecord, MAX_STREAM_MSG_LEN,
};
use crate::routing::{ewma, MAX_RTT_MS, UNKNOWN_RTT_MS};

/// Timeout for the auth handshake on a new connection.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an endpoint that failed authentication stays banned.
const BAN_TTL: Duration = Duration::from_secs(60);
/// Bound on frames queued per peer (lossy on overflow, TCP recovers).
const OUT_QUEUE_CAP: usize = 1024;
/// Bound on events emitted to node-level subscribers.
const EVENT_CAP: usize = 64;

/// Events emitted when mesh connections come and go.
#[derive(Clone, Copy, Debug)]
pub enum MeshEvent {
    PeerUp(EndpointId),
    PeerDown(EndpointId),
}

/// Result of dialing a peer.
#[derive(Debug)]
pub struct DialOutcome {
    pub remote: MemberRecord,
    /// Addresses assigned to us when the remote is the network creator.
    pub assigned_addrs: VirtualAddrs,
}

/// A unicast frame received from a peer, with its remaining hop budget.
///
/// The switch delivers frames addressed to us to the TAP and relays the rest
/// (partial-mesh multi-hop forwarding, see [`crate::routing`]). `from` is the
/// authenticated QUIC peer that sent the frame (the previous hop, not
/// necessarily the original source); the switch uses it for relay accounting.
/// It comes from the connection itself, so the wire format is unchanged.
#[derive(Debug)]
pub struct InboundFrame {
    pub from: EndpointId,
    pub hop: u8,
    pub frame: Bytes,
}

enum OutMsg {
    Frame {
        hop: u8,
        frame: Bytes,
    },
    /// Tagged payload ready for the wire (datagram or stream).
    Tagged(Vec<u8>),
}

struct PeerHandle {
    conn: Connection,
    stable_id: usize,
    out_tx: mpsc::Sender<OutMsg>,
}

/// Cumulative QUIC counters from the previous link-quality sample. Loss and
/// throughput are derived by differencing these between LSA refreshes.
#[derive(Clone, Copy, Debug)]
struct LinkSample {
    at: Instant,
    sent_packets: u64,
    lost_packets: u64,
    sent_bytes: u64,
    loss_permille: u32,
    tx_kbps: u32,
}

/// State shared between the router handler, the pumps and [`Mesh`].
struct Shared {
    endpoint: Endpoint,
    net_key: [u8; 32],
    is_creator: bool,
    my_id: EndpointId,
    my_hostname: String,
    my_addrs: RwLock<VirtualAddrs>,
    /// Creator-only lease allocator.
    allocator: Option<tokio::sync::Mutex<Allocator>>,
    membership: Arc<Membership>,
    peers: Mutex<HashMap<EndpointId, Vec<Arc<PeerHandle>>>>,
    /// Previous QUIC counter snapshot per peer for windowed loss/throughput.
    link_samples: Mutex<HashMap<EndpointId, LinkSample>>,
    bans: Mutex<HashMap<EndpointId, Instant>>,
    /// Unicast frames received from remote peers (with hop budget).
    frame_tx: mpsc::Sender<InboundFrame>,
    /// Flood envelopes received from remote peers (flood bus input).
    flood_tx: mpsc::Sender<(EndpointId, FloodEnvelope)>,
    event_tx: broadcast::Sender<MeshEvent>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("is_creator", &self.is_creator)
            .field("my_id", &self.my_id.fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn banned(&self, id: &EndpointId) -> bool {
        let mut bans = self.bans.lock().expect("bans lock");
        match bans.get(id) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                bans.remove(id);
                false
            }
            None => false,
        }
    }

    fn ban(&self, id: &EndpointId) {
        self.bans
            .lock()
            .expect("bans lock")
            .insert(*id, Instant::now() + BAN_TTL);
    }

    /// Send a tagged payload to all peers except `exclude`.
    fn flood_out(&self, tagged: &[u8], exclude: Option<EndpointId>) {
        let peers = self.peers.lock().expect("peers lock");
        for (id, handles) in peers.iter() {
            if Some(*id) == exclude {
                continue;
            }
            for handle in handles {
                let _ = handle.out_tx.try_send(OutMsg::Tagged(tagged.to_vec()));
            }
        }
    }

    fn push_frame(&self, id: &EndpointId, hop: u8, frame: Bytes) {
        let peers = self.peers.lock().expect("peers lock");
        if let Some(handles) = peers.get(id) {
            if let Some(handle) = handles.first() {
                if handle
                    .out_tx
                    .try_send(OutMsg::Frame { hop, frame })
                    .is_err()
                {
                    tracing::debug!(peer = %id.fmt_short(), "outbound queue full, frame dropped");
                }
            }
        }
    }

    fn remove_handle(&self, remote: &EndpointId, stable_id: usize) {
        let mut peers = self.peers.lock().expect("peers lock");
        if let Some(handles) = peers.get_mut(remote) {
            handles.retain(|h| h.stable_id != stable_id);
            if handles.is_empty() {
                peers.remove(remote);
            }
        }
    }
}

/// Router protocol handler (responder side of every connection).
#[derive(Debug)]
struct Handler {
    shared: Arc<Shared>,
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        if self.shared.banned(&remote) {
            tracing::warn!(peer = %remote.fmt_short(), "banned peer, rejecting");
            conn.close(VarInt::from(1u8), b"banned");
            return Ok(());
        }

        // Responder side of the auth handshake.
        let outcome = timeout(AUTH_TIMEOUT, auth_responder(&self.shared, &conn)).await;
        let remote_record = match outcome {
            Ok(Ok(record)) => record,
            Ok(Err(err)) => {
                tracing::warn!(peer = %remote.fmt_short(), "auth failed: {err:#}");
                if auth_failed(&err) {
                    self.shared.ban(&remote);
                }
                conn.close(VarInt::from(2u8), b"auth failed");
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(peer = %remote.fmt_short(), "auth timed out");
                conn.close(VarInt::from(3u8), b"auth timeout");
                return Ok(());
            }
        };

        register_conn(&self.shared, conn.clone());
        self.shared.membership.upsert(remote_record);
        let _ = self.shared.event_tx.send(MeshEvent::PeerUp(remote));

        // Serve control requests on additional bi-streams until closed.
        ctrl_loop(&self.shared, &conn).await;
        self.shared.remove_handle(&remote, conn.stable_id());
        let _ = self.shared.event_tx.send(MeshEvent::PeerDown(remote));
        Ok(())
    }
}

fn auth_failed(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AuthError>().is_some()
}

#[derive(Debug, thiserror::Error)]
#[error("authentication failed")]
struct AuthError;

impl AuthError {
    fn fail() -> anyhow::Error {
        anyhow::Error::new(AuthError)
    }
}

/// Our own member record, used in handshakes and periodic announcements.
fn my_record(shared: &Shared) -> MemberRecord {
    MemberRecord {
        id: IdBytes::from(shared.my_id),
        addrs: *shared.my_addrs.read().expect("my_addrs lock"),
        hostname: shared.my_hostname.clone(),
    }
}

/// Responder half of the auth handshake. Returns the initiator's member
/// record so the caller can register it.
async fn auth_responder(shared: &Shared, conn: &Connection) -> anyhow::Result<MemberRecord> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let raw = lenframe::read(&mut recv).await?;
    let CtrlMsg::AuthHello {
        nonce,
        proof,
        desired,
        my_addrs: remote_addrs,
        hostname,
    } = postcard::from_bytes(&raw)?
    else {
        return Err(anyhow::anyhow!("first message was not AuthHello"));
    };

    let remote = conn.remote_id();
    let expected = crypto::auth_proof(
        &shared.net_key,
        &IdBytes::from(remote),
        &IdBytes::from(shared.my_id),
        &nonce,
        crypto::ROLE_INITIATOR,
    );
    if expected != proof {
        return Err(AuthError::fail());
    }

    // The creator assigns (or confirms) the joiner's virtual addresses.
    let assigned = if shared.is_creator {
        let mut alloc = shared
            .allocator
            .as_ref()
            .expect("creator has an allocator")
            .lock()
            .await;
        match alloc.assign(IdBytes::from(remote), &hostname, desired) {
            Ok(addrs) => addrs,
            Err(reason) => {
                let reply = CtrlMsg::AuthReject { reason };
                lenframe::write(&mut send, &postcard::to_allocvec(&reply)?).await?;
                send.finish().ok();
                return Err(anyhow::anyhow!("address allocation refused"));
            }
        }
    } else {
        VirtualAddrs::default()
    };

    let reply_nonce = crypto::nonce();
    let reply_proof = crypto::auth_proof(
        &shared.net_key,
        &IdBytes::from(remote),
        &IdBytes::from(shared.my_id),
        &reply_nonce,
        crypto::ROLE_RESPONDER,
    );
    let reply = CtrlMsg::AuthAccept {
        nonce: reply_nonce,
        proof: reply_proof,
        assigned,
        record: my_record(shared),
    };
    lenframe::write(&mut send, &postcard::to_allocvec(&reply)?).await?;
    send.finish().ok();

    let effective = if assigned.is_empty() {
        remote_addrs
    } else {
        assigned
    };
    Ok(MemberRecord {
        id: IdBytes::from(remote),
        addrs: effective,
        hostname,
    })
}

/// Initiator half of the auth handshake (called from [`Mesh::dial`]).
async fn auth_initiator(
    shared: &Shared,
    conn: &Connection,
    desired: VirtualAddrs,
) -> anyhow::Result<(MemberRecord, VirtualAddrs)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let nonce = crypto::nonce();
    let proof = crypto::auth_proof(
        &shared.net_key,
        &IdBytes::from(shared.my_id),
        &IdBytes::from(conn.remote_id()),
        &nonce,
        crypto::ROLE_INITIATOR,
    );
    let hello = CtrlMsg::AuthHello {
        nonce,
        proof,
        desired,
        my_addrs: *shared.my_addrs.read().expect("my_addrs lock"),
        hostname: shared.my_hostname.clone(),
    };
    lenframe::write(&mut send, &postcard::to_allocvec(&hello)?).await?;
    send.finish().ok();

    let raw = timeout(AUTH_TIMEOUT, lenframe::read(&mut recv)).await??;
    match postcard::from_bytes::<CtrlMsg>(&raw)? {
        CtrlMsg::AuthAccept {
            nonce,
            proof,
            assigned,
            record,
        } => {
            let expected = crypto::auth_proof(
                &shared.net_key,
                &IdBytes::from(shared.my_id),
                &IdBytes::from(conn.remote_id()),
                &nonce,
                crypto::ROLE_RESPONDER,
            );
            if expected != proof {
                return Err(AuthError::fail());
            }
            Ok((record, assigned))
        }
        CtrlMsg::AuthReject { reason } => Err(anyhow::anyhow!("rejected: {reason}")),
        other => Err(anyhow::anyhow!("unexpected auth reply: {other:?}")),
    }
}

/// Serve control requests on incoming bi-streams until the conn closes.
async fn ctrl_loop(shared: &Shared, conn: &Connection) {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let remote = conn.remote_id();
        let outcome = async {
            let raw = timeout(AUTH_TIMEOUT, lenframe::read(&mut recv)).await??;
            let msg: CtrlMsg = postcard::from_bytes(&raw)?;
            let reply = handle_ctrl(shared, remote, msg).await;
            lenframe::write(&mut send, &postcard::to_allocvec(&reply)?).await?;
            send.finish().ok();
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(err) = outcome {
            tracing::debug!(peer = %remote.fmt_short(), "ctrl stream ended: {err:#}");
        }
    }
}

async fn handle_ctrl(shared: &Shared, remote: EndpointId, msg: CtrlMsg) -> CtrlMsg {
    match msg {
        CtrlMsg::RequestIp { desired } if shared.is_creator => {
            let hostname = shared
                .membership
                .get(&IdBytes::from(remote))
                .map(|m| m.record.hostname)
                .unwrap_or_else(|| "unknown".to_string());
            let mut alloc = shared
                .allocator
                .as_ref()
                .expect("creator has an allocator")
                .lock()
                .await;
            match alloc.assign(IdBytes::from(remote), &hostname, desired) {
                Ok(addrs) => CtrlMsg::AssignIp { addrs },
                Err(reason) => CtrlMsg::RejectIp { reason },
            }
        }
        other => CtrlMsg::RejectIp {
            reason: format!("unsupported request: {other:?}"),
        },
    }
}

/// Attach the connection to the mesh: spawn the outbound and inbound pumps
/// and the close watcher.
fn register_conn(shared: &Arc<Shared>, conn: Connection) {
    let remote = conn.remote_id();
    let stable_id = conn.stable_id();

    let (out_tx, out_rx) = mpsc::channel::<OutMsg>(OUT_QUEUE_CAP);
    let handle = Arc::new(PeerHandle {
        conn: conn.clone(),
        stable_id,
        out_tx,
    });

    shared
        .peers
        .lock()
        .expect("peers lock")
        .entry(remote)
        .or_default()
        .push(handle.clone());

    tokio::spawn(outbound_pump(handle.clone(), out_rx));
    tokio::spawn(inbound_pump(shared.clone(), handle.clone()));
    tokio::spawn(close_watcher(shared.clone(), handle, remote));
    tracing::debug!(peer = %remote.fmt_short(), "peer connected");
}

async fn close_watcher(shared: Arc<Shared>, handle: Arc<PeerHandle>, remote: EndpointId) {
    let _ = handle.conn.closed().await;
    shared.remove_handle(&remote, handle.stable_id);
    tracing::debug!(peer = %remote.fmt_short(), "peer disconnected");
}

async fn outbound_pump(handle: Arc<PeerHandle>, mut out_rx: mpsc::Receiver<OutMsg>) {
    let max_dgram = handle.conn.max_datagram_size().unwrap_or(0);
    loop {
        let msg = tokio::select! {
            msg = out_rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
            _ = handle.conn.closed() => break,
        };
        let result = match msg {
            OutMsg::Frame { hop, frame } => {
                // Wire shape: [tag][hop][frame…]
                let mut payload = BytesMut::with_capacity(frame.len() + 1);
                payload.extend_from_slice(&[hop]);
                payload.extend_from_slice(&frame);
                send_payload(&handle, tag::FRAME, payload.freeze(), max_dgram).await
            }
            OutMsg::Tagged(payload) => {
                let (t, rest) = payload.split_first().expect("tagged payload has tag");
                send_payload(&handle, *t, Bytes::copy_from_slice(rest), max_dgram).await
            }
        };
        if let Err(err) = result {
            tracing::debug!("send failed: {err:#}");
            break;
        }
    }
}

/// Send a tagged payload: datagram when it fits, uni-stream otherwise.
async fn send_payload(
    handle: &PeerHandle,
    tag_byte: u8,
    payload: Bytes,
    max_dgram: usize,
) -> anyhow::Result<()> {
    if max_dgram > 0 && payload.len() < max_dgram {
        let mut datagram = BytesMut::with_capacity(payload.len() + 1);
        datagram.extend_from_slice(&[tag_byte]);
        datagram.extend_from_slice(&payload);
        handle.conn.send_datagram_wait(datagram.freeze()).await?;
        return Ok(());
    }
    // Overflow path: one uni-directional stream per payload.
    let mut send = handle.conn.open_uni().await?;
    send.write_all(&[tag_byte]).await?;
    send.write_all(&payload).await?;
    send.finish().ok();
    Ok(())
}

async fn inbound_pump(shared: Arc<Shared>, handle: Arc<PeerHandle>) {
    let conn = handle.conn.clone();
    loop {
        tokio::select! {
            dg = conn.read_datagram() => {
                match dg {
                    Ok(data) => ingest_tagged(&shared, &conn.remote_id(), &data),
                    Err(_) => break,
                }
            }
            uni = conn.accept_uni() => {
                match uni {
                    Ok(mut recv) => match recv.read_to_end(MAX_STREAM_MSG_LEN).await {
                        Ok(data) => ingest_tagged(&shared, &conn.remote_id(), &data),
                        Err(err) => {
                            tracing::debug!("uni stream read failed: {err}");
                            continue;
                        }
                    },
                    Err(_) => break,
                }
            }
            _ = handle.conn.closed() => break,
        }
    }
}

fn ingest_tagged(shared: &Shared, from: &EndpointId, data: &[u8]) {
    let Some((tag_byte, rest)) = data.split_first() else {
        return;
    };
    match *tag_byte {
        tag::FRAME => {
            // Payload shape: [hop: u8][frame…]
            let Some((&hop, frame)) = rest.split_first() else {
                return;
            };
            let _ = shared.frame_tx.try_send(InboundFrame {
                from: *from,
                hop,
                frame: Bytes::copy_from_slice(frame),
            });
        }
        tag::FLOOD => match postcard::from_bytes::<FloodEnvelope>(rest) {
            Ok(envelope) => {
                let _ = shared.flood_tx.try_send((*from, envelope));
            }
            Err(err) => tracing::debug!("bad flood message: {err}"),
        },
        other => tracing::trace!("unknown payload tag {other}"),
    }
}

/// Everything the node needs to consume from the mesh.
pub struct MeshChannels {
    /// Unicast frames received from peers.
    pub frame_rx: mpsc::Receiver<InboundFrame>,
    /// Flood envelopes received from peers.
    pub flood_rx: mpsc::Receiver<(EndpointId, FloodEnvelope)>,
    /// Peer up/down events.
    pub events: broadcast::Receiver<MeshEvent>,
}

/// Builder-style construction input.
pub struct MeshConfig {
    pub endpoint: Endpoint,
    pub net_key: [u8; 32],
    pub is_creator: bool,
    pub my_hostname: String,
    pub allocator: Option<Allocator>,
    pub membership: Arc<Membership>,
    /// The iroh-gossip handle; registered on our router under the gossip
    /// ALPN so peers can reach us for the broadcast protocol.
    pub gossip: Option<iroh_gossip::Gossip>,
}

/// The mesh: owns the router, the connection registry and the pumps.
pub struct Mesh {
    shared: Arc<Shared>,
    router: Router,
    seq: AtomicU64,
}

impl Mesh {
    /// Build the mesh and spawn its router.
    pub fn new(cfg: MeshConfig) -> anyhow::Result<(Arc<Mesh>, MeshChannels)> {
        let (frame_tx, frame_rx) = mpsc::channel(1024);
        let (flood_tx, flood_rx) = mpsc::channel(1024);
        let (event_tx, events) = broadcast::channel(EVENT_CAP);

        let my_id = cfg.endpoint.id();
        let shared = Arc::new(Shared {
            endpoint: cfg.endpoint.clone(),
            net_key: cfg.net_key,
            is_creator: cfg.is_creator,
            my_id,
            my_hostname: cfg.my_hostname,
            my_addrs: RwLock::new(VirtualAddrs::default()),
            allocator: cfg.allocator.map(tokio::sync::Mutex::new),
            membership: cfg.membership,
            peers: Mutex::new(HashMap::new()),
            link_samples: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            frame_tx,
            flood_tx,
            event_tx,
        });

        let mut router_builder = Router::builder(cfg.endpoint.clone()).accept(
            crate::proto::ALPN,
            Handler {
                shared: shared.clone(),
            },
        );
        if let Some(gossip) = cfg.gossip {
            router_builder = router_builder.accept(iroh_gossip::ALPN, gossip);
        }
        let router = router_builder.spawn();

        Ok((
            Arc::new(Mesh {
                shared,
                router,
                seq: AtomicU64::new(0),
            }),
            MeshChannels {
                frame_rx,
                flood_rx,
                events,
            },
        ))
    }

    pub fn is_creator(&self) -> bool {
        self.shared.is_creator
    }

    pub fn my_id(&self) -> EndpointId {
        self.shared.my_id
    }

    pub fn my_record(&self) -> MemberRecord {
        my_record(&self.shared)
    }

    pub fn set_my_addrs(&self, addrs: VirtualAddrs) {
        *self.shared.my_addrs.write().expect("my_addrs lock") = addrs;
    }

    /// Whether we hold at least one live connection to `id`.
    pub fn is_connected(&self, id: &EndpointId) -> bool {
        self.shared
            .peers
            .lock()
            .expect("peers lock")
            .get(id)
            .is_some_and(|h| !h.is_empty())
    }

    pub fn connected_peers(&self) -> Vec<EndpointId> {
        self.shared
            .peers
            .lock()
            .expect("peers lock")
            .keys()
            .copied()
            .collect()
    }

    /// Measured QUIC link quality for every directly connected peer.
    ///
    /// Reads the currently selected path, so a link that migrated from relay
    /// to direct (or back) is reflected automatically. RTT and the congestion
    /// controller's bandwidth estimate are instantaneous; loss and observed
    /// send throughput are cumulative counters, so they are differenced
    /// against the previous sample and EWMA-smoothed here (the LSA smoother
    /// then applies a second EWMA with the same time constant).
    pub fn neighbor_link_metrics(&self) -> Vec<LinkMetric> {
        let peers = self.shared.peers.lock().expect("peers lock");
        let mut samples = self.shared.link_samples.lock().expect("link samples lock");
        let now = Instant::now();
        let mut out = Vec::with_capacity(peers.len());

        for (id, handles) in peers.iter() {
            let Some(handle) = handles.first() else {
                continue;
            };
            let paths = handle.conn.paths();
            let Some(path) = paths.iter().find(|p| p.is_selected()) else {
                let mut m = LinkMetric::unknown(IdBytes::from(*id), UNKNOWN_RTT_MS);
                if let Some(prev) = samples.get(id) {
                    m.loss_permille = prev.loss_permille;
                    m.tx_kbps = prev.tx_kbps;
                }
                out.push(m);
                continue;
            };
            let stats = path.stats();
            let rtt_ms = stats.rtt.as_millis().clamp(1, u128::from(MAX_RTT_MS)) as u32;
            let bw_kbps = stats
                .bandwidth_estimate
                .map(|bits| (bits / 1000).min(u128::from(u32::MAX) as u64) as u32)
                .unwrap_or(0);

            let (loss_permille, tx_kbps) = match samples.get(id) {
                Some(prev)
                    if stats.sent_packets >= prev.sent_packets
                        && stats.lost_packets >= prev.lost_packets
                        && stats.sent_bytes >= prev.sent_bytes =>
                {
                    let elapsed_us = now.saturating_duration_since(prev.at).as_micros().max(1);
                    let sent = stats.sent_packets - prev.sent_packets;
                    let lost = (stats.lost_packets - prev.lost_packets).min(sent);
                    let bytes = stats.sent_bytes - prev.sent_bytes;
                    let loss = if sent > 0 {
                        (u128::from(lost) * 1000 / u128::from(sent)).min(1000) as u32
                    } else {
                        prev.loss_permille
                    };
                    // bytes * 8 bits / 1000 (kbit) * 1e6 / micros (/s).
                    let tx =
                        ((u128::from(bytes) * 8_000 / elapsed_us).min(u128::from(u32::MAX))) as u32;
                    (ewma(prev.loss_permille, loss), ewma(prev.tx_kbps, tx))
                }
                // First sample, or a connection/path reset: no window yet.
                _ => (0, 0),
            };
            samples.insert(
                *id,
                LinkSample {
                    at: now,
                    sent_packets: stats.sent_packets,
                    lost_packets: stats.lost_packets,
                    sent_bytes: stats.sent_bytes,
                    loss_permille,
                    tx_kbps,
                },
            );
            out.push(LinkMetric {
                neighbor: IdBytes::from(*id),
                rtt_ms,
                loss_permille,
                tx_kbps,
                bw_kbps,
            });
        }
        samples.retain(|id, _| peers.contains_key(id));
        out
    }

    /// Dial a peer, authenticate, and register the connection.
    pub async fn dial(
        &self,
        addr: EndpointAddr,
        desired: VirtualAddrs,
    ) -> anyhow::Result<DialOutcome> {
        let remote = addr.id;
        if self.is_connected(&remote) {
            let record = self
                .shared
                .membership
                .get(&IdBytes::from(remote))
                .map(|m| m.record)
                .unwrap_or_else(|| MemberRecord::empty_addrs(IdBytes::from(remote)));
            return Ok(DialOutcome {
                remote: record,
                assigned_addrs: VirtualAddrs::default(),
            });
        }
        let conn = self
            .shared
            .endpoint
            .connect(addr, crate::proto::ALPN)
            .await
            .map_err(|e| anyhow::anyhow!("connect failed: {e}"))?;
        let (record, assigned_addrs) = auth_initiator(&self.shared, &conn, desired).await?;
        register_conn(&self.shared, conn.clone());
        self.shared.membership.upsert(record.clone());
        let _ = self.shared.event_tx.send(MeshEvent::PeerUp(remote));

        // The initiator side also serves control requests from the remote.
        let shared = self.shared.clone();
        tokio::spawn(async move {
            ctrl_loop(&shared, &conn).await;
            shared.remove_handle(&remote, conn.stable_id());
            let _ = shared.event_tx.send(MeshEvent::PeerDown(remote));
        });

        Ok(DialOutcome {
            remote: record,
            assigned_addrs,
        })
    }

    /// Send a unicast frame toward its next hop.
    ///
    /// `next_hop` may be the final destination (direct neighbor) or an
    /// intermediate relay; the frame itself is untouched, routing decisions
    /// live in the switch. `hop` is the remaining hop budget carried on the
    /// wire and decremented by every relaying node.
    pub fn send_unicast(&self, next_hop: &EndpointId, hop: u8, frame: Bytes) {
        self.shared.push_frame(next_hop, hop, frame);
    }

    /// Publish a message on the flood path (flood bus mode).
    pub fn flood_send(&self, envelope: &FloodEnvelope, exclude: Option<EndpointId>) {
        let payload = match postcard::to_allocvec(envelope) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!("flood encode failed: {err}");
                return;
            }
        };
        let mut tagged = Vec::with_capacity(payload.len() + 1);
        tagged.push(tag::FLOOD);
        tagged.extend_from_slice(&payload);
        self.shared.flood_out(&tagged, exclude);
    }

    /// Next sequence number for envelopes published by ourselves.
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn shutdown(&self) {
        let _ = self.router.shutdown().await;
    }
}
