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
use std::net::Ipv4Addr;
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
use crate::proto::{
    lenframe, tag, CtrlMsg, FloodEnvelope, IdBytes, MemberRecord, MAX_STREAM_MSG_LEN,
};

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
    /// IP assigned to us when the remote is the network creator.
    pub assigned_ip: Option<Ipv4Addr>,
}

/// A unicast frame received from a peer, with its remaining hop budget.
///
/// The switch delivers frames addressed to us to the TAP and relays the rest
/// (partial-mesh multi-hop forwarding, see [`crate::routing`]).
#[derive(Debug)]
pub struct InboundFrame {
    pub hop: u8,
    pub frame: Bytes,
}

enum OutMsg {
    Frame { hop: u8, frame: Bytes },
    /// Tagged payload ready for the wire (datagram or stream).
    Tagged(Vec<u8>),
}

struct PeerHandle {
    conn: Connection,
    stable_id: usize,
    out_tx: mpsc::Sender<OutMsg>,
}

/// State shared between the router handler, the pumps and [`Mesh`].
struct Shared {
    endpoint: Endpoint,
    net_key: [u8; 32],
    is_creator: bool,
    my_id: EndpointId,
    my_hostname: String,
    my_ip: RwLock<u32>,
    /// Creator-only lease allocator.
    allocator: Option<tokio::sync::Mutex<Allocator>>,
    membership: Arc<Membership>,
    peers: Mutex<HashMap<EndpointId, Vec<Arc<PeerHandle>>>>,
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

/// Responder half of the auth handshake. Returns the initiator's member
/// record so the caller can register it.
async fn auth_responder(shared: &Shared, conn: &Connection) -> anyhow::Result<MemberRecord> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let raw = lenframe::read(&mut recv).await?;
    let CtrlMsg::AuthHello {
        nonce,
        proof,
        desired_ip,
        ip: remote_ip,
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

    // The creator assigns (or confirms) the joiner's virtual IP.
    let assigned_ip = if shared.is_creator {
        let mut alloc = shared
            .allocator
            .as_ref()
            .expect("creator has an allocator")
            .lock()
            .await;
        match alloc.assign(
            IdBytes::from(remote),
            &hostname,
            desired_ip.map(Ipv4Addr::from),
        ) {
            Ok(ip) => Some(ip),
            Err(reason) => {
                let reply = CtrlMsg::AuthReject { reason };
                lenframe::write(&mut send, &postcard::to_allocvec(&reply)?).await?;
                send.finish().ok();
                return Err(anyhow::anyhow!("ip allocation refused"));
            }
        }
    } else {
        None
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
        assigned_ip: assigned_ip.map(u32::from),
        record: MemberRecord {
            id: IdBytes::from(shared.my_id),
            ip: *shared.my_ip.read().expect("my_ip lock"),
            hostname: shared.my_hostname.clone(),
        },
    };
    lenframe::write(&mut send, &postcard::to_allocvec(&reply)?).await?;
    send.finish().ok();

    let effective_ip = assigned_ip
        .map(u32::from)
        .or(remote_ip)
        .unwrap_or(0);
    Ok(MemberRecord {
        id: IdBytes::from(remote),
        ip: effective_ip,
        hostname,
    })
}

/// Initiator half of the auth handshake (called from [`Mesh::dial`]).
async fn auth_initiator(
    shared: &Shared,
    conn: &Connection,
    desired_ip: Option<Ipv4Addr>,
) -> anyhow::Result<(MemberRecord, Option<Ipv4Addr>)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let nonce = crypto::nonce();
    let proof = crypto::auth_proof(
        &shared.net_key,
        &IdBytes::from(shared.my_id),
        &IdBytes::from(conn.remote_id()),
        &nonce,
        crypto::ROLE_INITIATOR,
    );
    let my_ip = *shared.my_ip.read().expect("my_ip lock");
    let hello = CtrlMsg::AuthHello {
        nonce,
        proof,
        desired_ip: desired_ip.map(u32::from),
        ip: (my_ip != 0).then_some(my_ip),
        hostname: shared.my_hostname.clone(),
    };
    lenframe::write(&mut send, &postcard::to_allocvec(&hello)?).await?;
    send.finish().ok();

    let raw = timeout(AUTH_TIMEOUT, lenframe::read(&mut recv)).await??;
    match postcard::from_bytes::<CtrlMsg>(&raw)? {
        CtrlMsg::AuthAccept {
            nonce,
            proof,
            assigned_ip,
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
            Ok((record, assigned_ip.map(Ipv4Addr::from)))
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
            match alloc.assign(
                IdBytes::from(remote),
                &hostname,
                desired.map(Ipv4Addr::from),
            ) {
                Ok(ip) => CtrlMsg::AssignIp { ip: u32::from(ip) },
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
            let _ = shared
                .frame_tx
                .try_send(InboundFrame {
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
            my_ip: RwLock::new(0),
            allocator: cfg.allocator.map(tokio::sync::Mutex::new),
            membership: cfg.membership,
            peers: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            frame_tx,
            flood_tx,
            event_tx,
        });

        let mut router_builder = Router::builder(cfg.endpoint.clone())
            .accept(crate::proto::ALPN, Handler { shared: shared.clone() });
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
        MemberRecord {
            id: IdBytes::from(self.shared.my_id),
            ip: *self.shared.my_ip.read().expect("my_ip lock"),
            hostname: self.shared.my_hostname.clone(),
        }
    }

    pub fn set_my_ip(&self, ip: Ipv4Addr) {
        *self.shared.my_ip.write().expect("my_ip lock") = u32::from(ip);
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

    /// Dial a peer, authenticate, and register the connection.
    pub async fn dial(
        &self,
        addr: EndpointAddr,
        desired_ip: Option<Ipv4Addr>,
    ) -> anyhow::Result<DialOutcome> {
        let remote = addr.id;
        if self.is_connected(&remote) {
            let record = self
                .shared
                .membership
                .get(&IdBytes::from(remote))
                .map(|m| m.record)
                .unwrap_or(MemberRecord {
                    id: IdBytes::from(remote),
                    ip: 0,
                    hostname: String::new(),
                });
            return Ok(DialOutcome {
                remote: record,
                assigned_ip: None,
            });
        }
        let conn = self
            .shared
            .endpoint
            .connect(addr, crate::proto::ALPN)
            .await
            .map_err(|e| anyhow::anyhow!("connect failed: {e}"))?;
        let (record, assigned_ip) = auth_initiator(&self.shared, &conn, desired_ip).await?;
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
            assigned_ip,
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
