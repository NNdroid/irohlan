//! Broadcast bus: distributes ethernet broadcast/multicast frames and
//! membership announcements to all members of the virtual LAN.
//!
//! Two interchangeable implementations:
//! * [`BusMode::Gossip`] — an [iroh-gossip] epidemic broadcast tree. Efficient
//!   for larger networks, deduplication and loop prevention are built in.
//! * [`BusMode::Flood`] — naive flooding over the mesh connections with
//!   `(origin, seq)` deduplication. Works without iroh-gossip and doubles as
//!   a fallback.
//!
//! [iroh-gossip]: https://crates.io/crates/iroh-gossip

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::StreamExt;
use iroh::EndpointId;
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::{Gossip, TopicId};
use tokio::sync::{broadcast, mpsc};

use crate::mesh::Mesh;
use crate::proto::{BusMsg, FloodEnvelope, IdBytes, MemberRecord};

/// Capacity of the deduplication ring of the flood bus.
const FLOOD_DEDUP_CAP: usize = 8192;
/// Capacity of the event channel handed out to subscribers.
const EVENT_CAP: usize = 256;

/// Which transport the bus uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusMode {
    Gossip,
    Flood,
}

impl BusMode {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "gossip" => Ok(Self::Gossip),
            "flood" => Ok(Self::Flood),
            other => Err(anyhow::anyhow!(
                "unknown bus mode {other:?}, expected \"gossip\" or \"flood\""
            )),
        }
    }
}

/// Events published by the bus.
#[derive(Clone, Debug)]
pub enum BusEvent {
    /// A broadcast/multicast ethernet frame, destined for the local TAP.
    Frame(Bytes),
    /// A membership announcement from a peer.
    Announce(MemberRecord),
    /// A link-state advertisement for the partial-mesh routing table.
    LinkState(crate::proto::LinkStateMsg),
    /// We gained a direct neighbor in the broadcast overlay.
    NeighborUp(EndpointId),
    /// We lost a direct neighbor in the broadcast overlay.
    NeighborDown(EndpointId),
}

struct DedupRing {
    set: HashSet<(IdBytes, u64)>,
    ring: VecDeque<(IdBytes, u64)>,
}

impl DedupRing {
    fn new() -> Self {
        Self {
            set: HashSet::new(),
            ring: VecDeque::new(),
        }
    }

    /// Returns `true` if this (origin, seq) pair has not been seen before.
    fn mark(&mut self, origin: &IdBytes, seq: u64) -> bool {
        if !self.set.insert((*origin, seq)) {
            return false;
        }
        self.ring.push_back((*origin, seq));
        if self.ring.len() > FLOOD_DEDUP_CAP {
            if let Some(old) = self.ring.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// The broadcast bus.
pub struct BroadcastBus {
    mode: BusMode,
    event_tx: broadcast::Sender<BusEvent>,
    gossip_tx: Option<tokio::sync::Mutex<GossipSender>>,
    mesh: Arc<Mesh>,
    seen: Mutex<DedupRing>,
}

impl BroadcastBus {
    /// Start the bus and spawn its receive pumps.
    ///
    /// * `topic_id` / `bootstrap` — gossip topic and initial peers (the
    ///   creator for joiners, empty for the creator itself).
    /// * `flood_rx` — flood envelopes received by the mesh pumps.
    /// * `gossip` — the spawned gossip handle, if gossip mode is enabled.
    pub async fn start(
        mode: BusMode,
        topic_id: TopicId,
        bootstrap: Vec<EndpointId>,
        mesh: Arc<Mesh>,
        mut flood_rx: mpsc::Receiver<(EndpointId, FloodEnvelope)>,
        gossip: Option<Gossip>,
    ) -> anyhow::Result<Arc<Self>> {
        let (event_tx, _) = broadcast::channel(EVENT_CAP);

        let gossip_tx = match (mode, gossip) {
            (BusMode::Gossip, Some(gossip)) => {
                let topic = gossip.subscribe(topic_id, bootstrap).await?;
                let (sender, mut receiver) = topic.split();
                let events = event_tx.clone();
                tokio::spawn(async move {
                    while let Some(ev) = receiver.next().await {
                        match ev {
                            Ok(Event::Received(msg)) => {
                                match postcard::from_bytes::<BusMsg>(&msg.content) {
                                    Ok(BusMsg::Frame(frame)) => {
                                        let _ = events.send(BusEvent::Frame(Bytes::from(frame)));
                                    }
                                    Ok(BusMsg::Announce(record)) => {
                                        let _ = events.send(BusEvent::Announce(record));
                                    }
                                    Ok(BusMsg::LinkState(ls)) => {
                                        let _ = events.send(BusEvent::LinkState(ls));
                                    }
                                    Err(err) => {
                                        tracing::debug!("bad bus message: {err}");
                                    }
                                }
                            }
                            Ok(Event::NeighborUp(id)) => {
                                let _ = events.send(BusEvent::NeighborUp(id));
                            }
                            Ok(Event::NeighborDown(id)) => {
                                let _ = events.send(BusEvent::NeighborDown(id));
                            }
                            Ok(Event::Lagged) => {
                                tracing::warn!("gossip subscription lagged, events dropped");
                            }
                            Ok(other) => {
                                tracing::debug!("unhandled gossip event: {other:?}");
                            }
                            Err(err) => {
                                tracing::warn!("gossip stream error: {err:#}");
                                break;
                            }
                        }
                    }
                    tracing::warn!("gossip topic stream ended");
                });
                Some(tokio::sync::Mutex::new(sender))
            }
            _ => None,
        };

        let bus = Arc::new(Self {
            mode,
            event_tx,
            gossip_tx,
            mesh,
            seen: Mutex::new(DedupRing::new()),
        });

        // Flood receive pump (only receives traffic in flood mode, but the
        // mesh always decodes flood tags, so keep it running regardless).
        let bus_c = bus.clone();
        tokio::spawn(async move {
            while let Some((from, envelope)) = flood_rx.recv().await {
                bus_c.handle_flood(from, envelope);
            }
        });

        Ok(bus)
    }

    /// Subscribe to bus events.
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.event_tx.subscribe()
    }

    /// Publish a message to all members.
    pub async fn publish(&self, msg: BusMsg) {
        match self.mode {
            BusMode::Gossip => {
                let Some(sender) = &self.gossip_tx else {
                    tracing::warn!("gossip bus not available, dropping message");
                    return;
                };
                let Ok(payload) = postcard::to_allocvec(&msg) else {
                    tracing::warn!("bus message encode failed");
                    return;
                };
                let sender = sender.lock().await;
                if let Err(err) = sender.broadcast(Bytes::from(payload)).await {
                    tracing::warn!("gossip broadcast failed: {err:#}");
                }
            }
            BusMode::Flood => {
                let envelope = FloodEnvelope {
                    origin: IdBytes::from(self.mesh.my_id()),
                    seq: self.mesh.next_seq(),
                    msg,
                };
                self.mesh.flood_send(&envelope, None);
            }
        }
    }

    /// Handle a flood envelope received from a peer: dedup, deliver, relay.
    fn handle_flood(&self, from: EndpointId, envelope: FloodEnvelope) {
        let fresh = self
            .seen
            .lock()
            .expect("dedup lock")
            .mark(&envelope.origin, envelope.seq);
        if !fresh {
            return;
        }
        // Relay to everyone except the peer that delivered it to us.
        self.mesh.flood_send(&envelope, Some(from));
        match envelope.msg {
            BusMsg::Frame(frame) => {
                let _ = self.event_tx.send(BusEvent::Frame(Bytes::from(frame)));
            }
            BusMsg::Announce(record) => {
                let _ = self.event_tx.send(BusEvent::Announce(record));
            }
            BusMsg::LinkState(ls) => {
                let _ = self.event_tx.send(BusEvent::LinkState(ls));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flood_dedup_ring_marks_and_evicts() {
        let mut ring = DedupRing::new();
        let origin = IdBytes([1; 32]);
        assert!(ring.mark(&origin, 0));
        assert!(!ring.mark(&origin, 0), "duplicate is rejected");
        assert!(ring.mark(&origin, 1));
        let other = IdBytes([2; 32]);
        assert!(ring.mark(&other, 0), "same seq from another origin is fresh");

        // Eviction: insert until beyond capacity, the oldest entry is dropped.
        for seq in 2..(FLOOD_DEDUP_CAP as u64 + 10) {
            ring.mark(&origin, seq);
        }
        assert!(!ring.set.contains(&(origin, 0)));
        assert!(ring.set.contains(&(origin, FLOOD_DEDUP_CAP as u64 + 9)));
    }

    #[test]
    fn bus_mode_parse() {
        assert_eq!(BusMode::parse("gossip").unwrap(), BusMode::Gossip);
        assert_eq!(BusMode::parse("flood").unwrap(), BusMode::Flood);
        assert!(BusMode::parse("mesh").is_err());
    }
}
