//! Wire protocol definitions: ethernet frame classification, control
//! messages and the framing used on mesh connections.

use serde::{Deserialize, Serialize};

/// ALPN of the irohlan mesh protocol.
///
/// v2 added multi-hop unicast relaying (partial mesh): the FRAME payload
/// carries a hop counter and the bus carries link-state advertisements.
pub const ALPN: &[u8] = b"irohlan/v2";

/// Hard upper bound for anything we read from a stream (frames or messages).
pub const MAX_STREAM_MSG_LEN: usize = 65_535;
/// Upper bound for control messages on bi-directional streams.
pub const MAX_CTRL_MSG_LEN: usize = 4_096;

/// Tag byte prefixing every datagram and uni-directional stream payload.
pub mod tag {
    /// Unicast ethernet frame plus hop counter: `[hop: u8][frame…]`.
    pub const FRAME: u8 = 0x00;
    /// postcard-encoded [`FloodEnvelope`] (flooded broadcast / multicast
    /// frames and member announcements on the flood bus).
    pub const FLOOD: u8 = 0x01;
}

/// Length-prefix framing (u16 little endian) used on bi-directional streams.
pub mod lenframe {
    /// Maximum length accepted by the framing.
    pub const MAX: usize = crate::proto::MAX_CTRL_MSG_LEN;

    /// Encode `payload` with a u16 LE length prefix.
    pub fn encode(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            payload.len() <= MAX,
            "control message too large: {} bytes",
            payload.len()
        );
        let mut out = Vec::with_capacity(2 + payload.len());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Read one framed message from `recv` (length prefix + payload).
    pub async fn read(
        recv: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await?;
        let len = u16::from_le_bytes(len_buf) as usize;
        anyhow::ensure!(len <= MAX, "peer sent oversized control message: {len}");
        let mut buf = vec![0u8; len];
        if len > 0 {
            recv.read_exact(&mut buf).await?;
        }
        Ok(buf)
    }

    /// Write one framed message to `send`.
    pub async fn write(
        send: &mut (impl tokio::io::AsyncWriteExt + Unpin),
        payload: &[u8],
    ) -> anyhow::Result<()> {
        send.write_all(&encode(payload)?).await?;
        Ok(())
    }
}

/// A 32-byte endpoint identifier (an iroh `EndpointId` / Ed25519 public key).
///
/// Owned plain-copy type so that protocol messages stay `serde` friendly and
/// platform independent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdBytes(pub [u8; 32]);

impl IdBytes {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for IdBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl From<iroh::EndpointId> for IdBytes {
    fn from(id: iroh::EndpointId) -> Self {
        IdBytes(*id.as_bytes())
    }
}

impl TryFrom<IdBytes> for iroh::EndpointId {
    type Error = iroh::KeyParsingError;
    fn try_from(id: IdBytes) -> Result<Self, Self::Error> {
        iroh::EndpointId::from_bytes(&id.0)
    }
}

impl std::fmt::Display for IdBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// A member of the virtual LAN as announced over the control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// Endpoint id; the virtual MAC is derived from it.
    pub id: IdBytes,
    /// Virtual IPv4 address.
    pub ip: u32,
    /// Human readable hostname.
    pub hostname: String,
}

impl MemberRecord {
    pub fn ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.ip)
    }
}

/// Control-plane messages exchanged on bi-directional streams.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CtrlMsg {
    /// First message of a connection, sent by the dialing side.
    AuthHello {
        nonce: [u8; 16],
        proof: [u8; 32],
        /// Only honored by the network creator: requested virtual IP.
        desired_ip: Option<u32>,
        /// The dialer's current virtual IP, if it has one.
        ip: Option<u32>,
        hostname: String,
    },
    /// Successful auth reply, sent by the accepting side.
    AuthAccept {
        nonce: [u8; 16],
        proof: [u8; 32],
        /// Only set by the network creator: assigned virtual IP.
        assigned_ip: Option<u32>,
        /// The accepting side's own member record.
        record: MemberRecord,
    },
    /// Auth failed; connection will be closed.
    AuthReject { reason: String },
    /// Joiner asks the creator for a virtual IP (e.g. after a conflict).
    RequestIp { desired: Option<u32> },
    /// Creator grants a virtual IP.
    AssignIp { ip: u32 },
    /// Creator refuses to grant a virtual IP.
    RejectIp { reason: String },
}

/// Messages distributed through the broadcast bus (gossip tree or flood bus).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BusMsg {
    /// An ethernet frame addressed to a broadcast or multicast MAC.
    Frame(Vec<u8>),
    /// Membership announcement.
    Announce(MemberRecord),
    /// Link-state advertisement for the partial-mesh routing table.
    LinkState(LinkStateMsg),
}

/// Link-state advertisement distributed on the broadcast bus.
///
/// Each node announces the set of mesh neighbors it currently holds. Every
/// node assembles these into a link-state database and computes its own
/// next-hop table (see [`crate::routing`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkStateMsg {
    /// Endpoint that originated this advertisement.
    pub origin: IdBytes,
    /// Monotonically increasing per-origin sequence number; stale (older)
    /// advertisements are ignored.
    pub seq: u64,
    /// The origin's current mesh neighbors.
    pub neighbors: Vec<IdBytes>,
}

/// Envelope for messages distributed on the flood bus.
///
/// `(origin, seq)` identifies a message so every peer can drop duplicates it
/// has already seen — the flood bus is a naive epidemic broadcast and relies
/// on this for loop prevention.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FloodEnvelope {
    /// Endpoint that originally published the message.
    pub origin: IdBytes,
    /// Monotonically increasing per-origin sequence number.
    pub seq: u64,
    /// The message being flooded.
    pub msg: BusMsg,
}

/// Classification of an ethernet frame by destination MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// ff:ff:ff:ff:ff:ff
    Broadcast,
    /// destination MAC has the multicast bit set (includes broadcast).
    Multicast,
    /// directed at a single station
    Unicast([u8; 6]),
}

/// Minimum size of an ethernet II frame (dst + src + ethertype).
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Parse the destination MAC of a raw ethernet frame.
pub fn dst_mac(frame: &[u8]) -> Option<[u8; 6]> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[..6]);
    Some(mac)
}

/// Classify a raw ethernet frame for forwarding decisions.
pub fn classify_frame(frame: &[u8]) -> Option<FrameClass> {
    let mac = dst_mac(frame)?;
    if mac == [0xff; 6] {
        return Some(FrameClass::Broadcast);
    }
    if mac[0] & 0x01 != 0 {
        return Some(FrameClass::Multicast);
    }
    Some(FrameClass::Unicast(mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_request_frame() -> Vec<u8> {
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&[0x08, 0x06]); // ARP
        f.extend_from_slice(&[0u8; 28]);
        f
    }

    #[test]
    fn classifies_broadcast() {
        let f = arp_request_frame();
        assert_eq!(classify_frame(&f), Some(FrameClass::Broadcast));
    }

    #[test]
    fn classifies_unicast_and_multicast() {
        let mut f = vec![0x02, 1, 2, 3, 4, 5];
        f.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            classify_frame(&f),
            Some(FrameClass::Unicast([0x02, 1, 2, 3, 4, 5]))
        );

        // IPv4 multicast MAC 01:00:5e:...
        let mut m = vec![0x01, 0x00, 0x5e, 0, 0, 1];
        m.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        m.extend_from_slice(&[0x08, 0x00]);
        m.extend_from_slice(&[0u8; 20]);
        assert_eq!(classify_frame(&m), Some(FrameClass::Multicast));

        // IPv6 multicast MAC 33:33:...
        let mut m6 = vec![0x33, 0x33, 0, 0, 0, 1];
        m6.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        m6.extend_from_slice(&[0x86, 0xdd]);
        m6.extend_from_slice(&[0u8; 20]);
        assert_eq!(classify_frame(&m6), Some(FrameClass::Multicast));
    }

    #[test]
    fn rejects_runt_frames() {
        assert_eq!(classify_frame(&[0u8; 13]), None);
        assert_eq!(dst_mac(&[0u8; 10]), None);
    }

    #[test]
    fn length_prefix_roundtrip() {
        let payload = b"hello world".to_vec();
        let framed = lenframe::encode(&payload).unwrap();
        assert_eq!(framed.len(), payload.len() + 2);

        // decode via the async read helper
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(framed);
            let decoded = lenframe::read(&mut cursor).await.unwrap();
            assert_eq!(decoded, payload);
        });
    }

    #[test]
    fn length_prefix_rejects_oversize() {
        let too_big = vec![0xffu8; 3];
        // craft a length field larger than MAX
        let mut framed = (u16::MAX).to_le_bytes().to_vec();
        framed.extend_from_slice(&too_big);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(framed);
            assert!(lenframe::read(&mut cursor).await.is_err());
        });
    }

    #[test]
    fn ctrl_msg_postcard_roundtrip() {
        let msg = CtrlMsg::AuthHello {
            nonce: [1; 16],
            proof: [2; 32],
            desired_ip: Some(u32::from(std::net::Ipv4Addr::LOCALHOST)),
            ip: None,
            hostname: "testhost".into(),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let back: CtrlMsg = postcard::from_bytes(&bytes).unwrap();
        match back {
            CtrlMsg::AuthHello {
                nonce,
                desired_ip,
                hostname,
                ..
            } => {
                assert_eq!(nonce, [1; 16]);
                assert_eq!(desired_ip, Some(u32::from(std::net::Ipv4Addr::LOCALHOST)));
                assert_eq!(hostname, "testhost");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
