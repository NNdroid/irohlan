//! Join tickets: the self-contained "invite code" that a network creator
//! hands out so peers can join the virtual LAN.

use iroh::{EndpointAddr, RelayUrl, TransportAddr};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

use crate::proto::IdBytes;

/// Ticket format version.
pub const TICKET_VERSION: u8 = 1;
/// Human friendly prefix of the encoded ticket.
pub const TICKET_PREFIX: &str = "irohlan1_";

/// Everything a peer needs to join a virtual LAN.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinTicket {
    /// Format version.
    pub version: u8,
    /// Random 32-byte network id, binds keys and separates networks.
    pub net_id: IdBytes,
    /// Virtual subnet base address.
    pub subnet: u32,
    /// Virtual subnet prefix length (e.g. 24 for a /24).
    pub prefix: u8,
    /// iroh-gossip topic id used as broadcast bus.
    pub topic_id: IdBytes,
    /// Endpoint id of the network creator (the address allocator).
    pub creator_id: IdBytes,
    /// Creator relay URL, if the creator uses one.
    pub creator_relay: Option<String>,
    /// Creator direct addresses (LAN / public).
    pub creator_direct: Vec<SocketAddr>,
    /// Offline passphrase verifier (does not reveal the passphrase).
    pub verifier: [u8; 32],
}

impl JoinTicket {
    /// Subnet base address.
    pub fn subnet(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.subnet)
    }

    /// The creator's endpoint address including relay and direct addresses.
    ///
    /// The creator id was validated during [`Self::decode`].
    pub fn creator_addr(&self) -> EndpointAddr {
        let id = iroh::EndpointId::from_bytes(self.creator_id.as_bytes())
            .expect("creator id validated at decode time");
        let addr = EndpointAddr::new(id);
        let addr = match self.creator_relay.as_deref() {
            Some(relay) => match relay.parse::<RelayUrl>() {
                Ok(url) => addr.with_relay_url(url),
                Err(_) => addr,
            },
            None => addr,
        };
        addr.with_addrs(self.creator_direct.iter().map(|a| TransportAddr::Ip(*a)))
    }

    /// Canonical string form of the subnet, e.g. `10.13.37.0/24`.
    pub fn subnet_cidr(&self) -> String {
        format!("{}/{}", self.subnet(), self.prefix)
    }

    /// Encode to the textual ticket format (base32, crockford alphabet).
    pub fn encode(&self) -> anyhow::Result<String> {
        let bytes = postcard::to_allocvec(self)?;
        let body = base32::encode(base32::Alphabet::Crockford, &bytes);
        Ok(format!("{TICKET_PREFIX}{body}"))
    }

    /// Decode from the textual ticket format.
    pub fn decode(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let body = s
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("ticket must start with {TICKET_PREFIX:?}"))?;
        let bytes = base32::decode(base32::Alphabet::Crockford, &body.to_uppercase())
            .ok_or_else(|| anyhow::anyhow!("ticket is not valid base32"))?;
        let ticket: JoinTicket = postcard::from_bytes(&bytes)?;
        anyhow::ensure!(
            ticket.version == TICKET_VERSION,
            "unsupported ticket version {}",
            ticket.version
        );
        // Validate that the embedded ids are well-formed keys.
        iroh::EndpointId::from_bytes(ticket.creator_id.as_bytes())
            .map_err(|e| anyhow::anyhow!("ticket has an invalid creator id: {e}"))?;
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> JoinTicket {
        JoinTicket {
            version: TICKET_VERSION,
            net_id: IdBytes([1; 32]),
            subnet: u32::from(Ipv4Addr::new(10, 13, 37, 0)),
            prefix: 24,
            topic_id: IdBytes([2; 32]),
            creator_id: IdBytes([3; 32]),
            creator_relay: Some("https://relay.example.com".into()),
            creator_direct: vec!["192.168.1.10:12345".parse().unwrap()],
            verifier: [4; 32],
        }
    }

    #[test]
    fn ticket_roundtrip() {
        let t = sample();
        let encoded = t.encode().unwrap();
        assert!(encoded.starts_with(TICKET_PREFIX));
        let decoded = JoinTicket::decode(&encoded).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn ticket_roundtrip_is_case_insensitive_and_tolerates_whitespace() {
        let t = sample();
        let mut encoded = t.encode().unwrap();
        encoded = encoded.to_lowercase();
        let decoded = JoinTicket::decode(&format!("  {encoded}\n")).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(JoinTicket::decode("nonsense").is_err());
        assert!(JoinTicket::decode("irohlan1_####").is_err());
    }

    #[test]
    fn creator_addr_includes_relay_and_direct() {
        let t = sample();
        let addr = t.creator_addr();
        assert_eq!(*addr.id.as_bytes(), [3; 32]);
        assert!(addr.relay_urls().next().is_some());
        assert_eq!(addr.ip_addrs().count(), 1);
    }
}
