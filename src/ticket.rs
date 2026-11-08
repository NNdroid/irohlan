//! Join tickets: the self-contained "invite code" that a network creator
//! hands out so peers can join the virtual LAN.

use iroh::{EndpointAddr, RelayUrl, TransportAddr};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::netaddr::{AddrPlan, V4Net, V6Net};
use crate::proto::IdBytes;

/// Ticket format version. v2 carries both address families; v1 tickets are
/// still decodable and upgrade to IPv4-only networks.
pub const TICKET_VERSION: u8 = 2;
/// Human friendly prefix of the encoded ticket (format family, not version).
pub const TICKET_PREFIX: &str = "irohlan1_";

/// Everything a peer needs to join a virtual LAN.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinTicket {
    /// Format version.
    pub version: u8,
    /// Random 32-byte network id, binds keys and separates networks.
    pub net_id: IdBytes,
    /// IPv4 subnet, if enabled.
    pub v4: Option<V4Net>,
    /// IPv6 prefix, if enabled.
    pub v6: Option<V6Net>,
    /// iroh-gossip topic id used as broadcast bus.
    pub topic_id: IdBytes,
    /// Endpoint id of the network creator (the address allocator).
    pub creator_id: IdBytes,
    /// Creator relay URL, if the creator uses one.
    pub creator_relay: Option<String>,
    /// Creator direct addresses (LAN / public, IPv4 and IPv6).
    pub creator_direct: Vec<SocketAddr>,
    /// Offline passphrase verifier (does not reveal the passphrase).
    pub verifier: [u8; 32],
}

/// On-wire layout of v1 tickets, kept only so old invites remain usable.
#[derive(Serialize, Deserialize)]
struct JoinTicketV1 {
    version: u8,
    net_id: IdBytes,
    subnet: u32,
    prefix: u8,
    topic_id: IdBytes,
    creator_id: IdBytes,
    creator_relay: Option<String>,
    creator_direct: Vec<SocketAddr>,
    verifier: [u8; 32],
}

impl JoinTicketV1 {
    fn upgrade(self) -> JoinTicket {
        debug_assert_eq!(self.version, 1);
        JoinTicket {
            version: TICKET_VERSION,
            net_id: self.net_id,
            // v1 networks had no IPv6 plan; keep them IPv4-only.
            v4: Some(V4Net {
                base: self.subnet,
                prefix: self.prefix,
            }),
            v6: None,
            topic_id: self.topic_id,
            creator_id: self.creator_id,
            creator_relay: self.creator_relay,
            creator_direct: self.creator_direct,
            verifier: self.verifier,
        }
    }
}

impl JoinTicket {
    /// The address plan this ticket advertises.
    pub fn plan(&self) -> AddrPlan {
        AddrPlan::new(self.v4, self.v6)
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

    /// Canonical string form of the address plan.
    pub fn subnet_cidr(&self) -> String {
        self.plan().describe()
    }

    /// Encode to the textual ticket format (base32, crockford alphabet).
    pub fn encode(&self) -> anyhow::Result<String> {
        let bytes = postcard::to_allocvec(self)?;
        let body = base32::encode(base32::Alphabet::Crockford, &bytes);
        Ok(format!("{TICKET_PREFIX}{body}"))
    }

    /// Decode from the textual ticket format, accepting v1 and v2 tickets.
    pub fn decode(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let body = s
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("ticket must start with {TICKET_PREFIX:?}"))?;
        let bytes = base32::decode(base32::Alphabet::Crockford, &body.to_uppercase())
            .ok_or_else(|| anyhow::anyhow!("ticket is not valid base32"))?;
        anyhow::ensure!(!bytes.is_empty(), "ticket is empty");
        // postcard puts the `version: u8` field first, so we can dispatch
        // without partially decoding the rest.
        let ticket = match bytes[0] {
            1 => postcard::from_bytes::<JoinTicketV1>(&bytes)?.upgrade(),
            TICKET_VERSION => postcard::from_bytes::<JoinTicket>(&bytes)?,
            other => anyhow::bail!("unsupported ticket version {other}"),
        };
        ticket.plan().validate()?;
        // Validate that the embedded ids are well-formed keys.
        iroh::EndpointId::from_bytes(ticket.creator_id.as_bytes())
            .map_err(|e| anyhow::anyhow!("ticket has an invalid creator id: {e}"))?;
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn sample() -> JoinTicket {
        JoinTicket {
            version: TICKET_VERSION,
            net_id: IdBytes([1; 32]),
            v4: Some(V4Net::parse_cidr("10.13.37.0/24").unwrap()),
            v6: Some(V6Net::parse_cidr("fd00:1234:5678:9abc::/64").unwrap()),
            topic_id: IdBytes([2; 32]),
            creator_id: IdBytes([3; 32]),
            creator_relay: Some("https://relay.example.com".into()),
            creator_direct: vec![
                "192.168.1.10:12345".parse().unwrap(),
                "[2001:db8::10]:12345".parse().unwrap(),
            ],
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
        assert_eq!(decoded.plan(), t.plan());
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
        assert_eq!(addr.ip_addrs().count(), 2);
        assert!(addr
            .ip_addrs()
            .any(|a| a.ip() == std::net::IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn v1_tickets_decode_as_ipv4_only() {
        let v1 = JoinTicketV1 {
            version: 1,
            net_id: IdBytes([7; 32]),
            subnet: u32::from(std::net::Ipv4Addr::new(10, 13, 37, 0)),
            prefix: 24,
            topic_id: IdBytes([8; 32]),
            creator_id: IdBytes([3; 32]),
            creator_relay: None,
            creator_direct: vec!["192.168.1.10:12345".parse().unwrap()],
            verifier: [9; 32],
        };
        let bytes = postcard::to_allocvec(&v1).unwrap();
        let encoded = format!(
            "{TICKET_PREFIX}{}",
            base32::encode(base32::Alphabet::Crockford, &bytes)
        );
        let decoded = JoinTicket::decode(&encoded).unwrap();
        assert_eq!(decoded.version, TICKET_VERSION);
        assert!(decoded.plan().v4.is_some());
        assert!(decoded.plan().v6.is_none());
        assert_eq!(decoded.subnet_cidr(), "10.13.37.0/24");
    }

    #[test]
    fn single_stack_tickets_are_valid() {
        let mut t = sample();
        t.v4 = None;
        let encoded = t.encode().unwrap();
        let decoded = JoinTicket::decode(&encoded).unwrap();
        assert_eq!(decoded.plan().describe(), "fd00:1234:5678:9abc::/64");
    }
}
