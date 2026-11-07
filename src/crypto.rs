//! Key derivation, authentication proofs and MAC address derivation.
//!
//! iroh already provides transport encryption (QUIC + TLS, identity = Ed25519
//! public key) and authenticates the *identity* of a peer. What we add here is
//! *authorization*: only endpoints that know the network passphrase may join
//! the virtual LAN. Every connection must present a proof-of-knowledge of the
//! network key before it is registered.

use blake3::Hasher;

/// Domain-separation tag for the per-network symmetric key.
const NET_KEY_CONTEXT: &str = "irohlan v1 network key";
/// Domain-separation tag for the offline ticket verifier.
const VERIFIER_CONTEXT: &str = "irohlan v1 ticket verifier";

/// Derive the 32-byte symmetric network key from the network id and passphrase.
pub fn net_key(net_id: &[u8; 32], secret: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + secret.len());
    material.extend_from_slice(net_id);
    material.extend_from_slice(secret.as_bytes());
    blake3::derive_key(NET_KEY_CONTEXT, &material)
}

/// Derive the verifier stored inside a join ticket. It lets a joiner check
/// locally that the typed passphrase is the right one without revealing it.
pub fn ticket_verifier(net_id: &[u8; 32], secret: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + secret.len());
    material.extend_from_slice(net_id);
    material.extend_from_slice(secret.as_bytes());
    blake3::derive_key(VERIFIER_CONTEXT, &material)
}

/// Compute an authentication proof.
///
/// The transcript binds the proof to the role (initiator/responder), both
/// endpoint ids and the nonce, which prevents replay and reflection attacks.
/// Knowledge of the proof implies knowledge of the network key.
pub fn auth_proof(
    key: &[u8; 32],
    initiator: &crate::proto::IdBytes,
    responder: &crate::proto::IdBytes,
    nonce: &[u8; 16],
    role: &'static [u8],
) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    h.update(role);
    h.update(initiator.as_bytes());
    h.update(responder.as_bytes());
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// Roles for [`auth_proof`] transcripts, prevents proof reflection.
pub const ROLE_INITIATOR: &[u8] = b"irohlan auth initiator";
pub const ROLE_RESPONDER: &[u8] = b"irohlan auth responder";

/// Derive the stable virtual MAC address of an endpoint from its EndpointId.
///
/// The first byte sets the "locally administered" bit and clears the
/// "multicast" bit, so the address is a valid unicast address that does not
/// clash with hardware vendors. Deriving the MAC deterministically from the
/// identity means every peer can map `MAC <-> EndpointId` without any learning
/// or address resolution protocol of its own.
pub fn mac_from_id(id: &[u8; 32]) -> [u8; 6] {
    let h = blake3::hash(id);
    let b = h.as_bytes();
    [0x02, b[0], b[1], b[2], b[3], b[4]]
}

/// Format a MAC address in the canonical colon-separated lowercase form.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generate a random human-typeable passphrase (Crockford base32).
pub fn generate_secret() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut rng = rand::rng();
    (0..20)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Generate a random 16-byte nonce for the auth handshake.
pub fn nonce() -> [u8; 16] {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_key_is_deterministic_and_secret_dependent() {
        let net_id = [7u8; 32];
        let a = net_key(&net_id, "hunter2");
        let b = net_key(&net_id, "hunter2");
        let c = net_key(&net_id, "hunter3");
        let d = net_key(&[8u8; 32], "hunter2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn proof_binds_role_ids_and_nonce() {
        let key = net_key(&[1u8; 32], "s3cret");
        let i = crate::proto::IdBytes([1u8; 32]);
        let r = crate::proto::IdBytes([2u8; 32]);
        let p1 = auth_proof(&key, &i, &r, &[9u8; 16], ROLE_INITIATOR);
        let p2 = auth_proof(&key, &i, &r, &[9u8; 16], ROLE_INITIATOR);
        let p3 = auth_proof(&key, &i, &r, &[10u8; 16], ROLE_INITIATOR);
        let p4 = auth_proof(&key, &i, &r, &[9u8; 16], ROLE_RESPONDER);
        let p5 = auth_proof(&key, &r, &i, &[9u8; 16], ROLE_INITIATOR);
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p1, p4);
        assert_ne!(p1, p5);
    }

    #[test]
    fn mac_is_locally_administered_unicast() {
        let mac = mac_from_id(&[3u8; 32]);
        assert_eq!(mac.len(), 6);
        assert_eq!(mac[0] & 0b0000_0010, 0b0000_0010, "locally administered");
        assert_eq!(mac[0] & 0b0000_0001, 0, "unicast, not multicast");
        assert_eq!(mac_from_id(&[4u8; 32]), mac_from_id(&[4u8; 32]));
        assert_ne!(mac_from_id(&[3u8; 32]), mac_from_id(&[4u8; 32]));
    }

    #[test]
    fn mac_formatting() {
        assert_eq!(format_mac(&[0x02, 0x0a, 0xb, 0, 0xff, 1]), "02:0a:0b:00:ff:01");
    }
}
