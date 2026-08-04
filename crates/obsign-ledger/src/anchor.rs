//! RFC 3161 anchoring, by file exchange.
//!
//! The exchange is deliberately offline: `timestamp_request` produces a
//! `.tsq` artifact, an operator (or a cron with network access, where one
//! exists) carries it to the TSA, and the `.tsr` that comes back is attached
//! with `validate_response`. No HTTP client in this crate, because the
//! deployments this product targets are air-gapped first, and an internal TSA
//! reachable by sneakernet is a normal setup there.

use crate::store::Store;
use crate::Error;
use obsign_audit_core::rfc3161::{parse_timestamp_response, TimestampInfo};
use obsign_audit_core::Hash;

// DER content bytes of the SHA-256 OID (2.16.840.1.101.3.4.2.1).
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

/// Builds the DER `TimeStampReq` for a checkpoint.
///
/// The message imprint is the checkpoint hash itself: RFC 3161 timestamps a
/// digest, and `Checkpoint::hash()` *is* the checkpoint's identity, the same
/// value the next checkpoint chains from and the verifier recomputes.
///
/// Two deliberate choices:
///
/// * `certReq` is TRUE: the auditor validates the token against the TSA
///   certificate offline, so the token must carry it;
/// * no nonce: a nonce protects the freshness of an online exchange, which
///   this is not. Omitting it keeps the request deterministic: the same
///   checkpoint always produces byte-identical request material.
pub fn timestamp_request(checkpoint_hash: &Hash) -> Vec<u8> {
    let message_imprint = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(0x06, OID_SHA256)),
            tlv(0x04, checkpoint_hash.as_bytes()),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[
            tlv(0x02, &[1]),          // version
            message_imprint,
            tlv(0x01, &[0xFF]),       // certReq TRUE
        ]
        .concat(),
    )
}

/// Checks a TSA response against the checkpoint it claims to anchor.
///
/// Refused unless the TSA granted the request and the token imprints exactly
/// the checkpoint hash. Attaching a token that timestamps something else
/// would decorate the store with an anchor that collapses in front of the
/// verifier, so it is better to fail at the operator's keyboard.
pub fn validate_response(
    store: &Store,
    checkpoint_hash: &Hash,
    resp_der: &[u8],
) -> Result<TimestampInfo, Error> {
    if store.find_checkpoint(checkpoint_hash).is_none() {
        return Err(Error::UnknownCheckpoint(*checkpoint_hash));
    }
    let info = parse_timestamp_response(resp_der)?;
    if info.hashed_message != checkpoint_hash.as_bytes() {
        return Err(Error::AnchorMismatch(*checkpoint_hash));
    }
    Ok(info)
}
