//! Per-record origin authentication.
//!
//! The hash chain proves *internal consistency*; the checkpoint proves *who
//! sealed*. Neither proves *who wrote*: every input to a record's hash is
//! public, so an attacker with write access to the WAL — and no key — can
//! fabricate a perfectly well-formed record after the sealed head, and the
//! honest sealer blesses it on its next pass. The origin signature closes
//! that gap: the gateway signs each record as it writes it, and both the
//! sealer and the offline verifier refuse to treat as authentic what the
//! gateway did not sign.
//!
//! The signature is deliberately layered *outside* the frozen proof object.
//! `Record` and `Record::hash()` are untouched; the signature rides as
//! sibling fields in the serde envelope (WAL line, evidence pack). An absent
//! signature is an absent proof, not a format break — the same rule the pack
//! applies to `anchors`.
//!
//! What the signature can and cannot claim: it authenticates the *writer*,
//! raising the attack from "write the WAL directory" to "hold the gateway's
//! key material". It cannot defend against a compromised gateway process —
//! the gateway *is* the origin, and origin authentication cannot defend
//! against the origin.

use crate::canonical::Encoder;
use crate::error::Error;
use crate::hash::{digest, domain, Hash};
use crate::record::{Record, SessionCert};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The canonical id an origin key is known by, derived from its public bytes.
///
/// One derivation, used by whoever signs (the gateway naming its key in a
/// record envelope) and whoever verifies (resolving a session key from its
/// certificate): two schemes drifting is the single-implementation risk this
/// crate exists to remove. Sixteen hex chars of the public key — collision
/// there would already break the customer's key management.
pub fn key_id_for(key: &VerifyingKey) -> String {
    format!("origin-{}", &hex::encode(key.to_bytes())[..16])
}

/// The bytes the identity key signs to certify a session key.
///
/// Covers the session public key, the identity key that vouches for it, the
/// gateway, the validity window, and — via `chain_id` — the one chain this
/// certificate authorizes. A leaked session key cannot be replayed onto
/// another chain (chain_id bound) or presented as another gateway's
/// (gateway_id bound). `identity_sig` itself is excluded: it is the output.
pub fn session_cert_signing_bytes(chain_id: &str, cert: &SessionCert) -> Vec<u8> {
    let mut e = Encoder::new();
    e.str(chain_id)
        .str(&cert.session_pubkey)
        .str(&cert.identity_key_id)
        .str(&cert.gateway_id)
        .i64(cert.not_before_ms)
        .i64(cert.not_after_ms);
    digest(domain::SESSION_CERT, e.finish()).as_bytes().to_vec()
}

/// Verifies a session certificate under one identity key and returns the
/// session key it authorizes.
///
/// On success the returned key is what every record of the chain must verify
/// against; the caller keys it by [`key_id_for`], the id the records name.
pub fn verify_session_cert(
    chain_id: &str,
    cert: &SessionCert,
    identity_key: &VerifyingKey,
) -> Result<VerifyingKey, Error> {
    let raw = hex::decode(&cert.identity_sig).map_err(|_| Error::BadHex(cert.identity_sig.clone()))?;
    let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadSignatureLength)?;
    let msg = session_cert_signing_bytes(chain_id, cert);
    identity_key
        .verify(&msg, &Signature::from_bytes(&bytes))
        .map_err(|_| Error::BadSessionCert {
            identity_key_id: cert.identity_key_id.clone(),
        })?;

    // The session public key must itself be a usable ed25519 key.
    let pk = hex::decode(&cert.session_pubkey)
        .map_err(|_| Error::BadHex(cert.session_pubkey.clone()))?;
    let arr: [u8; 32] = pk.try_into().map_err(|_| Error::BadKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::BadKey(cert.session_pubkey.clone()))
}

/// The bytes an origin key signs for one record.
///
/// The record hash already binds `seq`, `prev_hash`, `ts_ms`, the ids and
/// the payload, so the signature is position-bound within its chain. The
/// chain id is added here because the record does not carry it — the WAL
/// *filename* does, and filenames are exactly what a disk attacker rewrites.
/// Without it, a signed record could be transplanted into another chain at
/// the same position.
pub fn origin_signing_bytes(chain_id: &str, record_hash: &Hash) -> Vec<u8> {
    let mut e = Encoder::new();
    e.str(chain_id).hash(record_hash);
    digest(domain::ORIGIN_RECORD, e.finish()).as_bytes().to_vec()
}

/// A record plus its origin authentication, as stored in the WAL and the
/// evidence pack.
///
/// `#[serde(flatten)]` keeps the wire format additive: a line written before
/// origin authentication existed deserializes with `None` fields, and a line
/// written after stays readable with `tail` — two hex fields longer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedRecord {
    #[serde(flatten)]
    pub record: Record,
    /// Ed25519 over [`origin_signing_bytes`], 64 bytes in hex.
    /// Absent on logs written before origin authentication existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_sig: Option<String>,
    /// Key that produced `origin_sig`; resolved against trusted keys with
    /// role `origin`, never against sealing keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_key_id: Option<String>,
}

impl SignedRecord {
    /// A record with no origin proof (legacy logs, unsigned gateways).
    pub fn unsigned(record: Record) -> Self {
        SignedRecord {
            record,
            origin_sig: None,
            origin_key_id: None,
        }
    }

    /// Attaches a signature produced over [`origin_signing_bytes`].
    pub fn signed(record: Record, key_id: impl Into<String>, sig: [u8; 64]) -> Self {
        SignedRecord {
            record,
            origin_sig: Some(hex::encode(sig)),
            origin_key_id: Some(key_id.into()),
        }
    }

    pub fn is_signed(&self) -> bool {
        self.origin_sig.is_some() || self.origin_key_id.is_some()
    }

    /// Verifies the origin signature against one key.
    ///
    /// The caller resolves `origin_key_id` to a key and checks its role; this
    /// function only answers "did that key sign this record of this chain".
    /// A half-attached signature (one field without the other) is an error,
    /// not an absence: it can only be produced by tampering.
    pub fn verify_origin(&self, chain_id: &str, key: &VerifyingKey) -> Result<(), Error> {
        let (Some(sig_hex), Some(_)) = (&self.origin_sig, &self.origin_key_id) else {
            return Err(Error::MissingOriginSignature {
                seq: self.record.seq,
            });
        };
        let raw = hex::decode(sig_hex).map_err(|_| Error::BadHex(sig_hex.clone()))?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadSignatureLength)?;
        let msg = origin_signing_bytes(chain_id, &self.record.hash());
        key.verify(&msg, &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadOriginSignature {
                seq: self.record.seq,
                key_id: self.origin_key_id.clone().unwrap_or_default(),
            })
    }
}

impl From<Record> for SignedRecord {
    fn from(record: Record) -> Self {
        SignedRecord::unsigned(record)
    }
}

/// Field access on the inner record (`sr.seq`, `sr.hash()`) without naming
/// `.record` at every call site: consumers overwhelmingly read, and the few
/// that construct do so through `unsigned`/`signed`.
impl std::ops::Deref for SignedRecord {
    type Target = Record;
    fn deref(&self) -> &Record {
        &self.record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Effect, EffectStatus, Payload};
    use crate::ChainWriter;
    use ed25519_dalek::{Signer, SigningKey};

    fn record() -> Record {
        let mut chain = ChainWriter::new("c1");
        chain.append(
            7,
            "r0",
            None,
            "s",
            Payload::Effect(Effect {
                status: EffectStatus::Ok,
                result_hash: None,
                latency_ms: 1,
            }),
        )
    }

    fn sign(rec: &Record, chain_id: &str, key: &SigningKey) -> SignedRecord {
        let msg = origin_signing_bytes(chain_id, &rec.hash());
        SignedRecord::signed(rec.clone(), "og1", key.sign(&msg).to_bytes())
    }

    #[test]
    fn a_signature_verifies_on_its_own_chain_only() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let rec = record();
        let sr = sign(&rec, "c1", &key);

        assert!(sr.verify_origin("c1", &key.verifying_key()).is_ok());
        // Cross-chain transplant: same record, same position, other chain.
        assert!(matches!(
            sr.verify_origin("c2", &key.verifying_key()),
            Err(Error::BadOriginSignature { seq: 0, .. })
        ));
    }

    #[test]
    fn a_foreign_key_is_refused() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let other = SigningKey::from_bytes(&[10u8; 32]);
        let sr = sign(&record(), "c1", &key);
        assert!(sr.verify_origin("c1", &other.verifying_key()).is_err());
    }

    #[test]
    fn an_unsigned_record_is_an_absence_not_a_proof() {
        let sr = SignedRecord::unsigned(record());
        assert!(!sr.is_signed());
        let key = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            sr.verify_origin("c1", &key.verifying_key()),
            Err(Error::MissingOriginSignature { seq: 0 })
        ));
    }

    #[test]
    fn a_half_attached_signature_is_tampering() {
        // Only tampering produces a key id without a signature (or the
        // reverse): the writer always sets both or neither.
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut sr = sign(&record(), "c1", &key);
        sr.origin_sig = None;
        assert!(sr.is_signed(), "half a signature still claims to be signed");
        assert!(sr.verify_origin("c1", &key.verifying_key()).is_err());
    }

    #[test]
    fn envelope_roundtrips_and_stays_additive() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let sr = sign(&record(), "c1", &key);
        let json = serde_json::to_string(&sr).unwrap();
        let back: SignedRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sr);

        // A pre-origin-auth line — a bare record — still deserializes.
        let legacy = serde_json::to_string(&sr.record).unwrap();
        let back: SignedRecord = serde_json::from_str(&legacy).unwrap();
        assert!(!back.is_signed());
        assert_eq!(back.record, sr.record);

        // And an unsigned envelope serializes as a bare record: the fields
        // appear on the wire only when there is a signature to carry.
        assert_eq!(
            serde_json::to_string(&SignedRecord::unsigned(sr.record.clone())).unwrap(),
            legacy
        );
    }
}
