use crate::canonical::Encoder;
use crate::error::Error;
use crate::hash::{digest, domain, Hash};
use crate::merkle::merkle_root;
use crate::record::Record;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Periodic seal over an interval of the chain.
///
/// The hash chain alone proves internal consistency and not much more:
/// whoever holds the log can rewrite it entirely and recompute every hash.
/// The checkpoint closes that hole: it is signed with a key held in a
/// KMS/HSM, out of reach of the process that writes the log.
///
/// In production the root is additionally timestamped per RFC 3161: that is
/// what makes the date enforceable against a third party.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    pub chain_id: String,
    /// Sealed interval, both bounds inclusive.
    pub from_seq: u64,
    pub to_seq: u64,
    /// Merkle root over the record hashes of the interval.
    pub root: Hash,
    /// Hash of the last sealed record. Lets a checkpoint be tied back to the
    /// chain without recomputing the whole interval.
    pub head_hash: Hash,
    /// Chains checkpoints to each other: without it, a whole checkpoint (and
    /// therefore a whole interval) could be removed unnoticed.
    pub prev_checkpoint_hash: Option<Hash>,
    pub ts_ms: i64,
    pub key_id: String,
}

impl Checkpoint {
    /// The bytes that are actually signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.chain_id)
            .u64(self.from_seq)
            .u64(self.to_seq)
            .hash(&self.root)
            .hash(&self.head_hash)
            .opt_hash(self.prev_checkpoint_hash.as_ref())
            .i64(self.ts_ms)
            .str(&self.key_id);
        digest(domain::CHECKPOINT, e.finish()).as_bytes().to_vec()
    }

    /// Hash of the checkpoint itself, referenced by the next one.
    pub fn hash(&self) -> Hash {
        let bytes = self.signing_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Hash(arr)
    }

    pub fn sign(self, key: &SigningKey) -> SignedCheckpoint {
        let sig = key.sign(&self.signing_bytes());
        SignedCheckpoint {
            checkpoint: self,
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// Builds a checkpoint over a contiguous slice of already-written records.
///
/// This is the ledger's sealing path. The ledger seals a log it did not
/// write. It lives here, next to `ChainWriter::seal`, because defining what a
/// checkpoint over records *means* is proof logic, and there must be exactly
/// one implementation of it.
///
/// The interval is re-checked before sealing (contiguous `seq`, propagated
/// `prev_hash`): a seal over an inconsistent interval would lend probative
/// value to garbage. The link between the first record and what precedes it
/// cannot be checked from the slice alone; the caller ties intervals together
/// through `prev_checkpoint_hash` and the previous checkpoint's `head_hash`.
pub fn seal_interval(
    chain_id: &str,
    records: &[Record],
    prev_checkpoint_hash: Option<Hash>,
    ts_ms: i64,
    key_id: &str,
) -> Result<Checkpoint, Error> {
    let first = records.first().ok_or(Error::EmptySeal)?;

    let mut leaves = Vec::with_capacity(records.len());
    let mut prev: Option<(u64, Hash)> = None;
    for rec in records {
        if let Some((pseq, phash)) = prev {
            if rec.seq != pseq + 1 {
                return Err(Error::BrokenInterval(format!(
                    "seq {} follows seq {pseq}",
                    rec.seq
                )));
            }
            if rec.prev_hash != phash {
                return Err(Error::BrokenInterval(format!(
                    "seq {}: prev_hash does not match the hash of seq {pseq}",
                    rec.seq
                )));
            }
        }
        let h = rec.hash();
        leaves.push(h);
        prev = Some((rec.seq, h));
    }

    let (to_seq, head_hash) = prev.expect("non-empty interval");
    let root = merkle_root(&leaves).expect("non-empty interval");

    Ok(Checkpoint {
        chain_id: chain_id.to_string(),
        from_seq: first.seq,
        to_seq,
        root,
        head_hash,
        prev_checkpoint_hash,
        ts_ms,
        key_id: key_id.to_string(),
    })
}

/// The one pack structure without `deny_unknown_fields`: serde does not
/// support it in combination with `flatten`, on either side. The exposure is
/// small. A stray field cannot alter verification, since the signature is
/// checked over `signing_bytes()`, which is rebuilt from the known fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedCheckpoint {
    #[serde(flatten)]
    pub checkpoint: Checkpoint,
    /// Ed25519 signature, 64 bytes in hex.
    pub signature: String,
}

impl SignedCheckpoint {
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Error> {
        let raw = hex::decode(&self.signature)
            .map_err(|_| Error::BadHex(self.signature.clone()))?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| Error::BadSignatureLength)?;
        let sig = Signature::from_bytes(&bytes);
        key.verify(&self.checkpoint.signing_bytes(), &sig)
            .map_err(|_| Error::BadSignature {
                key_id: self.checkpoint.key_id.clone(),
                from_seq: self.checkpoint.from_seq,
                to_seq: self.checkpoint.to_seq,
            })
    }
}

/// What a key is allowed to attest.
///
/// Origin keys authenticate the *writer* (the gateway signs each record as
/// it writes it); sealing keys certify the *log* (the ledger signs
/// checkpoints over it); ops keys name *who may write* (the control plane
/// signs the deployment bundle enrolling the origin keys). Confusing any two
/// would let one component hold an authority the split exists to deny (the
/// writer certifying its own log, or the operator who decides policy also
/// certifying the history that policy produced), so every verification
/// resolves a key within its role, and a key found under the wrong role is an
/// error, not a fallback.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Signs checkpoints. The default: every key that existed before roles
    /// did was a sealing key.
    #[default]
    Seal,
    /// Signs records at write time.
    Origin,
    /// Signs deployment bundles and policy releases, and nothing the auditor
    /// verifies directly. Resolved by `key_id` when a bundle names it, never
    /// admitted to the sealing or origin sets: an ops key that could also
    /// mint checkpoints would let whoever publishes the rules certify the
    /// history those rules produced.
    Ops,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRole::Seal => "seal",
            KeyRole::Origin => "origin",
            KeyRole::Ops => "ops",
        }
    }

    fn is_seal(&self) -> bool {
        *self == KeyRole::Seal
    }
}

/// A public key as it appears in an evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyEntry {
    pub key_id: String,
    /// Only algorithm accepted for now: `ed25519`.
    pub algo: String,
    /// Raw public key, 32 bytes in hex.
    pub public_key: String,
    /// Serialized only when it departs from the default: files and packs
    /// written before roles existed keep both their bytes and their meaning.
    #[serde(default, skip_serializing_if = "KeyRole::is_seal")]
    pub role: KeyRole,
}

impl PublicKeyEntry {
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, Error> {
        if self.algo != "ed25519" {
            return Err(Error::UnsupportedAlgo(self.algo.clone()));
        }
        let raw = hex::decode(&self.public_key)
            .map_err(|_| Error::BadHex(self.public_key.clone()))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| Error::BadKeyLength)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::BadKey(self.key_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Effect, EffectStatus, Payload};
    use crate::ChainWriter;

    fn payload(n: u64) -> Payload {
        Payload::Effect(Effect {
            status: EffectStatus::Ok,
            result_hash: None,
            latency_ms: n,
        })
    }

    fn build_records(n: u64) -> (Vec<Record>, ChainWriter) {
        let mut chain = ChainWriter::new("c1");
        let records: Vec<Record> = (0..n)
            .map(|i| chain.append(i as i64, format!("r{i}"), None, "s", payload(i)))
            .collect();
        (records, chain)
    }

    #[test]
    fn seal_interval_and_chain_writer_agree() {
        // The gateway seals through ChainWriter, the ledger through
        // seal_interval. If the two ever diverge, the export and the verifier
        // stop talking about the same object — this test is the tripwire.
        let (records, mut chain) = build_records(5);
        let from_writer = chain.seal(42, "k1").unwrap();
        let from_records = seal_interval("c1", &records, None, 42, "k1").unwrap();
        assert_eq!(from_writer, from_records);
    }

    #[test]
    fn empty_interval_is_rejected() {
        assert!(matches!(
            seal_interval("c1", &[], None, 0, "k1"),
            Err(Error::EmptySeal)
        ));
    }

    #[test]
    fn sequence_gap_is_rejected() {
        let (mut records, _) = build_records(4);
        records.remove(2);
        assert!(matches!(
            seal_interval("c1", &records, None, 0, "k1"),
            Err(Error::BrokenInterval(_))
        ));
    }

    #[test]
    fn broken_link_is_rejected() {
        // Contiguous seq but rewritten content: the prev_hash propagation
        // breaks, and the seal must refuse to bless it.
        let (mut records, _) = build_records(4);
        records[2].payload = payload(999);
        assert!(matches!(
            seal_interval("c1", &records, None, 0, "k1"),
            Err(Error::BrokenInterval(_))
        ));
    }
}
