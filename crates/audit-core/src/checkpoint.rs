use crate::canonical::Encoder;
use crate::error::Error;
use crate::hash::{digest, domain, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Periodic seal over an interval of the chain.
///
/// The hash chain alone proves internal consistency and not much more:
/// whoever holds the log can rewrite it entirely and recompute every hash.
/// The checkpoint closes that hole — it is signed with a key held in a
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

/// A public key as it appears in an evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyEntry {
    pub key_id: String,
    /// Only algorithm accepted for now: `ed25519`.
    pub algo: String,
    /// Raw public key, 32 bytes in hex.
    pub public_key: String,
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
