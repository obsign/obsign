use crate::Error;
use audit_core::checkpoint::{Checkpoint, PublicKeyEntry, SignedCheckpoint};
use ed25519_dalek::{Signer, SigningKey};
use std::path::Path;

/// Where the sealing key lives.
///
/// This trait is the KMS/HSM boundary: everything above it manipulates
/// checkpoints and signatures, everything below it decides where the private
/// key material sits. A production implementation forwards `sign` to a
/// KMS/HSM and never holds the key in process memory; what makes the ledger
/// worth deploying is that neither the gateway host *nor this process* has to
/// be trusted with the key.
pub trait Sealer {
    fn key_id(&self) -> &str;

    /// The public half, as it will appear in evidence packs and trusted key
    /// files.
    fn public_key(&self) -> PublicKeyEntry;

    /// Ed25519 signature over the message.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error>;
}

/// Signs a checkpoint and re-verifies the signature before returning it.
///
/// The self-check is not paranoia: with a remote signer, a misconfigured key
/// slot answers with a *valid signature from the wrong key*. That must fail
/// here, at sealing time — not twenty-four months later in front of an
/// auditor.
pub fn sign_checkpoint(cp: Checkpoint, sealer: &dyn Sealer) -> Result<SignedCheckpoint, Error> {
    let sig = sealer.sign(&cp.signing_bytes())?;
    let signed = SignedCheckpoint {
        checkpoint: cp,
        signature: hex::encode(sig),
    };
    let vk = sealer.public_key().to_verifying_key()?;
    signed.verify(&vk)?;
    Ok(signed)
}

/// Development sealer: a 32-byte hex seed in a file.
///
/// A key in a file is exactly the cohabitation problem the ledger exists to
/// solve, one host over. It stays acceptable for development and for a first
/// design partner running the ledger on a hardened admin host; anything
/// beyond that belongs behind a KMS/HSM implementation of [`Sealer`].
pub struct FileSealer {
    key: SigningKey,
    key_id: String,
}

impl FileSealer {
    pub fn from_seed_file(path: &Path, key_id: &str) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)?;
        let bytes = hex::decode(raw.trim())
            .map_err(|_| Error::BadSeed("not valid hex".to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::BadSeed("the seed must be 32 bytes".to_string()))?;
        Ok(FileSealer {
            key: SigningKey::from_bytes(&seed),
            key_id: key_id.to_string(),
        })
    }

    /// For tests and examples only.
    pub fn from_seed(seed: [u8; 32], key_id: &str) -> Self {
        FileSealer {
            key: SigningKey::from_bytes(&seed),
            key_id: key_id.to_string(),
        }
    }
}

impl Sealer for FileSealer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        Ok(self.key.sign(message).to_bytes())
    }
}
