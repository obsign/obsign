//! The ledger's sealing key over a PKCS#11 token.
//!
//! A thin wrapper over the shared [`obsign_pkcs11::Pkcs11Signer`]: the FFI, the token
//! selection and the Ed25519 signing live in the `pkcs11` crate, shared with
//! the gateway's identity key. Here we only give the signer the *sealing*
//! role: the key that certifies history, distinct from the origin/identity
//! keys that write it.

use crate::sealer::Sealer;
use crate::Error;
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use std::path::Path;

pub use obsign_pkcs11::TokenSelector;

fn map(e: obsign_pkcs11::Error) -> Error {
    Error::Pkcs11(e.to_string())
}

/// [`Sealer`] over a PKCS#11 module: the key never enters this process.
#[derive(Debug)]
pub struct Pkcs11Sealer {
    inner: obsign_pkcs11::Pkcs11Signer,
    key_id: String,
}

impl Pkcs11Sealer {
    pub fn open(
        module: &Path,
        token: &TokenSelector,
        pin: &str,
        key_label: &str,
        key_id: &str,
    ) -> Result<Self, Error> {
        let inner =
            obsign_pkcs11::Pkcs11Signer::open(module, token, pin, key_label, key_id).map_err(map)?;
        Ok(Pkcs11Sealer {
            inner,
            key_id: key_id.to_string(),
        })
    }
}

impl Sealer for Pkcs11Sealer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.inner.public_key_bytes()),
            role: KeyRole::Seal,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        self.inner.sign(message).map_err(map)
    }
}
