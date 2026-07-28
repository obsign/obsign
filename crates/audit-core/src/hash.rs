use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// A SHA-256 digest. Serialized as hex so it stays readable when an evidence
/// pack is opened in a plain text editor.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

/// Starting anchor of a chain: 32 zero bytes.
pub const GENESIS: Hash = Hash([0u8; 32]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, crate::Error> {
        let raw = hex::decode(s).map_err(|_| crate::Error::BadHex(s.to_string()))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| crate::Error::BadHex(s.to_string()))?;
        Ok(Hash(arr))
    }

    pub fn is_genesis(&self) -> bool {
        self.0 == GENESIS.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Domain separation bytes.
///
/// Every kind of hashed object is prefixed with a distinct byte. Without it,
/// an attacker could pass the encoding of one object off as another (type
/// confusion). This is a property you must be able to explain as-is to an
/// auditor.
pub mod domain {
    pub const RECORD: u8 = 0x01;
    pub const MERKLE_LEAF: u8 = 0x02;
    pub const MERKLE_NODE: u8 = 0x03;
    pub const CHECKPOINT: u8 = 0x04;
    /// Signed policy bundle.
    pub const POLICY_BUNDLE: u8 = 0x05;
    /// Signed identity bundle (issuer, audience, JWKS, claim mapping).
    pub const IDENTITY_BUNDLE: u8 = 0x06;
    /// Application content (prompt, arguments, result).
    pub const CONTENT: u8 = 0xF0;
}

/// Hash of an encoded body, with domain separation.
///
/// Public so that other crates (signed policy bundles) reuse the same
/// primitive instead of reimplementing a variant of it.
pub fn digest(domain: u8, body: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([domain]);
    h.update(body);
    Hash(h.finalize().into())
}
