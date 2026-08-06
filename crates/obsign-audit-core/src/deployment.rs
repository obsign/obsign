//! Deployment bundle: the control-plane-signed set of active gateway origin
//! keys.
//!
//! v0 distributed origin trust through a flat file an operator hand-kept on
//! the ledger host, the exact hole the identity and policy bundles exist to
//! close: whoever writes that file mints origin authority. This bundle moves
//! origin-key distribution onto the same footing as every other piece of
//! authority in the system: a reviewed file in git, compiled deterministically,
//! signed with the ops key, published immutably.
//!
//! What it governs, precisely: the keys a *fresh* seal will accept as having
//! written a record, and the keys a gateway will accept when resuming a chain.
//! It does **not** reach into sealed history. A record already sealed was
//! origin-verified at seal time, and the checkpoint attests that. Revoking a
//! key (removing it and republishing) bounds the future; the immutable
//! `releases/<sha>/` lineage dates the boundary. An auditor re-verifying an
//! old pack uses the origin keys embedded in that pack, not the current set.

use crate::attestation::KeyAttestation;
use crate::canonical::Encoder;
use crate::checkpoint::{KeyRole, PublicKeyEntry};
use crate::error::Error;
use crate::hash::{digest, domain};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FORMAT: &str = "obsign-deployment/1";

/// The active gateway origin keys of a deployment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentBundle {
    pub format: String,
    /// `deployment@<sha>`, the source ref, like `policies@<sha>`.
    pub version: String,
    /// Active origin keys. Order in the file is irrelevant: signing sorts by
    /// `key_id`. Every entry must have role `origin`.
    pub origin_keys: Vec<PublicKeyEntry>,
    /// Remote-attestation enrollments (v3), keyed by `key_id`. Optional and
    /// `default`, the `anchors` precedent: a bundle without attestations
    /// signs and parses exactly as before. Covered by the ops signature via
    /// `signing_bytes`, so the expected PCR policy an attacker would relax is
    /// under the same root as the keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<KeyAttestation>,
}

impl DeploymentBundle {
    /// Bytes that are signed. Explicit canonical encoding, never the JSON:
    /// the identity bundle's rule, for the identity bundle's reason.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.format).str(&self.version);

        // Sorted by key_id so the file's order never changes the signature.
        let mut keys: Vec<&PublicKeyEntry> = self.origin_keys.iter().collect();
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        e.u64(keys.len() as u64);
        for k in keys {
            e.str(&k.key_id)
                .str(&k.algo)
                .str(&k.public_key)
                .str(k.role.as_str());
        }

        // Attestations are appended only when present, so a bundle without
        // any (every v1 bundle) produces byte-identical signing bytes and
        // keeps verifying. A verifier reaches this branch under the same
        // condition. The field is deterministic from the parsed bundle.
        if !self.attestations.is_empty() {
            let mut atts: Vec<&KeyAttestation> = self.attestations.iter().collect();
            atts.sort_by(|a, b| a.key_id.cmp(&b.key_id));
            e.u64(atts.len() as u64);
            for a in atts {
                e.str(&a.key_id)
                    .str(&a.ak_pub)
                    .str(&a.ek_cert)
                    .str(&a.certify)
                    .str(&a.quote);
                // Presence-tagged (`opt_str`), so an attestation without the
                // TPMT_PUBLIC cannot be re-read as one with it or vice versa.
                e.opt_str(a.identity_pub.as_deref());
                e.u64(a.expected_pcrs.len() as u64);
                for p in &a.expected_pcrs {
                    e.u64(p.index as u64).str(&p.digest);
                }
            }
        }

        digest(domain::DEPLOYMENT_BUNDLE, e.finish())
            .as_bytes()
            .to_vec()
    }

    /// The active origin keys as a verifiable map, refusing anything that is
    /// not a usable origin key.
    ///
    /// A seal-role key here is the writer-certifier confusion the two roles
    /// exist to prevent, and a duplicate `key_id` would let one entry shadow
    /// another. Both are refused outright, because a deployment bundle that
    /// quietly dropped a key is precisely the failure this whole design
    /// removes.
    pub fn active_origin_keys(&self) -> Result<BTreeMap<String, VerifyingKey>, Error> {
        let mut map = BTreeMap::new();
        for entry in &self.origin_keys {
            if entry.role != KeyRole::Origin {
                return Err(Error::NonOriginKeyInBundle(entry.key_id.clone()));
            }
            let vk = entry.to_verifying_key()?;
            if map.insert(entry.key_id.clone(), vk).is_some() {
                return Err(Error::DuplicateBundleKey(entry.key_id.clone()));
            }
        }
        Ok(map)
    }

    pub fn sign(self, key_id: impl Into<String>, key: &SigningKey) -> SignedDeploymentBundle {
        let sig = key.sign(&self.signing_bytes());
        SignedDeploymentBundle {
            bundle: self,
            key_id: key_id.into(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// A deployment bundle plus the ops-key signature over it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedDeploymentBundle {
    pub bundle: DeploymentBundle,
    /// The ops key that signed, resolved against the trusted key set, the
    /// same root that signs policy and identity bundles.
    pub key_id: String,
    pub signature: String,
}

impl SignedDeploymentBundle {
    /// Verifies the signature under one ops key and returns the bundle.
    pub fn verify(&self, ops_key: &VerifyingKey) -> Result<&DeploymentBundle, Error> {
        let raw = hex::decode(&self.signature).map_err(|_| Error::BadDeploymentSignature)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadDeploymentSignature)?;
        ops_key
            .verify(&self.bundle.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadDeploymentSignature)?;
        if self.bundle.format != FORMAT {
            return Err(Error::UnknownDeploymentFormat(self.bundle.format.clone()));
        }
        Ok(&self.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin_entry(key_id: &str, seed: u8) -> PublicKeyEntry {
        let vk = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        PublicKeyEntry {
            key_id: key_id.into(),
            algo: "ed25519".into(),
            public_key: hex::encode(vk.to_bytes()),
            role: KeyRole::Origin,
        }
    }

    fn bundle(keys: Vec<PublicKeyEntry>) -> DeploymentBundle {
        DeploymentBundle {
            format: FORMAT.into(),
            version: "deployment@abc123".into(),
            origin_keys: keys,
            attestations: Vec::new(),
        }
    }

    #[test]
    fn a_bundle_verifies_under_its_ops_key_only() {
        let ops = SigningKey::from_bytes(&[1u8; 32]);
        let signed = bundle(vec![origin_entry("gw-a", 10)]).sign("ops-1", &ops);

        assert!(signed.verify(&ops.verifying_key()).is_ok());
        let other = SigningKey::from_bytes(&[2u8; 32]);
        assert!(matches!(
            signed.verify(&other.verifying_key()),
            Err(Error::BadDeploymentSignature)
        ));
    }

    #[test]
    fn key_order_in_the_file_does_not_change_the_signature() {
        let a = origin_entry("gw-a", 10);
        let b = origin_entry("gw-b", 11);
        let one = bundle(vec![a.clone(), b.clone()]).signing_bytes();
        let two = bundle(vec![b, a]).signing_bytes();
        assert_eq!(one, two, "the signature must not depend on file order");
    }

    #[test]
    fn a_seal_key_in_the_bundle_is_refused() {
        let mut entry = origin_entry("gw-a", 10);
        entry.role = KeyRole::Seal;
        let err = bundle(vec![entry]).active_origin_keys().unwrap_err();
        assert!(matches!(err, Error::NonOriginKeyInBundle(_)));
    }

    #[test]
    fn a_duplicate_key_id_is_refused() {
        let err = bundle(vec![origin_entry("gw-a", 10), origin_entry("gw-a", 11)])
            .active_origin_keys()
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateBundleKey(_)));
    }

    #[test]
    fn the_active_set_resolves_every_key() {
        let b = bundle(vec![origin_entry("gw-a", 10), origin_entry("gw-b", 11)]);
        let map = b.active_origin_keys().unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("gw-a") && map.contains_key("gw-b"));
    }
}
