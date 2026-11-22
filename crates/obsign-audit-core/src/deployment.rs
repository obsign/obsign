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
use crate::origin::IdentityKey;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FORMAT: &str = "obsign-deployment/1";
/// Signs the attestations' credential activation (attestation v4) too.
/// Emitted only by a bundle that carries one ([`format_for`]), the
/// `obsign-policy/2` rule: a fleet that never enrolls with activation never
/// has to upgrade its verifiers first.
pub const FORMAT_V2: &str = "obsign-deployment/2";

/// The format a bundle carrying `attestations` must be published under: the
/// oldest one whose signature covers every field they use.
pub fn format_for(attestations: &[KeyAttestation]) -> &'static str {
    if attestations.iter().any(|a| a.activation.is_some()) {
        FORMAT_V2
    } else {
        FORMAT
    }
}

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
                // v2 appends the activation, presence-tagged like the public
                // area. v1 bytes stay exactly as they were, and a v1 bundle
                // that carries one is refused by `verify`, never trusted.
                if self.format != FORMAT {
                    match &a.activation {
                        None => {
                            e.u8(0);
                        }
                        Some(act) => {
                            e.u8(1)
                                .str(&act.ek_pub)
                                .str(&act.ak_public)
                                .str(&act.nonce)
                                .str(&act.secret);
                        }
                    }
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
    ///
    /// Ed25519 only: this is the set records are signed under directly (v0/v1)
    /// and what the sealing and resuming paths consume. A P-256 identity key
    /// is refused here as `UnsupportedAlgo`; see [`Self::active_identity_keys`].
    pub fn active_origin_keys(&self) -> Result<BTreeMap<String, VerifyingKey>, Error> {
        self.active_identity_keys()?
            .into_iter()
            .map(|(kid, key)| match key {
                IdentityKey::Ed25519(vk) => Ok((kid, vk)),
                other => Err(Error::UnsupportedAlgo(other.algo().to_string())),
            })
            .collect()
    }

    /// The active origin keys with the same refusals, ECDSA-P256 identity
    /// keys included: the key a TPM without EdDSA holds, which certifies v2
    /// session keys and nothing else (see [`IdentityKey`]).
    pub fn active_identity_keys(&self) -> Result<BTreeMap<String, IdentityKey>, Error> {
        let mut map = BTreeMap::new();
        for entry in &self.origin_keys {
            if entry.role != KeyRole::Origin {
                return Err(Error::NonOriginKeyInBundle(entry.key_id.clone()));
            }
            let key = IdentityKey::from_entry(entry)?;
            if map.insert(entry.key_id.clone(), key).is_some() {
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
        let sig = crate::signature_from_hex(&self.signature)
            .map_err(|_| Error::BadDeploymentSignature)?;
        if !crate::ed25519_verify(ops_key, &self.bundle.signing_bytes(), &sig) {
            return Err(Error::BadDeploymentSignature);
        }
        match self.bundle.format.as_str() {
            FORMAT_V2 => {}
            FORMAT => {
                // A v1 signature never saw an activation. Accepting one would
                // let unsigned JSON claim the AK was bound to an EK and the
                // statements were fresh, the exact claims v2 exists to sign.
                if self.bundle.attestations.iter().any(|a| a.activation.is_some()) {
                    return Err(Error::UnsignedAttestationActivation(
                        self.bundle.version.clone(),
                    ));
                }
            }
            other => return Err(Error::UnknownDeploymentFormat(other.to_string())),
        }
        Ok(&self.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signing bytes of the pinned v1 bundle, captured before `FORMAT_V2`
    /// existed (at f06fcf6).
    const PINNED_V1: &str = "4d2488eeb4a271a13d4ceab4304b0e78872ce19a51f50f09f34e7497c9a09efa";

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

    fn activated_bundle(format: &str) -> DeploymentBundle {
        let identity = SigningKey::from_bytes(&[10u8; 32]);
        let ak = SigningKey::from_bytes(&[20u8; 32]);
        let pcrs = vec![crate::attestation::PcrExpectation {
            index: 16,
            digest: hex::encode([0x42u8; 32]),
        }];
        let att = crate::attestation::testutil::attestation_activated(
            "gw-a",
            &identity.verifying_key(),
            &ak,
            pcrs,
        );
        DeploymentBundle {
            format: format.into(),
            attestations: vec![att],
            ..bundle(vec![origin_entry("gw-a", 10)])
        }
    }

    #[test]
    fn an_activation_needs_the_v2_format() {
        let ops = SigningKey::from_bytes(&[1u8; 32]);
        let b = activated_bundle(FORMAT_V2);
        assert_eq!(format_for(&b.attestations), FORMAT_V2);
        assert!(b.sign("ops-1", &ops).verify(&ops.verifying_key()).is_ok());

        // Without an activation, v1 stays what is emitted.
        let mut plain = activated_bundle(FORMAT);
        plain.attestations[0].activation = None;
        assert_eq!(format_for(&plain.attestations), FORMAT);
    }

    #[test]
    fn a_v1_bundle_carrying_an_activation_is_refused_as_unsigned() {
        // A genuine v1 bundle, its attestation then given an activation in
        // the JSON. The v1 signature still verifies (it never covered the
        // field), which is exactly why the field must be refused.
        let ops = SigningKey::from_bytes(&[1u8; 32]);
        let mut v1 = activated_bundle(FORMAT);
        let injected = v1.attestations[0].activation.take();
        let mut signed = v1.sign("ops-1", &ops);
        assert!(signed.verify(&ops.verifying_key()).is_ok());
        signed.bundle.attestations[0].activation = injected;
        assert!(matches!(
            signed.verify(&ops.verifying_key()),
            Err(Error::UnsignedAttestationActivation(_))
        ));
    }

    #[test]
    fn v2_signs_the_activation_and_v1_bytes_do_not_move() {
        let ops = SigningKey::from_bytes(&[1u8; 32]);
        // Every activation field is covered: altering one breaks the v2
        // signature.
        let signed = activated_bundle(FORMAT_V2).sign("ops-1", &ops);
        for f in 0..4 {
            let mut t = signed.clone();
            let act = t.bundle.attestations[0].activation.as_mut().unwrap();
            let field = match f {
                0 => &mut act.ek_pub,
                1 => &mut act.ak_public,
                2 => &mut act.nonce,
                _ => &mut act.secret,
            };
            field.replace_range(0..2, "ff");
            assert!(
                matches!(t.verify(&ops.verifying_key()), Err(Error::BadDeploymentSignature)),
                "activation field {f} is not signed"
            );
        }
        // Dropping the activation altogether is also caught.
        let mut t = signed.clone();
        t.bundle.attestations[0].activation = None;
        assert!(matches!(t.verify(&ops.verifying_key()), Err(Error::BadDeploymentSignature)));

        // A v1 bundle's signing bytes ignore the v2 tail entirely: the bytes
        // an already-published v1 bundle was signed over cannot have moved.
        let mut with = activated_bundle(FORMAT);
        let without = {
            let mut b = with.clone();
            b.attestations[0].activation = None;
            b
        };
        assert_eq!(with.signing_bytes(), without.signing_bytes());
        with.format = FORMAT_V2.into();
        assert_ne!(with.signing_bytes(), without.signing_bytes());
    }

    #[test]
    fn the_v1_signing_bytes_are_pinned() {
        // A v1 bundle with a pre-v4 attestation: the bytes every bundle
        // published before the v2 format was signed over. Pinned so a later
        // edit to signing_bytes cannot move them silently.
        let identity = SigningKey::from_bytes(&[10u8; 32]);
        let ak = SigningKey::from_bytes(&[20u8; 32]);
        let att = crate::attestation::testutil::attestation_with_public(
            "gw-a",
            &identity.verifying_key(),
            &ak,
            vec![crate::attestation::PcrExpectation { index: 16, digest: hex::encode([0x42u8; 32]) }],
        );
        let b = DeploymentBundle {
            attestations: vec![att],
            ..bundle(vec![origin_entry("gw-a", 10)])
        };
        assert_eq!(hex::encode(b.signing_bytes()), PINNED_V1);
    }

    #[test]
    fn a_p256_identity_key_is_an_identity_key_not_a_record_key() {
        let mut entry = origin_entry("gw-tpm", 10);
        entry.algo = "ecdsa-p256".into();
        entry.public_key = format!("04{}", "11".repeat(64));
        let b = bundle(vec![origin_entry("gw-a", 11), entry]);
        let ids = b.active_identity_keys().unwrap();
        assert!(matches!(ids["gw-tpm"], IdentityKey::EcdsaP256(_)));
        // The record-key set, which the sealing path consumes, stays ed25519.
        assert!(matches!(b.active_origin_keys(), Err(Error::UnsupportedAlgo(_))));
    }

    #[test]
    fn the_active_set_resolves_every_key() {
        let b = bundle(vec![origin_entry("gw-a", 10), origin_entry("gw-b", 11)]);
        let map = b.active_origin_keys().unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("gw-a") && map.contains_key("gw-b"));
    }
}
