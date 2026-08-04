use obsign_audit_core::canonical::Encoder;
use obsign_audit_core::hash::{digest, domain, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::claims::ClaimMap;
use crate::jwks::{Jwk, JwkSet};
use crate::Error;

/// Current format: the display-label paths join the signed bytes.
pub const FORMAT: &str = "obsign-identity/3";
/// First format. Still verifiable (a bundle published before the revision
/// keeps its hash and its signature), but its signature does not cover
/// machine markers, so only the default markers are accepted with it.
pub const FORMAT_V1: &str = "obsign-identity/1";
/// Machine markers signed, label paths not yet. Same rule as v1 for what its
/// signature does not cover.
pub const FORMAT_V2: &str = "obsign-identity/2";

/// Identity configuration, signed and distributed by the control plane.
///
/// Why a signed artifact rather than a plain JWKS file passed as an option:
/// **the JWKS decides who can sign valid tokens**. Whoever can write that file
/// can mint an identity for themselves and bypass the entire attribution
/// chain. That is exactly the same threat as an unsigned policy bundle, and it
/// deserves the same answer.
///
/// The claim mapping lives in the same artifact for the same reason: it
/// determines which groups get assigned, hence which Cedar rules apply.
/// Moving it from one path to another changes authorization outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityBundle {
    pub format: String,
    /// Version, typically `identity@<git sha>`.
    pub version: String,
    /// Expected issuer (`iss` claim).
    pub issuer: String,
    /// Expected audience (`aud` claim).
    ///
    /// Known operational trap: Keycloak access tokens carry `aud: "account"`
    /// by default. You must configure an audience mapper in the realm. Never
    /// relax the check on this side.
    pub audience: String,
    pub jwks: JwkSet,
    #[serde(default)]
    pub claims: ClaimMap,
}

impl IdentityBundle {
    /// Bytes that are signed. Explicit canonical encoding, never the JSON.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.format)
            .str(&self.version)
            .str(&self.issuer)
            .str(&self.audience);

        // Keys sorted by kid: their order in the file must not change the
        // signature.
        let mut keys: Vec<&Jwk> = self.jwks.keys.iter().collect();
        keys.sort_by(|a, b| a.kid.cmp(&b.kid));
        e.u64(keys.len() as u64);
        for k in keys {
            e.str(&k.kty)
                .str(&k.kid)
                .opt_str(k.alg.as_deref())
                .opt_str(k.crv.as_deref())
                .opt_str(k.n.as_deref())
                .opt_str(k.e.as_deref())
                .opt_str(k.x.as_deref())
                .opt_str(k.y.as_deref());
        }

        e.str(&self.claims.subject)
            .str_seq(&self.claims.scopes)
            .str_seq(&self.claims.groups)
            .str_seq(&self.claims.client_id);

        // v2 extends the signed bytes with the machine markers; v1 bytes stay
        // exactly as they were so that already-published bundles keep their
        // hash and signature. The format string is itself signed (first field
        // above), so an attacker cannot relabel a v1 bundle as v2 or the
        // reverse.
        if self.format != FORMAT_V1 {
            let m = &self.claims.machine;
            e.u64(m.subject_is_client as u64);
            e.u64(m.equals.len() as u64);
            for r in &m.equals {
                e.str(&r.path).str(&r.value);
            }
            e.u64(m.prefixes.len() as u64);
            for r in &m.prefixes {
                e.str(&r.path).str(&r.value);
            }
        }

        // v3 extends again, with the claims a display label may be read
        // from. Signed for the same reason the subject path is: whoever
        // chooses the claim chooses the name an investigation will read, and
        // pointing it at an attacker-controlled claim would let a log say
        // "guillaume" about someone else.
        if self.format != FORMAT_V1 && self.format != FORMAT_V2 {
            e.str_seq(&self.claims.labels);
        }

        digest(domain::IDENTITY_BUNDLE, e.finish())
            .as_bytes()
            .to_vec()
    }

    pub fn hash(&self) -> Hash {
        let b = self.signing_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        Hash(a)
    }

    pub fn sign(self, key_id: impl Into<String>, key: &SigningKey) -> SignedIdentityBundle {
        let sig = key.sign(&self.signing_bytes());
        SignedIdentityBundle {
            bundle: self,
            key_id: key_id.into(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedIdentityBundle {
    pub bundle: IdentityBundle,
    pub key_id: String,
    pub signature: String,
}

impl SignedIdentityBundle {
    pub fn verify(&self, key: &VerifyingKey) -> Result<&IdentityBundle, Error> {
        let raw = hex::decode(&self.signature).map_err(|_| Error::BadBundleSignature)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadBundleSignature)?;
        key.verify(&self.bundle.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadBundleSignature)?;
        // Each older format is accepted, and refuses exactly what its own
        // signature does not cover. Re-signing at the current format is one
        // `obsign-control compile` away, and is the only way to use a field
        // an older signature never saw.
        match self.bundle.format.as_str() {
            FORMAT => {}
            FORMAT_V1 => {
                // A v1 signature does not cover the markers. Accepting a v1
                // file that carries non-default ones would let unsigned JSON
                // decide who counts as human — exactly the threat the signed
                // bundle exists to close.
                if self.bundle.claims.machine != crate::claims::MachineMarkers::default() {
                    return Err(Error::UnsignedMachineMarkers);
                }
                if self.bundle.claims.labels != crate::claims::default_labels() {
                    return Err(Error::UnsignedLabelPaths);
                }
            }
            FORMAT_V2 => {
                // v2 signs the markers but not the label paths. Same rule:
                // an unsigned label path chooses the name a log will carry.
                if self.bundle.claims.labels != crate::claims::default_labels() {
                    return Err(Error::UnsignedLabelPaths);
                }
            }
            other => return Err(Error::UnknownBundleFormat(other.to_string())),
        }
        Ok(&self.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{MachineMarkers, MarkerMatch};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn bundle(format: &str) -> IdentityBundle {
        IdentityBundle {
            format: format.into(),
            version: "identity@test".into(),
            issuer: "https://idp.example".into(),
            audience: "obsign".into(),
            jwks: JwkSet { keys: vec![] },
            claims: ClaimMap::default(),
        }
    }

    #[test]
    fn v2_roundtrip() {
        let k = key();
        let signed = bundle(FORMAT).sign("k1", &k);
        assert!(signed.verify(&k.verifying_key()).is_ok());
    }

    #[test]
    fn v1_with_default_markers_still_verifies() {
        // A bundle published before the format revision keeps verifying:
        // its signing bytes are unchanged by the v2 extension.
        let k = key();
        let signed = bundle(FORMAT_V1).sign("k1", &k);
        assert!(signed.verify(&k.verifying_key()).is_ok());
    }

    #[test]
    fn v1_with_custom_markers_is_refused() {
        // The v1 signature does not cover the markers: a valid signature plus
        // attacker-chosen markers must not pass, else unsigned JSON decides
        // who counts as human.
        let k = key();
        let mut b = bundle(FORMAT_V1);
        b.claims.machine.subject_is_client = false;
        let signed = b.sign("k1", &k);
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(Error::UnsignedMachineMarkers)
        ));
    }

    #[test]
    fn an_older_format_with_custom_label_paths_is_refused() {
        // Neither v1 nor v2 signs the label paths. A valid signature over
        // older bytes plus an attacker-chosen label path must not pass: the
        // path decides which claim becomes the name an investigation reads,
        // so pointing it at a claim the token's holder controls would let a
        // log say "guillaume" about someone else.
        let k = key();
        for fmt in [FORMAT_V1, FORMAT_V2] {
            let mut b = bundle(fmt);
            b.claims.labels = vec!["/attacker_controlled".into()];
            let signed = b.sign("k1", &k);
            assert!(
                matches!(signed.verify(&k.verifying_key()), Err(Error::UnsignedLabelPaths)),
                "{fmt} must refuse label paths its signature does not cover"
            );
        }
    }

    #[test]
    fn v3_label_paths_are_covered_by_the_signature() {
        let k = key();
        let mut signed = bundle(FORMAT).sign("k1", &k);
        signed.bundle.claims.labels.push("/x".into());
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(Error::BadBundleSignature)
        ));
    }

    #[test]
    fn v2_markers_are_covered_by_the_signature() {
        let k = key();
        let mut signed = bundle(FORMAT).sign("k1", &k);
        signed.bundle.claims.machine.equals.push(MarkerMatch {
            path: "/x".into(),
            value: "y".into(),
        });
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(Error::BadBundleSignature)
        ));
    }

    #[test]
    fn format_string_is_signed() {
        // Relabelling a v1 bundle as v2 (or the reverse) must break the
        // signature: the format decides which bytes the signature covers.
        let k = key();
        let mut signed = bundle(FORMAT_V1).sign("k1", &k);
        signed.bundle.format = FORMAT.into();
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(Error::BadBundleSignature)
        ));
    }

    #[test]
    fn custom_markers_change_the_hash() {
        let a = bundle(FORMAT);
        let mut b = bundle(FORMAT);
        b.claims.machine = MachineMarkers {
            subject_is_client: true,
            equals: vec![],
            prefixes: vec![],
        };
        assert_ne!(a.hash(), b.hash());
    }
}
