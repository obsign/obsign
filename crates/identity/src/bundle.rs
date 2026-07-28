use audit_core::canonical::Encoder;
use audit_core::hash::{digest, domain, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::claims::ClaimMap;
use crate::jwks::{Jwk, JwkSet};
use crate::Error;

pub const FORMAT: &str = "probant-identity/1";

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
    /// by default. You must configure an audience mapper in the realm — never
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
        if self.bundle.format != FORMAT {
            return Err(Error::UnknownBundleFormat(self.bundle.format.clone()));
        }
        Ok(&self.bundle)
    }
}
