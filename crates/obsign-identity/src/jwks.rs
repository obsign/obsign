use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Error;

/// The identity provider's public key set.
///
/// **Loaded from a file, never from the network.** The gateway sits on the
/// critical path and must be able to run air-gapped: it makes no outbound
/// call. The control plane fetches the JWKS from the provider and ships it
/// inside the signed identity bundle: same channel, same rotation cadence,
/// and one less network surface to justify in a security review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    /// Key family: `RSA`, `EC` or `OKP`.
    pub kty: String,
    /// Identifier, matched against the token's `kid` header.
    pub kid: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,

    // RSA
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,

    // EC and OKP (Ed25519)
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// Ready-to-use keys, indexed by `kid`.
pub struct KeyStore {
    keys: HashMap<String, (DecodingKey, Algorithm)>,
}

/// Manual `Debug`: `DecodingKey` does not implement it, and that is a good
/// thing; we expose only `kid` values and algorithms, never key material in
/// a log.
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kids: Vec<_> = self.keys.iter().map(|(k, (_, a))| (k, a)).collect();
        kids.sort_by_key(|(k, _)| *k);
        f.debug_struct("KeyStore").field("keys", &kids).finish()
    }
}

impl KeyStore {
    pub fn from_set(set: &JwkSet) -> Result<Self, Error> {
        let mut keys = HashMap::new();

        for jwk in &set.keys {
            let (key, alg) = match jwk.kty.as_str() {
                "RSA" => {
                    let (n, e) = match (&jwk.n, &jwk.e) {
                        (Some(n), Some(e)) => (n, e),
                        _ => return Err(Error::MalformedJwk(jwk.kid.clone())),
                    };
                    let alg = parse_alg(jwk.alg.as_deref().unwrap_or("RS256"))?;
                    (DecodingKey::from_rsa_components(n, e)?, alg)
                }
                "EC" => {
                    let (x, y) = match (&jwk.x, &jwk.y) {
                        (Some(x), Some(y)) => (x, y),
                        _ => return Err(Error::MalformedJwk(jwk.kid.clone())),
                    };
                    let alg = parse_alg(jwk.alg.as_deref().unwrap_or("ES256"))?;
                    (DecodingKey::from_ec_components(x, y)?, alg)
                }
                "OKP" => {
                    let x = jwk
                        .x
                        .as_ref()
                        .ok_or_else(|| Error::MalformedJwk(jwk.kid.clone()))?;
                    (DecodingKey::from_ed_components(x)?, Algorithm::EdDSA)
                }
                other => return Err(Error::UnsupportedKeyType(other.to_string())),
            };

            if keys.insert(jwk.kid.clone(), (key, alg)).is_some() {
                // Two keys for the same kid: we can no longer tell which one
                // signed. Ambiguous, therefore refused.
                return Err(Error::DuplicateKid(jwk.kid.clone()));
            }
        }

        if keys.is_empty() {
            return Err(Error::EmptyJwks);
        }

        Ok(KeyStore { keys })
    }

    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)?;
        let set: JwkSet = serde_json::from_str(&raw)?;
        Self::from_set(&set)
    }

    /// Finds the key designated by the token header.
    ///
    /// The `kid` is mandatory: without it we would have to try every key,
    /// which hides a failed rotation and muddies diagnosis.
    pub fn get(&self, kid: &str) -> Result<&(DecodingKey, Algorithm), Error> {
        self.keys
            .get(kid)
            .ok_or_else(|| Error::UnknownKid(kid.to_string()))
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn parse_alg(s: &str) -> Result<Algorithm, Error> {
    use Algorithm::*;
    Ok(match s {
        "RS256" => RS256,
        "RS384" => RS384,
        "RS512" => RS512,
        "PS256" => PS256,
        "PS384" => PS384,
        "PS512" => PS512,
        "ES256" => ES256,
        "ES384" => ES384,
        "EdDSA" => EdDSA,
        // HMAC algorithms are deliberately absent: a symmetric key in a
        // published JWKS would be a vulnerability, and `none` is obviously
        // not accepted either.
        other => return Err(Error::UnsupportedAlgorithm(other.to_string())),
    })
}
