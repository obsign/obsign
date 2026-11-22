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

    /// `sig` or `enc`. An IdP publishes its encryption keys in the same set
    /// (Keycloak: an `RSA-OAEP` key with `use: "enc"`), and those never
    /// verify a signature. Signed from `obsign-identity/4` on.
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    /// When present, the key verifies only if this lists `verify`. Signed
    /// from `obsign-identity/4` on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

/// Smallest RSA modulus accepted, in bits.
const MIN_RSA_BITS: usize = 2048;

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
    /// Builds the store from the keys that verify signatures.
    ///
    /// A key meant for something else is skipped, not refused: `use: "enc"`,
    /// a `key_ops` without `verify`, or an `alg` that is not a signature
    /// algorithm this verifier knows (`RSA-OAEP`, `ECDH-ES`, ...). An IdP
    /// publishes those beside its signing keys, and refusing the whole set
    /// over one of them would make the JWKS unusable as fetched. What stays
    /// a refusal is a key that claims to sign and cannot be trusted to: a
    /// symmetric algorithm, a curve that contradicts its `alg`, an RSA
    /// modulus under 2048 bits, a missing component. A set left with no
    /// signing key is still `EmptyJwks`.
    pub fn from_set(set: &JwkSet) -> Result<Self, Error> {
        let mut keys = HashMap::new();

        for jwk in &set.keys {
            if jwk.key_use.as_deref().is_some_and(|u| u != "sig")
                || jwk
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| !ops.iter().any(|o| o == "verify"))
            {
                continue;
            }

            let (key, alg) = match jwk.kty.as_str() {
                "RSA" => {
                    let (n, e) = match (&jwk.n, &jwk.e) {
                        (Some(n), Some(e)) => (n, e),
                        _ => return Err(Error::MalformedJwk(jwk.kid.clone())),
                    };
                    let Some(alg) = signing_alg(jwk.alg.as_deref().unwrap_or("RS256"))? else {
                        continue;
                    };
                    if !matches!(
                        alg,
                        Algorithm::RS256
                            | Algorithm::RS384
                            | Algorithm::RS512
                            | Algorithm::PS256
                            | Algorithm::PS384
                            | Algorithm::PS512
                    ) {
                        return Err(Error::MalformedJwk(jwk.kid.clone()));
                    }
                    if rsa_bits(n).ok_or_else(|| Error::MalformedJwk(jwk.kid.clone()))?
                        < MIN_RSA_BITS
                    {
                        return Err(Error::WeakRsaKey(jwk.kid.clone()));
                    }
                    (DecodingKey::from_rsa_components(n, e)?, alg)
                }
                "EC" => {
                    let (x, y) = match (&jwk.x, &jwk.y) {
                        (Some(x), Some(y)) => (x, y),
                        _ => return Err(Error::MalformedJwk(jwk.kid.clone())),
                    };
                    // Without an `alg`, the curve names it; a curve this
                    // verifier has no algorithm for is not a signing key here.
                    let named = match (jwk.alg.as_deref(), jwk.crv.as_deref()) {
                        (Some(a), _) => a,
                        (None, None | Some("P-256")) => "ES256",
                        (None, Some("P-384")) => "ES384",
                        (None, Some(_)) => continue,
                    };
                    let Some(alg) = signing_alg(named)? else {
                        continue;
                    };
                    let curve = match alg {
                        Algorithm::ES256 => "P-256",
                        Algorithm::ES384 => "P-384",
                        _ => return Err(Error::MalformedJwk(jwk.kid.clone())),
                    };
                    if jwk.crv.as_deref().is_some_and(|c| c != curve) {
                        return Err(Error::MalformedJwk(jwk.kid.clone()));
                    }
                    (DecodingKey::from_ec_components(x, y)?, alg)
                }
                "OKP" => {
                    // X25519 and X448 are key-agreement curves, Ed448 has no
                    // verifier here: none of them checks an Ed25519 signature.
                    if jwk.crv.as_deref().is_some_and(|c| c != "Ed25519") {
                        continue;
                    }
                    if let Some(a) = jwk.alg.as_deref() {
                        match signing_alg(a)? {
                            Some(Algorithm::EdDSA) => {}
                            Some(_) => return Err(Error::MalformedJwk(jwk.kid.clone())),
                            None => continue,
                        }
                    }
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

/// The signature algorithm `s` names, `None` for one this verifier does not
/// verify with (an encryption algorithm, or one it does not implement).
fn signing_alg(s: &str) -> Result<Option<Algorithm>, Error> {
    use Algorithm::*;
    Ok(Some(match s {
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
        // not accepted either. Both are refused rather than skipped: such a
        // key says it signs, and the set that carries it is not one to trust.
        "HS256" | "HS384" | "HS512" | "none" => {
            return Err(Error::UnsupportedAlgorithm(s.to_string()))
        }
        _ => return Ok(None),
    }))
}

/// Bit length of a base64url RSA modulus, `None` when it does not decode.
fn rsa_bits(n: &str) -> Option<usize> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n.trim_end_matches('='))
        .ok()?;
    let start = raw.iter().position(|b| *b != 0)?;
    Some((raw.len() - start) * 8 - raw[start].leading_zeros() as usize)
}
