//! Token minting for unit tests.
//!
//! Deliberately `#[cfg(test)]` rather than behind a feature of the `identity`
//! crate: a feature would be unified by cargo and would ship the means to
//! forge tokens inside the production binary. For a proof product, that
//! surface has no business in the shipped artifact.

use obsign_audit_core::checkpoint::PublicKeyEntry;
use base64::Engine;
use ed25519_dalek::SigningKey;
use obsign_identity::bundle::{IdentityBundle, FORMAT};
use obsign_identity::{ClaimMap, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use std::path::PathBuf;

pub const ISSUER: &str = "https://sso.acme.fr/realms/corp";
pub const AUDIENCE: &str = "obsign-proxy";

/// PKCS8 v1 prefix of an Ed25519 private key.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Signing key for the identity bundle.
pub const BUNDLE_SEED: [u8; 32] = [0x22; 32];

/// JWKS holding the keys named by `kids`: `(kid, seed)`.
pub fn jwks_with(kids: &[(&str, u8)]) -> JwkSet {
    let keys: Vec<_> = kids
        .iter()
        .map(|(kid, seed)| {
            let vk = SigningKey::from_bytes(&[*seed; 32]).verifying_key();
            json!({
                "kty": "OKP", "crv": "Ed25519", "kid": kid,
                "alg": "EdDSA", "x": b64(vk.as_bytes()),
            })
        })
        .collect();
    serde_json::from_value(json!({ "keys": keys })).unwrap()
}

pub fn keyring() -> Vec<PublicKeyEntry> {
    let k = SigningKey::from_bytes(&BUNDLE_SEED);
    vec![PublicKeyEntry {
        key_id: "identity-key".into(),
        algo: "ed25519".into(),
        public_key: hex::encode(k.verifying_key().to_bytes()),
        role: Default::default(),
    }]
}

/// Writes a signed identity bundle at the given path.
pub fn write_bundle(path: &PathBuf, version: &str, kids: &[(&str, u8)]) {
    let bundle = IdentityBundle {
        format: FORMAT.to_string(),
        version: version.to_string(),
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks: jwks_with(kids),
        claims: ClaimMap::default(),
    };
    let signed = bundle.sign("identity-key", &SigningKey::from_bytes(&BUNDLE_SEED));
    std::fs::write(path, serde_json::to_string(&signed).unwrap()).unwrap();
}

/// Mints a token expiring in `exp_offset` seconds (negative = already
/// expired).
///
/// `seed` designates both the signing key and, by test convention, the
/// announced `kid`: seed 1 -> `k1`, seed 2 -> `k2`.
pub fn mint(seed: u8, exp_offset: i64, scopes: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    mint_at(seed, now + exp_offset, scopes, None)
}

/// Mints a token with an explicit absolute expiry (seconds) and, optionally,
/// an RFC 8693 `act` claim naming the actor really acting on behalf of the
/// subject. Two tokens minted with the same `exp` differ only by their `act`
/// chain — the token-exchange shape, where the delegated token is bounded by
/// its parent's expiry.
pub fn mint_at(seed: u8, exp: i64, scopes: &str, act_sub: Option<&str>) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&[seed; 32]);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(format!("k{seed}"));

    let mut claims = json!({
        "sub": "u:marie.dupont",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": exp,
        "iat": now - 10,
        "scope": scopes,
        "groups": ["support-n2"],
        // Every mainstream IdP sends a display claim next to the opaque
        // subject. Present here so the tests exercise the shape a real token
        // has, rather than one where `sub` happens to be readable.
        "preferred_username": "marie.dupont",
    });
    if let Some(actor) = act_sub {
        claims["act"] = json!({ "sub": actor });
    }

    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der))
        .expect("minting the test token")
}
