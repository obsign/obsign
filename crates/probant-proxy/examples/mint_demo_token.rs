//! Demo identity provider.
//!
//! Writes a signed identity bundle (issuer, audience, JWKS, claim mapping) and
//! a token, then adds its public key to the trusted keys file produced by
//! `mkbundle`.
//!
//!     cargo run -p probant-proxy --example mint_demo_token -- /tmp/demo [ttl_s] [mode] [kid]
//!
//! A negative `ttl_s` produces an already-expired token. `kid` (default `k1`)
//! selects the IdP signing key: changing it simulates a key rotation on the
//! provider side. `mode` is one of:
//!
//! * `user`     — plain user token (default);
//! * `exchange` — token from an RFC 8693 token exchange, with an `act` claim;
//! * `service`  — `client_credentials` token: no human behind it.
//!
//! The claims are deliberately emitted **in the Keycloak shape**: roles under
//! `realm_access.roles` and `resource_access.<client>.roles`, no flat array.
//! That is what a real realm returns, and what a naive mapping breaks on.
//!
//! Built as an *example* rather than a binary: the means to forge tokens has
//! no business in the shipped artifact.

use base64::Engine;
use ed25519_dalek::SigningKey;
use identity::bundle::{IdentityBundle, FORMAT};
use identity::{ClaimMap, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const ISSUER: &str = "https://sso.acme.fr/realms/corp";
const AUDIENCE: &str = "probant-proxy";
const KEY_ID: &str = "identity-key-2026";

/// PKCS8 v1 prefix of an Ed25519 private key.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/demo".into());
    let exp: i64 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1800".into())
        .parse()
        .expect("ttl in seconds");
    let mode = std::env::args().nth(3).unwrap_or_else(|| "user".into());
    let kid = std::env::args().nth(4).unwrap_or_else(|| "k1".into());

    std::fs::create_dir_all(&dir).expect("creating the directory");

    // Fixed seed: this is a demo. In production the IdP private key never
    // leaves its HSM, and the bundle signing key is the control plane's.
    //
    // One seed per kid: changing the kid changes the key, which reproduces
    // exactly a rotation on the identity provider side.
    let idp_seed = [kid.bytes().fold(9u8, |a, b| a.wrapping_add(b)); 32];
    let bundle_seed = [0x22u8; 32];

    let idp_pub = SigningKey::from_bytes(&idp_seed).verifying_key();
    let jwks: JwkSet = serde_json::from_value(json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": kid,
            "alg": "EdDSA", "x": b64(idp_pub.as_bytes()),
        }]
    }))
    .unwrap();

    // Default mapping: it already covers Keycloak, Entra ID and Okta.
    let bundle = IdentityBundle {
        format: FORMAT.to_string(),
        version: format!("identity@{kid}"),
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks,
        claims: ClaimMap::default(),
    };

    let bundle_key = SigningKey::from_bytes(&bundle_seed);
    let signed = bundle.sign(KEY_ID, &bundle_key);
    std::fs::write(
        format!("{dir}/identity-bundle.json"),
        serde_json::to_string_pretty(&signed).unwrap(),
    )
    .unwrap();

    // Add the identity bundle key to the trusted keyring, next to the policy
    // bundle key.
    let keys_path = format!("{dir}/trusted-keys.json");
    let mut keys: Vec<serde_json::Value> = std::fs::read_to_string(&keys_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    keys.retain(|k| k.get("key_id").and_then(|v| v.as_str()) != Some(KEY_ID));
    keys.push(json!({
        "key_id": KEY_ID,
        "algo": "ed25519",
        "public_key": hex::encode(bundle_key.verifying_key().to_bytes()),
    }));
    std::fs::write(&keys_path, serde_json::to_string_pretty(&keys).unwrap()).unwrap();

    // --- The token ------------------------------------------------------
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Keycloak shape: nothing flat, everything under realm_access /
    // resource_access.
    let mut claims = json!({
        "sub": "u:marie.dupont",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "azp": "probant-proxy",
        "exp": now + exp,
        "iat": now - 10,
        "scope": "support:read support:ticket_update",
        "realm_access": { "roles": ["support-n2", "offline_access"] },
        "resource_access": { "probant-proxy": { "roles": ["ticket-writer"] } },
    });

    match mode.as_str() {
        // RFC 8693 token exchange: `sub` stays the human, `act` names the
        // agent acting on their behalf.
        "exchange" => {
            claims["act"] = json!({ "sub": "support-copilot" });
        }
        // client_credentials: `sub` == `client_id`, nobody behind it.
        "service" => {
            claims["sub"] = json!("batch-agent");
            claims["azp"] = json!("batch-agent");
            claims["client_id"] = json!("batch-agent");
        }
        _ => {}
    }

    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&idp_seed);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.clone());

    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der))
        .expect("minting the token");
    std::fs::write(format!("{dir}/token.jwt"), &token).unwrap();

    println!("identity bundle : {dir}/identity-bundle.json");
    println!("trusted keys    : {keys_path}");
    println!("token           : {dir}/token.jwt  (mode {mode}, kid {kid}, ttl {exp} s)");
}
