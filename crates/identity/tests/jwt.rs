//! Token verification tests.
//!
//! We use Ed25519: key generation is instantaneous, where RSA would make the
//! suite too slow to run on every commit. The algorithm is not what these
//! tests are about — the checks around it are.

use base64::Engine;
use ed25519_dalek::SigningKey;
use identity::{Error, JwkSet, KeyStore, Verifier};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const ISSUER: &str = "https://sso.acme.fr/realms/corp";
const AUDIENCE: &str = "probant-proxy";

/// PKCS8 v1 prefix of an Ed25519 private key: a fixed structure, you just
/// append the 32-byte seed behind it.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct Idp {
    seed: [u8; 32],
    kid: String,
}

impl Idp {
    fn new(kid: &str, seed_byte: u8) -> Self {
        Idp {
            seed: [seed_byte; 32],
            kid: kid.to_string(),
        }
    }

    fn jwk(&self) -> serde_json::Value {
        let vk = SigningKey::from_bytes(&self.seed).verifying_key();
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "alg": "EdDSA",
            "x": b64(vk.as_bytes()),
        })
    }

    fn mint(&self, claims: serde_json::Value) -> String {
        let mut der = PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&self.seed);
        let key = EncodingKey::from_ed_der(&der);

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, &claims, &key).expect("minting the token")
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims() -> serde_json::Value {
    json!({
        "sub": "u:marie.dupont",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now() + 1800,
        "iat": now(),
        "scope": "support:read support:ticket_update",
        "groups": ["support-n2"],
    })
}

fn verifier(idp: &Idp) -> Verifier {
    let set: JwkSet = serde_json::from_value(json!({ "keys": [idp.jwk()] })).unwrap();
    Verifier::new(KeyStore::from_set(&set).unwrap(), ISSUER, AUDIENCE)
}

#[test]
fn a_valid_token_yields_a_proven_delegation() {
    let idp = Idp::new("k1", 1);
    let d = verifier(&idp).verify(&idp.mint(claims())).unwrap();

    assert_eq!(d.subject, "u:marie.dupont");
    // The real issuer, not `cli://declared`: this is what attests in the log
    // that the identity was verified.
    assert_eq!(d.issuer, ISSUER);
    assert_eq!(d.scopes, vec!["support:read", "support:ticket_update"]);
    assert_eq!(d.groups, vec!["support-n2"]);
    assert!(!d.is_expired(now() * 1000));
    assert!(d.remaining_secs(now() * 1000) > 1700);
}

#[test]
fn forged_signature_is_refused() {
    let idp = Idp::new("k1", 1);
    let token = idp.mint(claims());

    // We change a character *in the middle* of the signature, never the last
    // one: in base64url the padding bits of the final character are ignored on
    // decode, so several characters map to the same bytes there and the
    // tampering would have no effect.
    let mut parts: Vec<&str> = token.split('.').collect();
    let sig = parts[2];
    let mid = sig.len() / 2;
    let replacement = if sig.as_bytes()[mid] == b'A' { 'B' } else { 'A' };
    let altered = format!("{}{replacement}{}", &sig[..mid], &sig[mid + 1..]);
    parts[2] = &altered;

    assert!(verifier(&idp).verify(&parts.join(".")).is_err());
}

#[test]
fn modified_payload_is_refused() {
    // The scenario that matters: someone grants themselves an extra scope.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(claims());
    let parts: Vec<&str> = token.split('.').collect();

    let escalated = b64(
        json!({
            "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
            "exp": now() + 1800, "scope": "db:admin",
        })
        .to_string()
        .as_bytes(),
    );

    let forged = format!("{}.{}.{}", parts[0], escalated, parts[2]);
    assert!(verifier(&idp).verify(&forged).is_err());
}

#[test]
fn different_issuer_is_refused() {
    // A perfectly valid token, but issued by another provider.
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    c["iss"] = json!("https://sso.attacker.example/realms/corp");
    assert!(verifier(&idp).verify(&idp.mint(c)).is_err());
}

#[test]
fn different_audience_is_refused() {
    // The classic trap: a legitimate token, signed by the right provider, but
    // intended for another service. Verifying the signature without verifying
    // the audience would let it through.
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    c["aud"] = json!("another-service");
    assert!(verifier(&idp).verify(&idp.mint(c)).is_err());
}

#[test]
fn expired_token_is_refused() {
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    // Beyond the 60 s clock tolerance.
    c["exp"] = json!(now() - 3600);
    assert!(verifier(&idp).verify(&idp.mint(c)).is_err());
}

#[test]
fn unknown_kid_is_refused() {
    let idp = Idp::new("k1", 1);
    let other = Idp::new("k-unknown", 2);
    let err = verifier(&idp).verify(&other.mint(claims())).unwrap_err();
    assert!(matches!(err, Error::UnknownKid(_)), "got {err:?}");
}

#[test]
fn algorithm_confusion_is_refused() {
    // The historical JWT attack: the token declares HS256 and is HMAC-signed
    // with the IdP's *public* key, which everyone knows. If we trusted
    // `header.alg`, it would pass. Hence the algorithm comes from the JWKS,
    // never from the token.
    let idp = Idp::new("k1", 1);
    let vk = SigningKey::from_bytes(&idp.seed).verifying_key();

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".to_string());
    let forged = jsonwebtoken::encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(vk.as_bytes()),
    )
    .unwrap();

    assert!(verifier(&idp).verify(&forged).is_err());
}

#[test]
fn token_without_kid_is_refused() {
    let idp = Idp::new("k1", 1);
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&idp.seed);
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &claims(),
        &EncodingKey::from_ed_der(&der),
    )
    .unwrap();

    assert!(matches!(
        verifier(&idp).verify(&token).unwrap_err(),
        Error::MissingKid
    ));
}

#[test]
fn array_scopes_are_accepted() {
    // Entra ID emits `scp` as an array where Keycloak emits `scope` as a string.
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    c.as_object_mut().unwrap().remove("scope");
    c["scp"] = json!(["support:read", "support:ticket_update"]);

    let d = verifier(&idp).verify(&idp.mint(c)).unwrap();
    assert_eq!(d.scopes, vec!["support:read", "support:ticket_update"]);
}

#[test]
fn groups_and_roles_are_merged() {
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    c["groups"] = json!(["support-n2", "dba"]);
    c["roles"] = json!(["oncall", "dba"]);

    let d = verifier(&idp).verify(&idp.mint(c)).unwrap();
    // Merged, sorted and deduplicated: "dba" appears in both claims.
    assert_eq!(d.groups, vec!["dba", "oncall", "support-n2"]);
}

#[test]
fn token_without_scope_is_refused() {
    // An empty delegation would only authorize tools requiring no scope.
    // That is nearly always a configuration mistake: better to fail loudly
    // than to let an agent run with empty permissions.
    let idp = Idp::new("k1", 1);
    let mut c = claims();
    c.as_object_mut().unwrap().remove("scope");

    assert!(matches!(
        verifier(&idp).verify(&idp.mint(c)).unwrap_err(),
        Error::NoScopes
    ));
}

#[test]
fn duplicate_kid_in_the_jwks_is_refused() {
    // Two keys for the same kid: impossible to tell which one signed.
    let a = Idp::new("k1", 1);
    let b = Idp::new("k1", 2);
    let set: JwkSet =
        serde_json::from_value(json!({ "keys": [a.jwk(), b.jwk()] })).unwrap();

    assert!(matches!(
        KeyStore::from_set(&set).unwrap_err(),
        Error::DuplicateKid(_)
    ));
}

#[test]
fn empty_jwks_is_refused() {
    let set: JwkSet = serde_json::from_value(json!({ "keys": [] })).unwrap();
    assert!(matches!(
        KeyStore::from_set(&set).unwrap_err(),
        Error::EmptyJwks
    ));
}

#[test]
fn symmetric_algorithm_is_forbidden_in_a_jwks() {
    // An HMAC key in a distributed JWKS would be a published shared secret.
    let set: JwkSet = serde_json::from_value(json!({
        "keys": [{ "kty": "RSA", "kid": "k1", "alg": "HS256",
                   "n": "abc", "e": "AQAB" }]
    }))
    .unwrap();

    assert!(matches!(
        KeyStore::from_set(&set).unwrap_err(),
        Error::UnsupportedAlgorithm(_)
    ));
}
