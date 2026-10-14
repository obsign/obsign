//! Token verification tests.
//!
//! We use Ed25519: key generation is instantaneous, where RSA would make the
//! suite too slow to run on every commit. The algorithm is not what these
//! tests are about; the checks around it are.

use base64::Engine;
use ed25519_dalek::SigningKey;
use obsign_identity::{Error, JwkSet, KeyStore, Verifier};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const ISSUER: &str = "https://sso.acme.fr/realms/corp";
const AUDIENCE: &str = "obsign-proxy";

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

// --------------------------------------------------------------------------
// Claim type confusion.
//
// jsonwebtoken deserializes each spec claim into a `TryParse`. A claim it
// could not parse used to be handled exactly like an absent one -- its check
// skipped, no error raised -- which is CVE-2026-25537, fixed upstream in
// 10.3.0 for the time-based claims. The audience is NOT covered by that fix:
// on 11.1.0 an `aud` that is absent or of the wrong type still falls through
// a catch-all unless `set_required_spec_claims` names it. The tokens below
// were all accepted before that line landed, each carrying a scope its
// bearer was never granted; the first two still would be without it.
//
// The symmetrical cases matter as much: a provider that omits `nbf`, or one
// that sends `aud` as an array, must keep working. Those are pinned too.

#[test]
fn an_audience_of_the_wrong_type_is_refused() {
    // Same trusted issuer, but the token was minted for ANOTHER service and
    // carries its audience as a number. Skipping the check here accepts a
    // token addressed to someone else.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER, "aud": 1234,
        "exp": now() + 1800, "scope": "db:admin",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

#[test]
fn a_token_without_an_audience_is_refused() {
    // The likelier variant: no type trickery, the claim is simply missing.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER,
        "exp": now() + 1800, "scope": "db:admin",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

#[test]
fn an_issuer_of_the_wrong_type_is_refused() {
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": 42, "aud": AUDIENCE,
        "exp": now() + 1800, "scope": "db:admin",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

#[test]
fn a_not_before_of_the_wrong_type_is_refused() {
    // `nbf` an hour out, as a string. Parsed as a number it is an
    // ImmatureSignature; left unparsed it used to be no constraint at all.
    // This is the half of CVE-2026-25537 the library itself now refuses, so
    // the assertion is on the refusal and not on which layer produced it:
    // naming the variant would pin an implementation detail of the
    // dependency, and this test exists to catch that dependency regressing.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
        "exp": now() + 1800, "nbf": format!("{}", now() + 3600),
        "scope": "support:read",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

#[test]
fn a_numeric_not_before_in_the_future_is_still_refused() {
    // The control for the test above: the check itself was never broken, only
    // its malformed case. This pins that the fix did not replace one skip
    // with another.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
        "exp": now() + 1800, "nbf": now() + 3600,
        "scope": "support:read",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

#[test]
fn a_token_without_a_not_before_is_still_accepted() {
    // Most providers omit `nbf`. Requiring it outright would have been the
    // easy fix and would have locked them all out.
    let idp = Idp::new("k1", 1);
    let d = verifier(&idp).verify(&idp.mint(claims())).unwrap();

    assert_eq!(d.subject, "u:marie.dupont");
}

#[test]
fn a_past_numeric_not_before_is_accepted() {
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
        "exp": now() + 1800, "nbf": now() - 60,
        "scope": "support:read",
    }));

    assert_eq!(verifier(&idp).verify(&token).unwrap().subject, "u:marie.dupont");
}

#[test]
fn an_audience_array_containing_us_is_accepted() {
    // RFC 7519 allows `aud` to be an array. Tightening the type check must
    // not narrow it to a string.
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER,
        "aud": ["some-other-service", AUDIENCE],
        "exp": now() + 1800, "scope": "support:read",
    }));

    assert_eq!(verifier(&idp).verify(&token).unwrap().subject, "u:marie.dupont");
}

#[test]
fn an_audience_array_without_us_is_refused() {
    let idp = Idp::new("k1", 1);
    let token = idp.mint(json!({
        "sub": "u:marie.dupont", "iss": ISSUER,
        "aud": ["some-other-service", "a-third-one"],
        "exp": now() + 1800, "scope": "support:read",
    }));

    assert!(verifier(&idp).verify(&token).is_err());
}

// --------------------------------------------------------------------------
// The RSA and EC key paths.
//
// The suite above is Ed25519 for speed, and the module doc says so. But
// `jwks.rs` also accepts `kty: "RSA"` and `kty: "EC"`, and those are what an
// enterprise IdP actually serves -- Keycloak and Entra sign RS256 by
// default. Until jsonwebtoken 11 the implementation behind them was `ring`;
// it is now aws-lc. Swapping the backend under two code paths that no test
// exercised is how a verifier starts refusing every token from the one
// provider class the product is sold into, in production, on a Monday.
//
// The keys are fixed rather than generated: a 2048-bit keygen per test run
// is the cost the module doc refused, and a constant costs nothing. They are
// test material, generated for this file, and sign nothing else.

const RSA_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbE4Q1pyqSL170\nNeShpefGA4Eu6kJNmSN4GZJSz6R+U38qQ9OVckzZTtB1Jt2nFcVbXX2G1i9X7eyr\nbgMQB5k4vQNmz5VEnL1Gxm6w/HAtg5bcIgSw0rD/Vb/tcohN75wc6RcOcKdLcwpH\n+4Z0Sv3UNvCT15yaxP0mLcD5/laE+HCdIM72F/NCs5X4TO188cE9qrqFUMKxA+5v\nVdYkHJWgkzejiJtaoH2SFd6Rh/WfP2gf2FhFd+fGTPvI9cuaqBVLaPuz7YdRaTuw\nURseJlBiE3VWO94rBIdENxl2gX1diJMcFhxv/ewiqc404hsgQHSWkAFQ+2Enntsw\nL0yJ5/8fAgMBAAECggEAAeHhQ3N1gVPA3879qPamExG80jB2wJFgzFbnH0k08nGa\nBA3RtikuhJ6/ygRAQYRyolLGsMnNxk/1hPkvYVTuR7GHpopTggMzCvZippRR2kOU\nI7ToAKt2CYtlaoDu5Z9IclNj+8FjTnelgs0rSyMT5K0MC4dc98X3WqzIgGBVdYS3\npucBqxdrB99AMwRvsgR4ZV+DFazRqW2b+LQ8WTfRZrLWJXs78x6OwBa49469GVID\npUskT/eM2euAy5NQA7Iz61+6a7IFnv7fKas2yrUOR3F0HW57QnZF8XSz657u3JNb\nIPbW4o2pu8Igh8K/WBJIJyqoDLFD0dMvpMYUyMzfDQKBgQDIlDFwisvk7+i26efv\nc+qw4S4sBxs0lPuQp7URShy/BzGtvr8PkD83hIeGlbXlP0BxzF90CMlmGr8YHDzl\ns5ib3Ppmf8YgtwVzTaef70hl7jnhhYxyCtRTKR/t0hDLFiOA+3ywUj86mLlvpT0B\nvVg9Rfu950FhpGZfDilfO+4j4wKBgQDF7LnDwf9Dz7mhqkSU+qdabZJ0C1qdo0RB\nXBOjZe7nplZ8b6/Sy/yWx7thEKwKPdj/4Z6rkDxSiNh65nPXQebjmqIjd+nVTNX5\ncsrNG+3Zjs6d/TmUDGLrTZFWVsUtXlWO4vuferuLRMtt4hmPjIp/QYPxPTctqdYF\nZdpNkGE0lQKBgFdWuCRyO5BnquSi+3x39BSrKMjBG2aNDPGTJTPvGo9P2aD3Mwja\n3bwV+FFxNTAql6w1usay4MeWE+myug2nY2dTFLG3J5WtPDFV+gyZS+QelJOP7HTo\nJEZF3QJYezmDXVhXqZa5aZDhWbW0tNjiEt8zbwfk/8I9rNntN7ShSvPTAoGAQWoH\ny2cmkqbo10GLASIGhaCJMsk93bPEL0XbR7m8x9r14pKXLbg1dy/0AhSch5YBTjCn\nXFSDW1PXGGdqCc7CHJ9Szx4mrlSCs7r4w+ljJvBH4Xd7vC6L0vEEA+ERsfjnlh32\nw7KwoUrPYTXE9OiiLYTdsrFktzbWgVo0WEZLmjECgYEAkKKTL49bXZzdGKhj6eyH\n4FNsLR3tXYdYfmX06n7E2xI5WZX3wViZfYi3qV13Lvn5RUH2cs8J+WXcRR5uqKGu\ndYDb3mKtz9m3e0NNYxPlZkj2N8ssb/Zsb1vqHWBc5URa3/aWBGT0VFpl0tttUAGI\nb98wCxGTbBQI7kxiNsce9L0=\n-----END PRIVATE KEY-----";

const RSA_N: &str = "mxOENacqki9e9DXkoaXnxgOBLupCTZkjeBmSUs-kflN_KkPTlXJM2U7QdSbdpxXFW119htYvV-3sq24DEAeZOL0DZs-VRJy9RsZusPxwLYOW3CIEsNKw_1W_7XKITe-cHOkXDnCnS3MKR_uGdEr91Dbwk9ecmsT9Ji3A-f5WhPhwnSDO9hfzQrOV-EztfPHBPaq6hVDCsQPub1XWJByVoJM3o4ibWqB9khXekYf1nz9oH9hYRXfnxkz7yPXLmqgVS2j7s-2HUWk7sFEbHiZQYhN1VjveKwSHRDcZdoF9XYiTHBYcb_3sIqnONOIbIEB0lpABUPthJ57bMC9Mief_Hw";

const EC_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHxecRClzMqvrMx6C\nR+XCB9GX5uKWFdIyNz0C5LZeNhGhRANCAARkCegKc7AMZPJ0HP6k01CwNw9fddB/\nMvq7b1xUmfOHUi5QGsRs1E2x5vO321+NpuTfkpYkw8SSwJwfSF20d49P\n-----END PRIVATE KEY-----";

const EC_X: &str = "ZAnoCnOwDGTydBz-pNNQsDcPX3XQfzL6u29cVJnzh1I";
const EC_Y: &str = "LlAaxGzUTbHm87fbX42m5N-SliTDxJLAnB9IXbR3j08";

fn verifier_for(jwk: serde_json::Value) -> Verifier {
    let set: JwkSet = serde_json::from_value(json!({ "keys": [jwk] })).unwrap();
    Verifier::new(KeyStore::from_set(&set).unwrap(), ISSUER, AUDIENCE)
}

#[test]
fn an_rs256_token_from_an_rsa_jwk_verifies() {
    let key = EncodingKey::from_rsa_pem(RSA_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("rsa-1".into());
    let token = jsonwebtoken::encode(&header, &claims(), &key).unwrap();

    let v = verifier_for(json!({
        "kty": "RSA", "kid": "rsa-1", "alg": "RS256",
        "n": RSA_N, "e": "AQAB",
    }));

    assert_eq!(v.verify(&token).unwrap().subject, "u:marie.dupont");
}

#[test]
fn a_tampered_rs256_token_is_refused() {
    // The positive test above proves the backend can verify. This one proves
    // it is verifying, and not waving the signature through.
    let key = EncodingKey::from_rsa_pem(RSA_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("rsa-1".into());
    let token = jsonwebtoken::encode(&header, &claims(), &key).unwrap();

    let mut parts: Vec<&str> = token.split('.').collect();
    let forged_payload = b64(
        &serde_json::to_vec(&json!({
            "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
            "exp": now() + 1800, "scope": "db:admin",
        }))
        .unwrap(),
    );
    parts[1] = &forged_payload;
    let forged = parts.join(".");

    let v = verifier_for(json!({
        "kty": "RSA", "kid": "rsa-1", "alg": "RS256",
        "n": RSA_N, "e": "AQAB",
    }));

    assert!(v.verify(&forged).is_err());
}

#[test]
fn an_es256_token_from_an_ec_jwk_verifies() {
    let key = EncodingKey::from_ec_pem(EC_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ec-1".into());
    let token = jsonwebtoken::encode(&header, &claims(), &key).unwrap();

    let v = verifier_for(json!({
        "kty": "EC", "kid": "ec-1", "alg": "ES256",
        "crv": "P-256", "x": EC_X, "y": EC_Y,
    }));

    assert_eq!(v.verify(&token).unwrap().subject, "u:marie.dupont");
}

#[test]
fn a_tampered_es256_token_is_refused() {
    let key = EncodingKey::from_ec_pem(EC_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ec-1".into());
    let token = jsonwebtoken::encode(&header, &claims(), &key).unwrap();

    let mut parts: Vec<&str> = token.split('.').collect();
    let forged_payload = b64(
        &serde_json::to_vec(&json!({
            "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
            "exp": now() + 1800, "scope": "db:admin",
        }))
        .unwrap(),
    );
    parts[1] = &forged_payload;
    let forged = parts.join(".");

    let v = verifier_for(json!({
        "kty": "EC", "kid": "ec-1", "alg": "ES256",
        "crv": "P-256", "x": EC_X, "y": EC_Y,
    }));

    assert!(v.verify(&forged).is_err());
}
