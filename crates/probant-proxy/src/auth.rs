use audit_core::record::PrincipalKind;
use identity::{BundleSource, Delegation, ReloadOutcome};
use std::path::{Path, PathBuf};

/// Source of the identity the agent acts under.
///
/// Two deliberately asymmetric modes: OIDC is the normal one, declared mode
/// requires an explicit flag whose name says what it is. We do not want a
/// deployment to end up on unverified identity by simply forgetting an
/// option.
pub struct Auth {
    source: Option<BundleSource>,
    token_path: Option<PathBuf>,
    /// Last token accepted via `present` (HTTP transport). Kept so that the
    /// common case — the same token on every request — costs a string
    /// comparison, not a signature verification.
    presented: Option<String>,
    current: Delegation,
    /// Incremented on every renewal, to number the delegation records.
    generation: u64,
}

/// Reason an act was refused on identity grounds.
///
/// Distinct from a policy denial: here it is not a rule that forbids, it is
/// authority that is missing. The log must be able to tell them apart.
#[derive(Debug)]
pub struct AuthDenied(pub String);

impl std::fmt::Display for AuthDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Auth {
    /// Identity declared on the command line. Nothing is verified.
    pub fn declared(principal: &str, scopes: Vec<String>, groups: Vec<String>) -> Self {
        Auth {
            source: None,
            token_path: None,
            presented: None,
            current: Delegation {
                subject: principal.to_string(),
                // Deliberately conspicuous marker: an auditor reading
                // `cli://declared` in the log immediately knows the identity
                // was never proven.
                issuer: "cli://declared".to_string(),
                scopes,
                groups,
                // No expiry: a declared identity has none, which is exactly
                // the problem.
                expires_at_ms: i64::MAX,
                issued_at_ms: None,
                actor_chain: vec![principal.to_string()],
                // Nothing was attested: we do not pretend a human sits at the
                // end of the chain. A "destructive requires a human" rule will
                // therefore block in declared mode, which is the intended
                // behaviour.
                kind: PrincipalKind::Machine,
            },
            generation: 1,
        }
    }

    /// Identity proven by a verified OIDC token.
    pub fn oidc(mut source: BundleSource, token_path: PathBuf) -> Result<Self, String> {
        let current = read_and_verify(&mut source, &token_path, 0)?;
        Ok(Auth {
            source: Some(source),
            token_path: Some(token_path),
            presented: None,
            current,
            generation: 1,
        })
    }

    /// Identity proven by a token presented with the request (HTTP transport).
    ///
    /// Same verification as `oidc`, different plumbing: over stdio the token
    /// lives in a file the gateway re-reads; over HTTP each request carries
    /// its own `Authorization` header and renewal shows up as a new value
    /// there. There is no file to fall back on.
    pub fn oidc_presented(mut source: BundleSource, token: &str) -> Result<Self, String> {
        let current = verify_token(&mut source, token, 0)?;
        if current.is_expired(crate::session::now_ms()) {
            return Err("presented token is expired".to_string());
        }
        Ok(Auth {
            source: Some(source),
            token_path: None,
            presented: Some(token.to_string()),
            current,
            generation: 1,
        })
    }

    pub fn is_proven(&self) -> bool {
        self.source.is_some()
    }

    /// Version of the identity bundle currently in force.
    pub fn identity_version(&self) -> &str {
        self.source.as_ref().map_or("cli://declared", |s| s.version())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn delegation(&self) -> &Delegation {
        &self.current
    }

    /// The delegation in force at this instant.
    ///
    /// Expiry is re-evaluated **on every act**, not only when the session
    /// opens: an agent session routinely outlives a token. Checking once at
    /// startup amounts to granting unlimited authority from a 30-minute
    /// token.
    ///
    /// Returns `true` when the delegation has just been renewed — the caller
    /// must then record it in the log.
    pub fn refresh(&mut self, now_ms: i64) -> Result<bool, AuthDenied> {
        if !self.current.is_expired(now_ms) {
            return Ok(false);
        }

        let (Some(source), Some(path)) = (&mut self.source, &self.token_path) else {
            // Impossible in declared mode (expiry at i64::MAX), but we do not
            // leave the branch silent.
            return Err(AuthDenied("delegation expired".to_string()));
        };

        // The token may have been renewed on disk by whatever holds the OIDC
        // session. We re-read before concluding a refusal.
        match read_and_verify(source, path, now_ms) {
            Ok(fresh) if !fresh.is_expired(now_ms) => {
                let changed = fresh.subject != self.current.subject
                    || fresh.scopes != self.current.scopes
                    || fresh.groups != self.current.groups
                    || fresh.expires_at_ms != self.current.expires_at_ms;
                self.current = fresh;
                if changed {
                    self.generation += 1;
                    return Ok(true);
                }
                Ok(false)
            }
            Ok(_) => Err(AuthDenied(format!(
                "delegation expired {} s ago and the on-disk token is expired too",
                -self.current.remaining_secs(now_ms)
            ))),
            Err(e) => Err(AuthDenied(format!(
                "delegation expired and token unrecoverable: {e}"
            ))),
        }
    }

    /// Takes the token presented with the current request into account.
    ///
    /// The HTTP counterpart of `refresh`: same contract, same per-act
    /// re-evaluation, but the fresh token arrives in the request instead of a
    /// file. Returns `true` when the delegation changed — the caller must
    /// then record it in the log.
    ///
    /// A rejected token does not touch the delegation in force: expiry keeps
    /// doing its work, and the refusal reason names the token, not the
    /// session.
    pub fn present(&mut self, token: &str, now_ms: i64) -> Result<bool, AuthDenied> {
        if self.presented.as_deref() == Some(token) {
            // Same token as last time: only its expiry can have changed.
            return if self.current.is_expired(now_ms) {
                Err(AuthDenied(format!(
                    "delegation expired {} s ago and the presented token is the same",
                    -self.current.remaining_secs(now_ms)
                )))
            } else {
                Ok(false)
            };
        }

        let Some(source) = &mut self.source else {
            // Declared mode: nothing was ever verified, presenting a token
            // does not change that. Refusing would be wrong (the mode is
            // explicitly unverified); accepting it as proof would be worse.
            return self.refresh(now_ms);
        };

        match verify_token(source, token, now_ms) {
            Ok(fresh) if !fresh.is_expired(now_ms) => {
                self.presented = Some(token.to_string());
                let changed = fresh.subject != self.current.subject
                    || fresh.scopes != self.current.scopes
                    || fresh.groups != self.current.groups
                    || fresh.expires_at_ms != self.current.expires_at_ms;
                self.current = fresh;
                if changed {
                    self.generation += 1;
                    return Ok(true);
                }
                Ok(false)
            }
            Ok(_) => Err(AuthDenied("presented token is expired".to_string())),
            Err(e) => Err(AuthDenied(format!("presented token rejected: {e}"))),
        }
    }
}

/// Verifies the token, recovering from a key rotation on the provider side.
///
/// An unknown `kid` is the exact signal of a rotation: identity providers
/// renew their signing keys routinely, and Keycloak does so on its realm
/// keys. We then reload the bundle from disk — where the control plane has
/// published the new version — and retry once.
///
/// **Once only.** Looping on the reload would turn a permanently invalid
/// token into a disk-access loop, and the `BundleSource` minimum interval
/// would merely slow it down without stopping it.
fn read_and_verify(
    source: &mut BundleSource,
    path: &Path,
    now_ms: i64,
) -> Result<Delegation, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    verify_token(source, raw.trim(), now_ms)
}

fn verify_token(
    source: &mut BundleSource,
    token: &str,
    now_ms: i64,
) -> Result<Delegation, String> {
    match source.verifier().verify(token) {
        Ok(d) => Ok(d),
        Err(identity::Error::UnknownKid(kid)) => {
            match source.reload(now_ms) {
                ReloadOutcome::Reloaded { version, keys } => {
                    eprintln!(
                        "[probant] rotation detected (unknown kid \"{kid}\") — identity \
                         bundle reloaded: {version}, {keys} key(s)"
                    );
                }
                ReloadOutcome::Failed { reason } => {
                    // The previous bundle stays in place: we fail on this
                    // token, not on the service.
                    eprintln!(
                        "[probant] WARNING: identity bundle reload failed ({reason}) \
                         — previous configuration kept"
                    );
                }
                ReloadOutcome::Unchanged => {}
            }

            source
                .verifier()
                .verify(token)
                .map_err(|e| format!("token verification after reload: {e}"))
        }
        Err(e) => Err(format!("token verification: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{mint, keyring, write_bundle, ISSUER};
    use identity::BundleSource;

    /// Bundle that only knows `k1`.
    fn source(name: &str) -> (BundleSource, PathBuf) {
        let p = std::env::temp_dir()
            .join(format!("probant-auth-{name}-{}.bundle.json", std::process::id()));
        write_bundle(&p, "identity@1", &[("k1", 1)]);
        (BundleSource::load(&p, &keyring()).unwrap(), p)
    }

    fn token_file(name: &str, exp_offset: i64, scopes: &str) -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("probant-auth-{name}-{}.jwt", std::process::id()));
        std::fs::write(&p, mint(1, exp_offset, scopes)).unwrap();
        p
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[test]
    fn declared_identity_is_marked_and_never_expires() {
        let mut a = Auth::declared("marie", vec!["s1".into()], vec![]);
        assert!(!a.is_proven());
        assert_eq!(a.delegation().issuer, "cli://declared");
        // No expiry: precisely what makes it unacceptable in production, and
        // the log must be able to show it.
        assert!(!a.refresh(i64::MAX - 1).unwrap());
    }

    #[test]
    fn expired_token_at_startup_prevents_opening() {
        let (src, bp) = source("startup-exp");
        let p = token_file("startup-exp", -3600, "support:read");
        assert!(Auth::oidc(src, p.clone()).is_err());
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(bp);
    }

    #[test]
    fn a_valid_delegation_triggers_no_renewal() {
        let (src, bp) = source("valid");
        let p = token_file("valid", 1800, "support:read");
        let mut a = Auth::oidc(src, p.clone()).unwrap();
        assert!(a.is_proven());
        assert_eq!(a.delegation().issuer, ISSUER);
        assert!(!a.refresh(now()).unwrap());
        assert_eq!(a.generation(), 1);
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(bp);
    }

    #[test]
    fn mid_session_expiry_blocks() {
        // The case a one-shot startup check misses: the token was valid when
        // the session opened, it no longer is at the moment of the act.
        let (src, bp) = source("midsession");
        let p = token_file("midsession", 1800, "support:read");
        let mut a = Auth::oidc(src, p.clone()).unwrap();

        let after_expiry = a.delegation().expires_at_ms + 1;
        let err = a.refresh(after_expiry).unwrap_err();
        assert!(
            err.0.contains("expired"),
            "unclear refusal reason: {}",
            err.0
        );
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(bp);
    }

    #[test]
    fn a_token_renewed_on_disk_is_picked_up() {
        let (src, bp) = source("renew");
        let p = token_file("renew", 1800, "support:read");
        let mut a = Auth::oidc(src, p.clone()).unwrap();
        let previous_end = a.delegation().expires_at_ms;

        // Whoever holds the OIDC session renews the token, with wider
        // scopes.
        std::fs::write(&p, mint(1, 7200, "support:read db:admin")).unwrap();

        let renewed = a.refresh(previous_end + 1).unwrap();
        assert!(renewed, "the renewal must be signalled to the caller");
        assert_eq!(a.generation(), 2, "the generation must advance");
        assert!(a.delegation().scopes.contains(&"db:admin".to_string()));
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(bp);
    }

    #[test]
    fn an_on_disk_token_also_expired_stays_refused() {
        let (src, bp) = source("both-exp");
        let p = token_file("both-exp", 2, "support:read");
        let mut a = Auth::oidc(src, p.clone()).unwrap();
        let end = a.delegation().expires_at_ms;

        // The file was not refreshed: re-reading saves nothing.
        assert!(a.refresh(end + 3_600_000).is_err());
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(bp);
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::testutil::{mint, keyring, write_bundle, ISSUER};
    use identity::BundleSource;

    fn paths(name: &str) -> (PathBuf, PathBuf) {
        let pid = std::process::id();
        (
            std::env::temp_dir().join(format!("rot-{name}-{pid}.bundle.json")),
            std::env::temp_dir().join(format!("rot-{name}-{pid}.jwt")),
        )
    }

    fn cleanup(a: &PathBuf, b: &PathBuf) {
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn rotation_recovered_at_startup() {
        // The gateway loaded a bundle that only knows k1. Meanwhile the
        // provider rotated to k2 and the control plane published the new
        // bundle. The token presents k2: unknown in memory, present on
        // disk.
        let (bp, tp) = paths("startup");
        write_bundle(&bp, "identity@1", &[("k1", 1)]);
        let source = BundleSource::load(&bp, &keyring()).unwrap();

        write_bundle(&bp, "identity@2", &[("k1", 1), ("k2", 2)]);
        std::fs::write(&tp, mint(2, 1800, "support:read")).unwrap();

        let a = Auth::oidc(source, tp.clone()).expect("the rotation must be recovered");
        assert_eq!(a.delegation().issuer, ISSUER);
        assert_eq!(a.identity_version(), "identity@2");
        cleanup(&bp, &tp);
    }

    #[test]
    fn rotation_recovered_mid_session() {
        // The real sequence: the token expires, whoever holds the OIDC
        // session gets a new one — signed with the freshly rotated key.
        // Without reloading, the gateway would refuse everything until
        // restart.
        let (bp, tp) = paths("midsession");
        write_bundle(&bp, "identity@1", &[("k1", 1)]);
        let source = BundleSource::load(&bp, &keyring()).unwrap();
        std::fs::write(&tp, mint(1, 1800, "support:read")).unwrap();

        let mut a = Auth::oidc(source, tp.clone()).unwrap();
        let end = a.delegation().expires_at_ms;

        write_bundle(&bp, "identity@2", &[("k2", 2)]);
        std::fs::write(&tp, mint(2, 7200, "support:read db:admin")).unwrap();

        let renewed = a.refresh(end + 1).expect("the new token must pass");
        assert!(renewed, "the renewal must be signalled");
        assert_eq!(a.identity_version(), "identity@2");
        assert!(a.delegation().scopes.contains(&"db:admin".to_string()));
        cleanup(&bp, &tp);
    }

    #[test]
    fn a_permanently_unknown_kid_stays_refused() {
        // Reloading is not a bypass: if the key is nowhere, the token is
        // refused.
        let (bp, tp) = paths("unknown");
        write_bundle(&bp, "identity@1", &[("k1", 1)]);
        let source = BundleSource::load(&bp, &keyring()).unwrap();
        std::fs::write(&tp, mint(7, 1800, "support:read")).unwrap();

        let err = match Auth::oidc(source, tp.clone()) {
            Err(e) => e,
            Ok(_) => panic!("a kid absent everywhere was accepted"),
        };
        assert!(err.contains("k7") || err.contains("kid"), "got: {err}");
        cleanup(&bp, &tp);
    }

    #[test]
    fn a_rogue_bundle_does_not_slip_in_via_rotation() {
        // An attacker who can write the file tries to drop their own JWKS in
        // to get their tokens accepted. The bundle signature is revalidated on
        // every reload, so the attempt fails and the previous configuration
        // stays in force.
        use ed25519_dalek::SigningKey;
        use identity::bundle::{IdentityBundle, FORMAT};
        use identity::{ClaimMap, JwkSet};
        use serde_json::json;

        let (bp, tp) = paths("pirate");
        write_bundle(&bp, "identity@1", &[("k1", 1)]);
        let source = BundleSource::load(&bp, &keyring()).unwrap();

        // Bundle holding k9, signed with a key that is not trusted.
        let vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let x = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            vk.as_bytes(),
        );
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "k9",
                       "alg": "EdDSA", "x": x }]
        }))
        .unwrap();
        let rogue = IdentityBundle {
            format: FORMAT.to_string(),
            version: "identity@rogue".into(),
            issuer: ISSUER.into(),
            audience: crate::testutil::AUDIENCE.into(),
            jwks,
            claims: ClaimMap::default(),
        }
        .sign("identity-key", &SigningKey::from_bytes(&[0x99; 32]));
        std::fs::write(&bp, serde_json::to_string(&rogue).unwrap()).unwrap();

        std::fs::write(&tp, mint(9, 1800, "support:read")).unwrap();
        assert!(
            Auth::oidc(source, tp.clone()).is_err(),
            "a badly signed bundle allowed a token to be accepted"
        );
        cleanup(&bp, &tp);
    }
}
