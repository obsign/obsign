use audit_core::checkpoint::PublicKeyEntry;
use audit_core::{content_hash, Hash};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::bundle::SignedIdentityBundle;
use crate::verifier::Verifier;
use crate::Error;

/// What happened during a reload attempt.
///
/// `Failed` is deliberately not an error: an invalid identity bundle dropped
/// on disk — botched deployment, truncated file, bad signature — must
/// **never** bring the gateway down. The previous bundle stays in place and
/// the service keeps running. The type says so explicitly so that no caller
/// can treat this case as fatal by accident.
#[derive(Debug, Clone, PartialEq)]
pub enum ReloadOutcome {
    /// The file has not changed.
    Unchanged,
    /// New bundle loaded and verified. `content` is the hash of the file as
    /// read, so the reload can be recorded against exact bytes, not just a
    /// version string the bundle declares about itself.
    Reloaded {
        version: String,
        keys: usize,
        content: Hash,
    },
    /// Attempt failed, the previous bundle is kept. `content` hashes the
    /// rejected bytes — evidence of *what* was refused — and is `None` only
    /// when the file could not be read at all.
    Failed {
        reason: String,
        content: Option<Hash>,
    },
}

/// Hot-reloadable identity bundle.
///
/// Identity providers rotate their signing keys routinely — Keycloak in
/// particular, on its realm keys. Without reloading, every rotation would
/// require a gateway restart, i.e. an outage on the critical path for a
/// completely mundane operation.
///
/// Two complementary triggers:
///
/// * **on demand**, when a token carries an unknown `kid`. That is the exact
///   signal of a rotation, so reloading costs nothing in nominal operation:
///   no disk access as long as nothing rotates;
/// * **on file change**, checked as we go, to pick up a modified claim
///   mapping or audience without waiting for a token to fail.
///
/// Detection uses the content hash rather than the modification time: mtime
/// granularity goes up to one second on some filesystems, enough to miss two
/// writes close together.
pub struct BundleSource {
    path: PathBuf,
    trusted: Vec<PublicKeyEntry>,
    verifier: Verifier,
    version: String,
    content: Hash,
    /// Timestamp of the last *attempt*, successful or not.
    last_attempt_ms: i64,
    min_interval_ms: i64,
}

impl BundleSource {
    /// Loads and verifies the initial bundle. Failure here is fatal:
    /// starting without a valid identity configuration is meaningless.
    pub fn load(path: &Path, trusted: &[PublicKeyEntry]) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)?;
        let (verifier, version) = verify_bundle(&raw, trusted)?;

        Ok(BundleSource {
            path: path.to_path_buf(),
            trusted: trusted.to_vec(),
            verifier,
            version,
            content: content_hash(raw.as_bytes()),
            last_attempt_ms: i64::MIN,
            // Key rotation happens on a scale of hours or days. One second
            // between attempts is plenty, and it bounds the cost of a flood of
            // tokens with random `kid` values: the attacker triggers one file
            // read per second, not one per request.
            min_interval_ms: 1_000,
        })
    }

    pub fn with_min_interval(mut self, ms: i64) -> Self {
        self.min_interval_ms = ms;
        self
    }

    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attempts a reload, honouring the minimum interval.
    ///
    /// Called when a token presents an unknown `kid`: the signature of a
    /// rotation on the provider side.
    pub fn reload(&mut self, now_ms: i64) -> ReloadOutcome {
        if now_ms.saturating_sub(self.last_attempt_ms) < self.min_interval_ms {
            return ReloadOutcome::Unchanged;
        }
        self.last_attempt_ms = now_ms;
        self.reload_now()
    }

    /// Reload with no rate limiting.
    fn reload_now(&mut self) -> ReloadOutcome {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(r) => r,
            Err(e) => {
                return ReloadOutcome::Failed {
                    reason: format!("reading {}: {e}", self.path.display()),
                    content: None,
                }
            }
        };

        let digest = content_hash(raw.as_bytes());
        if digest == self.content {
            return ReloadOutcome::Unchanged;
        }

        // The signature is revalidated on every reload. Without that, hot
        // rotation would become the easiest way to inject a JWKS: writing the
        // file would be enough.
        match verify_bundle(&raw, &self.trusted) {
            Ok((verifier, version)) => {
                let keys = verifier.key_count();
                self.verifier = verifier;
                self.version = version.clone();
                self.content = digest;
                ReloadOutcome::Reloaded {
                    version,
                    keys,
                    content: digest,
                }
            }
            Err(e) => {
                // We still record the hash: no point re-verifying a broken
                // file that is not changing.
                self.content = digest;
                ReloadOutcome::Failed {
                    reason: e.to_string(),
                    content: Some(digest),
                }
            }
        }
    }
}

fn verify_bundle(
    raw: &str,
    trusted: &[PublicKeyEntry],
) -> Result<(Verifier, String), Error> {
    let signed: SignedIdentityBundle = serde_json::from_str(raw)?;

    let mut keys = BTreeMap::new();
    for entry in trusted {
        if let Ok(vk) = entry.to_verifying_key() {
            keys.insert(entry.key_id.clone(), vk);
        }
    }

    let vk = keys
        .get(&signed.key_id)
        .ok_or_else(|| Error::UnknownBundleKey(signed.key_id.clone()))?;

    let bundle = signed.verify(vk)?;
    Ok((Verifier::from_bundle(bundle)?, bundle.version.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{IdentityBundle, FORMAT};
    use crate::{ClaimMap, JwkSet};
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    const ISSUER: &str = "https://sso.acme.fr/realms/corp";
    const AUDIENCE: &str = "obsign-proxy";

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// Bundle holding the keys named by `kids` (seed = the kid's byte).
    fn bundle_json(version: &str, kids: &[(&str, u8)], signer: &SigningKey) -> String {
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

        let jwks: JwkSet = serde_json::from_value(json!({ "keys": keys })).unwrap();
        let bundle = IdentityBundle {
            format: FORMAT.to_string(),
            version: version.to_string(),
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            jwks,
            claims: ClaimMap::default(),
        };
        serde_json::to_string(&bundle.sign("identity-key", signer)).unwrap()
    }

    fn keyring(signer: &SigningKey) -> Vec<PublicKeyEntry> {
        vec![PublicKeyEntry {
            key_id: "identity-key".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(signer.verifying_key().to_bytes()),
            role: Default::default(),
        }]
    }

    fn tmpfile(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("src-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn reload_picks_up_the_new_keys() {
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("rotate");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer)).unwrap();
        assert_eq!(src.version(), "identity@1");
        assert_eq!(src.verifier().key_count(), 1);

        // Rotation on the IdP side: k2 appears, k1 stays during transition.
        std::fs::write(
            &p,
            bundle_json("identity@2", &[("k1", 1), ("k2", 2)], &signer),
        )
        .unwrap();

        match src.reload(10_000) {
            ReloadOutcome::Reloaded { version, keys, content } => {
                assert_eq!(version, "identity@2");
                assert_eq!(keys, 2);
                // The hash names the exact bytes now in force.
                let raw = std::fs::read(&p).unwrap();
                assert_eq!(content, content_hash(&raw));
            }
            other => panic!("expected Reloaded, got {other:?}"),
        }
        assert_eq!(src.verifier().key_count(), 2);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn unchanged_file_does_not_reload() {
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("same");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer)).unwrap();
        assert_eq!(src.reload(10_000), ReloadOutcome::Unchanged);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn badly_signed_bundle_is_refused_and_previous_kept() {
        // The scenario that matters: without signature revalidation, hot
        // rotation would be the easiest way to inject a JWKS.
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let attacker = SigningKey::from_bytes(&[0x99; 32]);
        let p = tmpfile("forged");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer)).unwrap();

        // The forger replaces the file, signed with their own key.
        std::fs::write(
            &p,
            bundle_json("identity@rogue", &[("kx", 9)], &attacker),
        )
        .unwrap();

        match src.reload(10_000) {
            ReloadOutcome::Failed { .. } => {}
            other => panic!("a badly signed bundle was accepted: {other:?}"),
        }
        // And crucially: the service keeps running on the old config.
        assert_eq!(src.version(), "identity@1");
        assert_eq!(src.verifier().key_count(), 1);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn truncated_file_does_not_take_the_gateway_down() {
        // Botched deployment, partial write: the gateway must survive.
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("truncated");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer)).unwrap();
        std::fs::write(&p, "{\"bundle\": {\"forma").unwrap();

        assert!(matches!(src.reload(10_000), ReloadOutcome::Failed { .. }));
        assert_eq!(src.version(), "identity@1");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn deleted_file_does_not_take_the_gateway_down() {
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("deleted");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer)).unwrap();
        std::fs::remove_file(&p).unwrap();

        assert!(matches!(src.reload(10_000), ReloadOutcome::Failed { .. }));
        assert_eq!(src.version(), "identity@1");
    }

    #[test]
    fn reload_frequency_is_bounded() {
        // Without a limit, a flood of tokens with random `kid` values would
        // cause one file read per request.
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("throttle");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer))
            .unwrap()
            .with_min_interval(5_000);

        // First attempt: allowed through, but nothing changed.
        assert_eq!(src.reload(10_000), ReloadOutcome::Unchanged);

        std::fs::write(
            &p,
            bundle_json("identity@2", &[("k1", 1), ("k2", 2)], &signer),
        )
        .unwrap();

        // Too soon: the attempt is skipped, the old bundle stays.
        assert_eq!(src.reload(11_000), ReloadOutcome::Unchanged);
        assert_eq!(src.version(), "identity@1");

        // Past the interval, the reload happens.
        assert!(matches!(
            src.reload(16_000),
            ReloadOutcome::Reloaded { .. }
        ));
        assert_eq!(src.version(), "identity@2");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_broken_file_is_not_revalidated_in_a_loop() {
        // Once an invalid file's hash is memorised, we do not retry until it
        // changes.
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let p = tmpfile("stable-broken");
        std::fs::write(&p, bundle_json("identity@1", &[("k1", 1)], &signer)).unwrap();

        let mut src = BundleSource::load(&p, &keyring(&signer))
            .unwrap()
            .with_min_interval(0);
        std::fs::write(&p, "casse").unwrap();

        assert!(matches!(src.reload(1), ReloadOutcome::Failed { .. }));
        assert_eq!(src.reload(2), ReloadOutcome::Unchanged);
        let _ = std::fs::remove_file(p);
    }
}
