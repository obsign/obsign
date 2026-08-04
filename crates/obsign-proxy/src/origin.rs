//! Where the gateway's origin key lives.
//!
//! The mirror of `obsign_ledger::Sealer`, deliberately the same shape: everything
//! above the trait manipulates signed records, everything below decides
//! where the private key material sits. The MVP holds a seed in a file; the
//! roadmap (hardware identity key certifying per-session memory keys)
//! replaces the implementation, not the boundary.
//!
//! The trust this key carries is stated where it is earned: it authenticates
//! the *writer*, raising the attack from "write the WAL directory" to "read
//! the gateway's key material". It is not, and cannot be, a defense against
//! a compromised gateway process; the gateway *is* the origin.

use anyhow::{bail, Context as _, Result};
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use obsign_audit_core::record::SessionCert;
use obsign_audit_core::{
    content_hash, key_id_for, session_cert_signing_bytes, Hash, SignedDeploymentBundle,
};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub trait OriginSigner: Send + Sync {
    fn key_id(&self) -> &str;

    /// The public half, role `origin`, as the ledger's trusted key file and
    /// the evidence pack will carry it.
    fn public_key(&self) -> PublicKeyEntry;

    /// Ed25519 signature over the message (`origin_signing_bytes`).
    ///
    /// On the hot path: called for every record, between the chain append
    /// and the fsync. An implementation that cannot sign in microseconds
    /// does not belong here. Hardware keys certify a session key instead
    /// (see the design's two-tier target).
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], io::Error>;
}

/// Development origin signer: a 32-byte hex seed in a file.
///
/// Same custody class as the ledger's `FileSealer`, same honesty about it: a
/// disk attacker who can also *read* this file forges signatures. Acceptable
/// for development and first design partners; the file dies when the
/// two-tier key road lands.
pub struct FileOriginSigner {
    key: SigningKey,
    key_id: String,
}

impl FileOriginSigner {
    pub fn from_seed_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the origin key seed {}", path.display()))?;
        let bytes = hex::decode(raw.trim()).context("origin key seed is not valid hex")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the origin key seed must be 32 bytes"))?;
        Ok(Self::from_seed(seed))
    }

    /// Key id derived from the public key: self-describing in the log and in
    /// key files, and two gateways with different keys can never collide on
    /// an id the way two `--key-id gateway-1` flags would.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let key_id = format!(
            "origin-{}",
            &hex::encode(key.verifying_key().to_bytes())[..16]
        );
        FileOriginSigner { key, key_id }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl OriginSigner for FileOriginSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], io::Error> {
        Ok(self.key.sign(message).to_bytes())
    }
}

// ===========================================================================
// v2: two-tier keys — a hardware identity key certifies ephemeral session keys
// ===========================================================================

/// The long-lived gateway identity key. Signs session certificates, never
/// records, so it can live in hardware (a TPM/HSM implementation certifies
/// once per session, off the hot path) while records keep signing at
/// memory-key speed.
///
/// The mirror of [`OriginSigner`], deliberately the same shape: everything
/// above manipulates certificates, everything below decides where the private
/// key sits. `FileIdentitySigner` is the dev implementation; a
/// `Pkcs11IdentitySigner` (production) is another consumer of the PKCS#11
/// module the ledger already ships.
pub trait IdentitySigner: Send + Sync {
    fn key_id(&self) -> &str;
    /// The public half, role `origin`, enrolled in the deployment bundle.
    fn public_key(&self) -> PublicKeyEntry;
    fn verifying_key(&self) -> VerifyingKey;
    /// Signs the session-certificate bytes (`session_cert_signing_bytes`).
    fn certify(&self, message: &[u8]) -> Result<[u8; 64], io::Error>;
}

/// Development identity signer: a 32-byte hex seed, same custody class as the
/// dev origin/sealing seeds. Production replaces this with a PKCS#11-backed
/// signer; nothing above the trait changes.
pub struct FileIdentitySigner {
    key: SigningKey,
    key_id: String,
}

impl FileIdentitySigner {
    pub fn from_seed_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the identity key seed {}", path.display()))?;
        let bytes = hex::decode(raw.trim()).context("identity key seed is not valid hex")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the identity key seed must be 32 bytes"))?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let key_id = key_id_for(&key.verifying_key());
        FileIdentitySigner { key, key_id }
    }
}

impl IdentitySigner for FileIdentitySigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }
    fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    fn certify(&self, message: &[u8]) -> Result<[u8; 64], io::Error> {
        Ok(self.key.sign(message).to_bytes())
    }
}

/// Production identity signer: the key lives in a PKCS#11 token (HSM/TPM/
/// smartcard) and never enters this process. Wraps the same
/// [`obsign_pkcs11::Pkcs11Signer`] the ledger's sealing key uses: one audited
/// FFI, two roles.
pub struct Pkcs11IdentitySigner {
    inner: obsign_pkcs11::Pkcs11Signer,
    key_id: String,
}

impl Pkcs11IdentitySigner {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        module: &Path,
        token: &obsign_pkcs11::TokenSelector,
        pin: &str,
        key_label: &str,
    ) -> Result<Self> {
        // The key id is derived from the public key, like the file signer's,
        // so the same key always enrolls under the same id whatever the
        // custody.
        let inner = obsign_pkcs11::Pkcs11Signer::open(module, token, pin, key_label, "identity")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let vk = pubkey_from_bytes(&inner.public_key_bytes())?;
        let key_id = key_id_for(&vk);
        Ok(Pkcs11IdentitySigner { inner, key_id })
    }
}

fn pubkey_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(|e| anyhow::anyhow!("token public key unusable: {e}"))
}

impl IdentitySigner for Pkcs11IdentitySigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.inner.public_key_bytes()),
            role: KeyRole::Origin,
        }
    }
    fn verifying_key(&self) -> VerifyingKey {
        pubkey_from_bytes(&self.inner.public_key_bytes())
            .expect("token public key validated at open")
    }
    fn certify(&self, message: &[u8]) -> Result<[u8; 64], io::Error> {
        self.inner
            .sign(message)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// An ephemeral session signing key, generated in memory and discarded at
/// session close. It signs every record of one chain; it never touches disk.
/// This is the [`OriginSigner`] the session actually uses under v2.
pub struct SessionKey {
    key: SigningKey,
    key_id: String,
}

impl SessionKey {
    /// Generates a fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("generating a session key: {e}"))?;
        let key = SigningKey::from_bytes(&seed);
        let key_id = key_id_for(&key.verifying_key());
        Ok(SessionKey { key, key_id })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl OriginSigner for SessionKey {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], io::Error> {
        Ok(self.key.sign(message).to_bytes())
    }
}

/// Certifies a fresh session key for one chain: generates the key, has the
/// identity key sign a certificate over it, and returns both.
///
/// The certificate binds the session key to this `chain_id` and `gateway_id`,
/// and to a validity window `[now, now+lifetime]`. A leaked session key
/// forges records only for this chain, only until it expires.
pub fn certify_session(
    identity: &dyn IdentitySigner,
    chain_id: &str,
    gateway_id: &str,
    now_ms: i64,
    lifetime_ms: i64,
) -> Result<(SessionKey, SessionCert)> {
    let session = SessionKey::generate()?;
    let mut cert = SessionCert {
        session_pubkey: hex::encode(session.verifying_key().to_bytes()),
        identity_key_id: identity.key_id().to_string(),
        gateway_id: gateway_id.to_string(),
        not_before_ms: now_ms,
        not_after_ms: now_ms.saturating_add(lifetime_ms),
        identity_sig: String::new(),
    };
    let sig = identity
        .certify(&session_cert_signing_bytes(chain_id, &cert))
        .context("the identity key failed to certify the session key")?;
    cert.identity_sig = hex::encode(sig);
    Ok((session, cert))
}

/// The origin keys a v2 gateway accepts when resuming a chain: the session
/// keys already certified in the chain (validated against the trusted
/// identity keys), plus the new session key about to sign.
///
/// A resumed tail was signed by a *previous* session key; the gateway no
/// longer holds it, but the chain carries its certificate, and the identity
/// key vouches for it. So the gateway rebuilds the trust set from the chain
/// itself. A tail whose certificate the identity key did not sign is
/// foreign.
pub fn resume_session_trust(
    existing: &[obsign_audit_core::SignedRecord],
    chain_id: &str,
    identity_active: &BTreeMap<String, VerifyingKey>,
    new_session: &SessionKey,
) -> BTreeMap<String, VerifyingKey> {
    let mut trusted = BTreeMap::new();
    for sr in existing {
        if let obsign_audit_core::record::Payload::SessionCert(cert) = &sr.record.payload {
            if let Some(id_vk) = identity_active.get(&cert.identity_key_id) {
                if let Ok(session_vk) =
                    obsign_audit_core::verify_session_cert(chain_id, cert, id_vk)
                {
                    trusted.insert(key_id_for(&session_vk), session_vk);
                }
            }
        }
    }
    trusted.insert(new_session.key_id.clone(), new_session.verifying_key());
    trusted
}

/// How this gateway signs records.
///
/// One place decides the whole key story, so the stdio and HTTP transports
/// share it: they must sign identically or the log's meaning starts depending
/// on deployment topology.
pub enum Signing {
    /// No origin key: records are chained but unsigned (legacy / rollout).
    None,
    /// v0/v1: one origin key signs every record directly.
    Direct(Arc<FileOriginSigner>),
    /// v2: a long-lived identity key certifies a fresh session key per chain;
    /// the session key signs records.
    TwoTier {
        identity: Arc<dyn IdentitySigner>,
        lifetime_ms: i64,
    },
}

/// Everything a gateway needs to sign and to authenticate a resume, resolved
/// once at startup and shared across sessions.
pub struct GatewayKeys {
    pub signing: Signing,
    pub deployment: Option<DeploymentTrust>,
    pub gateway_id: String,
}

/// What one session open needs, derived from [`GatewayKeys`] per chain.
pub struct SessionSetup {
    /// The record signer (a session key under v2, the origin key under v0/v1).
    pub origin: Option<Arc<dyn OriginSigner>>,
    /// A certificate to write as the chain's first record (v2 only).
    pub cert: Option<SessionCert>,
    /// The trusted origin-key set for an authenticated resume; `None` runs
    /// the plain, unauthenticated open (no origin key at all).
    pub resume_trust: Option<BTreeMap<String, VerifyingKey>>,
}

impl GatewayKeys {
    /// The key id this gateway must be enrolled under: its origin key (v0/v1)
    /// or its identity key (v2).
    pub fn own_key_id(&self) -> Option<String> {
        match &self.signing {
            Signing::None => None,
            Signing::Direct(o) => Some(o.key_id().to_string()),
            Signing::TwoTier { identity, .. } => Some(identity.key_id().to_string()),
        }
    }

    /// Fails at startup if a deployment bundle is configured but does not
    /// enroll this gateway's key, whose records would be refused at sealing.
    pub fn verify_enrolled(&self) -> Result<()> {
        if let (Some(trust), Some(id)) = (&self.deployment, self.own_key_id()) {
            trust.require_enrolled(&id)?;
        }
        Ok(())
    }

    /// The active identity/origin keys: the deployment bundle's set, or just
    /// this gateway's own key when there is no bundle.
    fn active_set(&self) -> BTreeMap<String, VerifyingKey> {
        if let Some(trust) = &self.deployment {
            return trust.active.clone();
        }
        let mut m = BTreeMap::new();
        match &self.signing {
            Signing::None => {}
            Signing::Direct(o) => {
                m.insert(o.key_id().to_string(), o.verifying_key());
            }
            Signing::TwoTier { identity, .. } => {
                m.insert(identity.key_id().to_string(), identity.verifying_key());
            }
        }
        m
    }

    /// Derives the per-session signer, certificate and resume trust.
    ///
    /// `existing` is the chain's current records (empty for a fresh chain),
    /// read so a v2 resume can rebuild trust from the certificates already in
    /// the log.
    pub fn open_session(
        &self,
        chain_id: &str,
        existing: &[obsign_audit_core::SignedRecord],
        now_ms: i64,
    ) -> Result<SessionSetup> {
        match &self.signing {
            Signing::None => Ok(SessionSetup {
                origin: None,
                cert: None,
                resume_trust: None,
            }),
            Signing::Direct(o) => Ok(SessionSetup {
                origin: Some(Arc::clone(o) as Arc<dyn OriginSigner>),
                cert: None,
                resume_trust: Some(self.active_set()),
            }),
            Signing::TwoTier {
                identity,
                lifetime_ms,
            } => {
                let (session, cert) = certify_session(
                    identity.as_ref(),
                    chain_id,
                    &self.gateway_id,
                    now_ms,
                    *lifetime_ms,
                )?;
                let resume =
                    resume_session_trust(existing, chain_id, &self.active_set(), &session);
                Ok(SessionSetup {
                    origin: Some(Arc::new(session) as Arc<dyn OriginSigner>),
                    cert: Some(cert),
                    resume_trust: Some(resume),
                })
            }
        }
    }
}

/// The deployment bundle in force, and the origin keys it makes acceptable.
///
/// v1: instead of trusting only its own key on resume, the gateway trusts the
/// whole active set the control plane published. That is what lets it adopt a
/// tail written by a predecessor key during a rotation window (the home v0
/// left open), and it is recorded in-chain (`ConfigKind::DeploymentBundle`)
/// so every pack self-documents which origin keys the gateway trusted.
pub struct DeploymentTrust {
    /// Active origin keys by id, which are the resume trust set and, in-chain,
    /// the answer to "who could have written this?".
    pub active: BTreeMap<String, VerifyingKey>,
    pub version: String,
    /// Hash of the exact bytes on disk, recorded in-chain so the pack names
    /// the precise bundle the gateway trusted. (The ledger embeds the bundle
    /// itself at export; the gateway only witnesses which one was in force.)
    pub content: Hash,
}

impl DeploymentTrust {
    /// Loads and verifies the bundle under the ops key it names, resolved
    /// from the gateway's trusted keys, the same root that verifies the
    /// policy and identity bundles.
    pub fn load(path: &Path, trusted: &[PublicKeyEntry]) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the deployment bundle {}", path.display()))?;
        let signed: SignedDeploymentBundle =
            serde_json::from_str(&raw).context("parsing the deployment bundle")?;

        let ops = trusted
            .iter()
            .find(|k| k.key_id == signed.key_id)
            .with_context(|| {
                format!(
                    "deployment bundle signed by ops key \"{}\", absent from the \
                     trusted keys",
                    signed.key_id
                )
            })?
            .to_verifying_key()
            .context("unusable ops key")?;

        let bundle = signed
            .verify(&ops)
            .context("verifying the deployment bundle signature")?;
        let active = bundle
            .active_origin_keys()
            .context("the deployment bundle lists an unusable origin key")?;
        let version = bundle.version.clone();

        Ok(DeploymentTrust {
            active,
            version,
            content: content_hash(raw.as_bytes()),
        })
    }

    /// Confirms this gateway's own key is enrolled, since a gateway signing
    /// with a key the deployment does not trust would write records the ledger
    /// refuses, and it should learn that at startup, before the first seal.
    pub fn require_enrolled(&self, own_key_id: &str) -> Result<()> {
        if !self.active.contains_key(own_key_id) {
            bail!(
                "this gateway signs as \"{own_key_id}\", which the deployment \
                 bundle {} does not enroll: its records would be refused at \
                 sealing. Enroll the key or point at the right bundle.",
                self.version
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obsign_audit_core::checkpoint::KeyRole;

    #[test]
    fn the_public_entry_carries_the_origin_role() {
        let s = FileOriginSigner::from_seed([1u8; 32]);
        let entry = s.public_key();
        assert_eq!(entry.role, KeyRole::Origin);
        assert!(entry.key_id.starts_with("origin-"));
        assert_eq!(entry.key_id, s.key_id());
    }

    #[test]
    fn the_key_id_is_bound_to_the_key_material() {
        let a = FileOriginSigner::from_seed([1u8; 32]);
        let b = FileOriginSigner::from_seed([2u8; 32]);
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn a_file_identity_certifies_a_session_key_offline() {
        let identity = FileIdentitySigner::from_seed([7u8; 32]);
        let (session, cert) =
            certify_session(&identity, "c1", "gw-1", 1_000, 60_000).unwrap();
        let vk = obsign_audit_core::verify_session_cert("c1", &cert, &identity.verifying_key()).unwrap();
        assert_eq!(vk, session.verifying_key());
        assert!(obsign_audit_core::verify_session_cert("other", &cert, &identity.verifying_key()).is_err());
    }

    /// The v2 hardware path end to end: an identity key held in a PKCS#11
    /// token certifies an in-memory session key, and the certificate verifies
    /// against the token's public half.
    ///
    /// Gated on a provisioned token, like the ledger's PKCS#11 test:
    ///
    ///     source scripts/pkcs11-test-env.sh
    ///     cargo test -p obsign-proxy
    ///
    /// Without `OBSIGN_TEST_PKCS11_MODULE` it passes vacuously and says so.
    /// An unprovisioned machine must not fail the suite.
    #[test]
    fn an_hsm_identity_key_certifies_a_memory_session_key() {
        let Ok(module) = std::env::var("OBSIGN_TEST_PKCS11_MODULE") else {
            eprintln!("skipped: set OBSIGN_TEST_PKCS11_MODULE (scripts/pkcs11-test-env.sh)");
            return;
        };
        let pin = std::env::var("OBSIGN_TEST_PKCS11_PIN").expect("OBSIGN_TEST_PKCS11_PIN");
        let label =
            std::env::var("OBSIGN_TEST_PKCS11_KEY_LABEL").expect("OBSIGN_TEST_PKCS11_KEY_LABEL");

        let identity = Pkcs11IdentitySigner::open(
            std::path::Path::new(&module),
            &obsign_pkcs11::TokenSelector::Only,
            &pin,
            &label,
        )
        .expect("opening the HSM identity key");
        assert_eq!(identity.public_key().role, KeyRole::Origin);

        // Certify a fresh session key for a chain, off the token's key.
        let (session, cert) =
            certify_session(&identity, "chain-hsm", "gw-hsm", 1_000, 60_000).expect("certify");

        // The certificate verifies against the token's public half, and the
        // key it authorizes is exactly the session key we generated.
        let session_vk =
            obsign_audit_core::verify_session_cert("chain-hsm", &cert, &identity.verifying_key())
                .expect("the HSM-signed certificate must verify");
        assert_eq!(session_vk, session.verifying_key());
        // Bound to that chain: another chain id does not verify.
        assert!(
            obsign_audit_core::verify_session_cert("other", &cert, &identity.verifying_key()).is_err()
        );
    }
}
