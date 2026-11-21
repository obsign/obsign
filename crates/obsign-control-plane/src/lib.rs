//! Control plane: the operator-side counterpart of the gateway.
//!
//! Everything the gateway trusts (the policy bundle, the identity bundle)
//! arrives as a signed file. This crate is where those files come from:
//!
//! * **compile**: reads a policy source tree out of a git checkout,
//!   validates it (Cedar syntax, mandatory `@id` annotations, catalogue
//!   consistency, usable JWKS) and signs the bundles. The version carries the
//!   commit sha, so a rule change is a dated, reviewed pull request and never
//!   a click in a UI. A working tree that has drifted from HEAD is refused:
//!   the sha never stamps bytes its commit does not contain;
//! * **publish**: places a release into a distribution directory,
//!   immutably (`releases/<sha>/` is never rewritten) and atomically (the
//!   current files the gateways watch are replaced by rename). Rolling back
//!   is republishing an old sha;
//! * **export**, assembles the audit dossier: one evidence pack per chain,
//!   verified on the way out, listed in a signed export manifest whose file
//!   hashes are checkable with nothing but `sha256sum`;
//! * **console**: a read-only, server-rendered view of the log and the
//!   current release. GET-only by construction: there is no handler that
//!   mutates anything, so the console cannot become a second write path
//!   around git.
//!
//! Like every other component, the control plane makes **no network calls**.
//! The JWKS is a file in the source tree, reviewed like a rule, because it
//! decides who can mint identities. Fetching it from the IdP is a job for
//! whatever refreshes the git repository, not for this binary.

pub mod compile;
pub mod console;
pub mod export;
pub mod release;
pub mod schema;
pub mod source;
pub mod worktree;

pub use compile::{compile, Compiled};
pub use console::Console;
pub use export::{export_all, ExportManifest, SignedExportManifest};
pub use release::{publish, Manifest, Published, SignedManifest};
pub use schema::{default_schema_path, sync_schema, SchemaSync};
pub use source::SourceTree;
pub use worktree::worktree_divergence;

use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use ed25519_dalek::SigningKey;
use std::io::Write as _;
use std::path::Path;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("policy: {0}")]
    Policy(#[from] obsign_policy::Error),

    #[error("identity: {0}")]
    Identity(#[from] obsign_identity::Error),

    #[error("ledger: {0}")]
    Ledger(#[from] obsign_ledger::Error),

    #[error("log: {0}")]
    Wal(#[from] obsign_wal::Error),

    #[error(transparent)]
    Core(#[from] obsign_audit_core::Error),

    /// The source tree cannot be compiled. The message names the file: a
    /// compile error that does not say where is a support ticket.
    #[error("source: {0}")]
    Source(String),

    #[error("no version for this compilation: {0}")]
    NoVersion(String),

    #[error(
        "invalid version \"{0}\": a version names one directory under \
         releases/, so it is 1 to 128 characters of [A-Za-z0-9._+-] and does \
         not start with a dot"
    )]
    InvalidVersion(String),

    /// The version stamps a commit sha onto bytes read from disk. When the
    /// working tree has drifted from that commit, every decision in the log
    /// citing `policies@<sha>` would point auditors at rules that were never
    /// the ones enforced.
    #[error(
        "the working tree diverges from HEAD — refusing to stamp its sha \
         onto bytes the commit does not contain:\n{0}\ncommit (or restore) \
         the changes, or pass --label to version this build without citing \
         a commit"
    )]
    DirtyTree(String),

    #[error("invalid signing seed: {0}")]
    BadSeed(String),

    /// A version identifier maps to exactly one content, forever. Decisions
    /// in the log cite `policies@<sha>`; letting a sha designate two
    /// different rule sets would make those citations unreplayable.
    #[error(
        "version \"{version}\" is already published with different content: \
         a release is immutable, commit the change and publish the new sha"
    )]
    VersionConflict { version: String },

    /// Same rule as the ledger store: a key id binds one key, forever.
    #[error(
        "key id \"{0}\" already recorded with different key material: a \
         rotated key must take a new id, or old signatures become unverifiable"
    )]
    KeyConflict(String),

    /// A key id binds one role too: the same key admitted under a second
    /// role would let it sign what the first role was kept away from.
    #[error(
        "key id \"{key_id}\" already recorded with role \"{recorded}\", not \
         \"{requested}\": a key keeps the role it was trusted under"
    )]
    KeyRoleConflict {
        key_id: String,
        recorded: &'static str,
        requested: &'static str,
    },

    #[error(
        "{0} is locked by another publish — wait for it to finish; releases \
         are published one at a time"
    )]
    Busy(String),

    #[error("invalid manifest signature")]
    BadManifestSignature,

    #[error("unknown manifest format: {0}")]
    UnknownManifestFormat(String),
}

/// The operator's signing key, the one the gateways trust bundles from.
///
/// A seed in a file is development-grade, exactly like the ledger's
/// [`obsign_ledger::FileSealer`] and for the same reason: production puts the key in
/// a KMS/HSM. It is deliberately a *different* key than the sealing key.
/// Compromising the one that writes rules must not yield the one that seals
/// history, and vice versa.
pub struct OpsKey {
    key: SigningKey,
    key_id: String,
}

impl OpsKey {
    pub fn from_seed_file(path: &Path, key_id: &str) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)?;
        let bytes =
            hex::decode(raw.trim()).map_err(|_| Error::BadSeed("not valid hex".to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::BadSeed("the seed must be 32 bytes".to_string()))?;
        Ok(Self::from_seed(seed, key_id))
    }

    /// For tests and examples only.
    pub fn from_seed(seed: [u8; 32], key_id: &str) -> Self {
        OpsKey {
            key: SigningKey::from_bytes(&seed),
            key_id: key_id.to_string(),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The ops key as the auditor must trust it: role `ops`, which admits it
    /// to neither the sealing nor the origin set.
    ///
    /// It used to carry the default `seal` role, for want of anything better
    /// to say. That handed whoever published the rules the power to mint
    /// checkpoints the auditor would accept, collapsing "who decides policy"
    /// and "who certifies history" into one authority. Nothing ever signed a
    /// checkpoint with it (the ledger seals, from its own key or an HSM), so
    /// no pack loses a proof by this becoming explicit.
    pub fn public_entry(&self) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: self.key_id.clone(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            role: obsign_audit_core::checkpoint::KeyRole::Ops,
        }
    }
}

/// Write-then-rename. This is what makes `publish` safe to run against live
/// gateways: a reader sees the old file or the new one, never a torn one.
///
/// The temporary file has a name of its own (pid and a counter), created
/// exclusively: a fixed `<name>.tmp` was shared by every writer of that path
/// and followed whatever sat there. The directory is synced after the
/// rename, or a crash could forget the rename the caller was told happened.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_data()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_parent_dir(path)
}

/// Makes a rename or a creation in `path`'s directory durable.
pub(crate) fn sync_parent_dir(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// An exclusive advisory lock on `dir`, held until the returned file is
/// dropped. Two publishes interleaving their writes into one dist/ could
/// each pass the other's checks and leave a manifest naming the other's
/// artifacts; the second one fails fast instead. The kernel drops the lock
/// with the process, so a crash leaves nothing to clean up.
pub(crate) fn lock_dir(dir: &Path) -> Result<std::fs::File, Error> {
    let path = dir.join(".publish.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::Busy(dir.display().to_string())),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Records the ops key's public half in a trusted-keys file, the file a
/// gateway is pointed at with `--trusted-keys`.
pub fn record_trusted_key_file(path: &Path, ops: &OpsKey) -> Result<Vec<PublicKeyEntry>, Error> {
    record_trusted_key(path, &ops.public_entry())
}

/// Records a public key in a trusted-keys file, enforcing the one-id-one-key
/// rule. Returns the full set as written.
pub(crate) fn record_trusted_key(
    path: &Path,
    entry: &PublicKeyEntry,
) -> Result<Vec<PublicKeyEntry>, Error> {
    let (keys, changed) = merge_trusted_key(path, entry)?;
    if changed {
        write_atomic(path, serde_json::to_string_pretty(&keys)?.as_bytes())?;
    }
    Ok(keys)
}

/// The trusted-keys set with `entry` merged in, and whether that changed it,
/// without writing anything: `publish` runs every refusal before its first
/// write, and a key recorded by a publish that was then refused would be
/// trust nobody decided to grant.
///
/// A key id binds one key in one role. The one role change accepted is the
/// documented upgrade of an ops key recorded by an earlier build under the
/// default `seal` role: same key material, tightened to `ops`.
pub(crate) fn merge_trusted_key(
    path: &Path,
    entry: &PublicKeyEntry,
) -> Result<(Vec<PublicKeyEntry>, bool), Error> {
    let mut keys: Vec<PublicKeyEntry> = if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(path)?)?
    } else {
        Vec::new()
    };

    if let Some(existing) = keys.iter_mut().find(|k| k.key_id == entry.key_id) {
        if existing.public_key != entry.public_key || existing.algo != entry.algo {
            return Err(Error::KeyConflict(entry.key_id.clone()));
        }
        if existing.role == entry.role {
            return Ok((keys, false));
        }
        if existing.role == KeyRole::Seal && entry.role == KeyRole::Ops {
            existing.role = KeyRole::Ops;
            return Ok((keys, true));
        }
        return Err(Error::KeyRoleConflict {
            key_id: entry.key_id.clone(),
            recorded: existing.role.as_str(),
            requested: entry.role.as_str(),
        });
    }
    keys.push(entry.clone());
    Ok((keys, true))
}
