//! Publication: signed artifacts become a release the gateways can watch.
//!
//! Distribution directory layout:
//!
//! ```text
//! <dist>/
//!   policy-bundle.json      current: atomically replaced, gateways watch these
//!   identity-bundle.json    current, absent when the release has none
//!   deployment-bundle.json  current, absent when the release has none
//!   manifest.json           current, signed
//!   trusted-keys.json       accumulated ops public keys
//!   releases/<version>/     immutable history, one directory per version
//! ```
//!
//! Two invariants carry this module:
//!
//! * **a version is immutable**, `releases/<sha>/` is written once; a
//!   publish that would change its content, artifact set included, is
//!   refused. Decisions in the audit
//!   log cite `policies@<sha>`: replaying them months later requires that the
//!   sha still designate the same rules;
//! * **the current files change atomically**, write-then-rename, so a
//!   gateway hot-reloading mid-publish reads the old release or the new one,
//!   never a torn file. Rollback needs no tooling: republish the old sha.

use obsign_audit_core::canonical::Encoder;
use obsign_audit_core::checkpoint::PublicKeyEntry;
use obsign_audit_core::hash::{digest, domain, sha256, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::compile::Compiled;
use crate::{merge_trusted_key, write_atomic, Error, OpsKey};

pub const FORMAT: &str = "obsign-release/1";

/// Every artifact a release can carry. A release that lacks one must not
/// leave the previous release's copy current in dist/.
const ARTIFACT_NAMES: [&str; 3] = [
    "deployment-bundle.json",
    "identity-bundle.json",
    "policy-bundle.json",
];

/// What a release contains, hashed file by file.
///
/// The artifact hashes are plain SHA-256 of the file bytes, deliberately
/// comparable with `sha256sum`, so "is the bundle my gateway loaded the one
/// the manifest names?" is answerable with standard tooling. What is signed
/// is the manifest, through the canonical encoding, like everything else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    /// The source ref: short commit sha or explicit label.
    pub version: String,
    pub ts_ms: i64,
    /// Sorted by name; the order is part of the signature.
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub sha256: Hash,
}

impl Manifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.format).str(&self.version).i64(self.ts_ms);
        e.u64(self.artifacts.len() as u64);
        for a in &self.artifacts {
            e.str(&a.name).hash(&a.sha256);
        }
        digest(domain::RELEASE_MANIFEST, e.finish())
            .as_bytes()
            .to_vec()
    }

    pub fn sign(self, key_id: impl Into<String>, key: &SigningKey) -> SignedManifest {
        let sig = key.sign(&self.signing_bytes());
        SignedManifest {
            manifest: self,
            key_id: key_id.into(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub key_id: String,
    pub signature: String,
}

impl SignedManifest {
    pub fn verify(&self, key: &VerifyingKey) -> Result<&Manifest, Error> {
        let raw = hex::decode(&self.signature).map_err(|_| Error::BadManifestSignature)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadManifestSignature)?;
        key.verify(&self.manifest.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadManifestSignature)?;
        if self.manifest.format != FORMAT {
            return Err(Error::UnknownManifestFormat(self.manifest.format.clone()));
        }
        Ok(&self.manifest)
    }
}

#[derive(Debug)]
pub struct Published {
    pub version: String,
    pub release_dir: PathBuf,
    /// True when `releases/<version>/` already held these exact bytes: an
    /// idempotent re-publish, or a rollback to an earlier release.
    pub reused: bool,
}

pub fn publish(
    dist: &Path,
    compiled: &Compiled,
    ops: &OpsKey,
    ts_ms: i64,
) -> Result<Published, Error> {
    std::fs::create_dir_all(dist)?;

    // Serialized once; these exact bytes are hashed, written into the release
    // directory and copied to the current files. Manifest hash == file bytes,
    // by construction rather than by care.
    let mut artifacts: Vec<(String, Vec<u8>)> = vec![(
        "policy-bundle.json".to_string(),
        serde_json::to_vec_pretty(&compiled.policy)?,
    )];
    if let Some(idb) = &compiled.identity {
        artifacts.push((
            "identity-bundle.json".to_string(),
            serde_json::to_vec_pretty(idb)?,
        ));
    }
    if let Some(db) = &compiled.deployment {
        artifacts.push((
            "deployment-bundle.json".to_string(),
            serde_json::to_vec_pretty(db)?,
        ));
    }
    artifacts.sort_by(|a, b| a.0.cmp(&b.0));

    // Every refusal runs before the first write: a refused publish leaves
    // dist/ exactly as it found it.
    //
    // The ops key becomes (or already is) a trusted key; a rebound key id is
    // refused here. The full set is kept: a rollback may republish a
    // manifest signed by an *earlier* ops key.
    let trusted_path = dist.join("trusted-keys.json");
    let (trusted, trusted_changed) = merge_trusted_key(&trusted_path, &ops.public_entry())?;

    let version = compiled.source_ref.clone();
    let release_dir = dist.join("releases").join(&version);

    // Immutability check, with crash repair: an artifact missing from an
    // existing release directory (a publish that died halfway) is rewritten;
    // an artifact with *different* content is a refusal, the author changed
    // the source without committing, and the sha would lie.
    let mut missing = Vec::new();
    for (name, bytes) in &artifacts {
        match std::fs::read(release_dir.join(name)) {
            Ok(existing) if &existing == bytes => {}
            Ok(_) => return Err(Error::VersionConflict { version }),
            Err(_) => missing.push((name, bytes)),
        }
    }
    let reused = missing.is_empty();

    // The artifact *set* is part of the release too: the same version
    // without its identity bundle (or with one it did not have) is different
    // content, whether the earlier publish got as far as its manifest or
    // died before it.
    let published = |name: &str| artifacts.iter().any(|(n, _)| n == name);
    for name in ARTIFACT_NAMES.iter().filter(|n| !published(n)) {
        if release_dir.join(name).exists() {
            return Err(Error::VersionConflict { version });
        }
    }
    let manifest_path = release_dir.join("manifest.json");
    if let Ok(bytes) = std::fs::read(&manifest_path) {
        if let Ok(existing) = serde_json::from_slice::<SignedManifest>(&bytes) {
            let names: Vec<&str> = existing.manifest.artifacts.iter().map(|a| a.name.as_str()).collect();
            if names.iter().any(|n| !published(n)) || names.len() != artifacts.len() {
                return Err(Error::VersionConflict { version });
            }
        }
    }

    if trusted_changed {
        write_atomic(&trusted_path, serde_json::to_string_pretty(&trusted)?.as_bytes())?;
    }
    std::fs::create_dir_all(&release_dir)?;
    for (name, bytes) in missing {
        write_atomic(&release_dir.join(name), bytes)?;
    }

    let manifest = Manifest {
        format: FORMAT.to_string(),
        version: version.clone(),
        ts_ms,
        artifacts: artifacts
            .iter()
            .map(|(name, bytes)| Artifact {
                name: name.clone(),
                sha256: sha256(bytes),
            })
            .collect(),
    };

    // On a rollback the original manifest (and its original timestamp) is
    // kept: the manifest describes the release, not the act of pointing the
    // fleet at it. A fresh one is only written when the directory is new or
    // its manifest is unreadable or no longer verifies (crash repair again).
    let manifest_bytes = match read_matching_manifest(&manifest_path, &manifest.artifacts, &trusted)
    {
        Some(bytes) => bytes,
        None => {
            let signed = manifest.clone().sign(ops.key_id(), ops.signing_key());
            signed.verify(&ops.signing_key().verifying_key())?;
            let bytes = serde_json::to_vec_pretty(&signed)?;
            write_atomic(&manifest_path, &bytes)?;
            bytes
        }
    };

    // Current files last, manifest last of all: a reader that sees the new
    // manifest is guaranteed to see the artifacts it names, and none it does
    // not. A current file the new release lacks is removed: left in place,
    // a gateway would keep loading the previous release's identity bundle,
    // or a ledger the previous enrolment, under a manifest that says this
    // release has none.
    for (name, bytes) in &artifacts {
        write_atomic(&dist.join(name), bytes)?;
    }
    for name in ARTIFACT_NAMES.iter().filter(|n| !published(n)) {
        match std::fs::remove_file(dist.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    write_atomic(&dist.join("manifest.json"), &manifest_bytes)?;

    Ok(Published {
        version,
        release_dir,
        reused,
    })
}

/// Returns the existing manifest bytes if they parse, name exactly the
/// artifacts being published, and still carry a valid signature from a
/// trusted key.
///
/// The signature check is not redundancy: on a rollback these bytes become
/// the *current* manifest the fleet trusts. A manifest tampered with in the
/// release directory since it was written must be re-signed fresh, not
/// propagated as-is.
fn read_matching_manifest(
    path: &Path,
    artifacts: &[Artifact],
    trusted: &[PublicKeyEntry],
) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let signed: SignedManifest = serde_json::from_slice(&bytes).ok()?;
    if signed.manifest.artifacts != artifacts {
        return None;
    }
    let vk = trusted
        .iter()
        .find(|k| k.key_id == signed.key_id)?
        .to_verifying_key()
        .ok()?;
    signed.verify(&vk).ok()?;
    Some(bytes)
}
