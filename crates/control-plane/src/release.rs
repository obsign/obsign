//! Publication: signed artifacts become a release the gateways can watch.
//!
//! Distribution directory layout:
//!
//! ```text
//! <dist>/
//!   policy-bundle.json      current — atomically replaced, gateways watch these
//!   identity-bundle.json    current
//!   manifest.json           current, signed
//!   trusted-keys.json       accumulated ops public keys
//!   releases/<version>/     immutable history, one directory per version
//! ```
//!
//! Two invariants carry this module:
//!
//! * **a version is immutable** — `releases/<sha>/` is written once; a
//!   publish that would change its content is refused. Decisions in the audit
//!   log cite `policies@<sha>`: replaying them months later requires that the
//!   sha still designate the same rules;
//! * **the current files change atomically** — write-then-rename, so a
//!   gateway hot-reloading mid-publish reads the old release or the new one,
//!   never a torn file. Rollback needs no tooling: republish the old sha.

use audit_core::canonical::Encoder;
use audit_core::hash::{digest, domain, sha256, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::compile::Compiled;
use crate::{record_trusted_key, write_atomic, Error, OpsKey};

pub const FORMAT: &str = "probant-release/1";

/// What a release contains, hashed file by file.
///
/// The artifact hashes are plain SHA-256 of the file bytes — deliberately
/// comparable with `sha256sum`, so "is the bundle my gateway loaded the one
/// the manifest names?" is answerable with standard tooling. What is signed
/// is the manifest, through the canonical encoding, like everything else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: String,
    /// The source ref: short commit sha or explicit label.
    pub version: String,
    pub ts_ms: i64,
    /// Sorted by name; the order is part of the signature.
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

    // The ops key becomes (or already is) a trusted key. Refusing a rebound
    // key id happens before anything else is written.
    record_trusted_key(&dist.join("trusted-keys.json"), &ops.public_entry())?;

    let version = compiled.source_ref.clone();
    let release_dir = dist.join("releases").join(&version);
    std::fs::create_dir_all(&release_dir)?;

    // Immutability check, with crash repair: an artifact missing from an
    // existing release directory (a publish that died halfway) is rewritten;
    // an artifact with *different* content is a refusal — the author changed
    // the source without committing, and the sha would lie.
    let mut reused = true;
    for (name, bytes) in &artifacts {
        let path = release_dir.join(name);
        match std::fs::read(&path) {
            Ok(existing) if &existing == bytes => {}
            Ok(_) => return Err(Error::VersionConflict { version }),
            Err(_) => {
                reused = false;
                write_atomic(&path, bytes)?;
            }
        }
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
    // its manifest no longer matches the artifacts (crash repair again).
    let manifest_path = release_dir.join("manifest.json");
    let manifest_bytes = match read_matching_manifest(&manifest_path, &manifest.artifacts) {
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
    // manifest is guaranteed to see the artifacts it names.
    for (name, bytes) in &artifacts {
        write_atomic(&dist.join(name), bytes)?;
    }
    write_atomic(&dist.join("manifest.json"), &manifest_bytes)?;

    Ok(Published {
        version,
        release_dir,
        reused,
    })
}

/// Returns the existing manifest bytes if they parse and name exactly the
/// artifacts being published.
fn read_matching_manifest(path: &Path, artifacts: &[Artifact]) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let signed: SignedManifest = serde_json::from_slice(&bytes).ok()?;
    (signed.manifest.artifacts == artifacts).then_some(bytes)
}
