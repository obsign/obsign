//! Fleet export: the audit dossier.
//!
//! `obsign-ledger export` produces one evidence pack for one chain. An
//! auditor asks for a period, not a chain: with the Streamable HTTP transport
//! every agent session is its own chain, and "what did your agents do in Q3"
//! is dozens of packs. This module walks every chain the WAL holds, exports
//! and verifies each pack, and binds the set together in a **signed export
//! manifest**, so the dossier itself cannot lose a pack in transit without
//! the loss being visible.
//!
//! Pack hashes are plain SHA-256 of the files as written: the recipient
//! checks them with `sha256sum`, then verifies each pack with `obsign
//! verify`. Nothing here requires our tooling twice.

use obsign_audit_core::canonical::Encoder;
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use obsign_audit_core::evidence::Report;
use obsign_audit_core::hash::{digest, domain, sha256, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use obsign_ledger::Store;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{write_atomic, Error, OpsKey};

pub const FORMAT: &str = "obsign-export/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub format: String,
    pub ts_ms: i64,
    /// Sorted by chain id; the order is part of the signature.
    pub packs: Vec<PackEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackEntry {
    pub chain_id: String,
    /// File name inside the export directory.
    pub file: String,
    pub sha256: Hash,
    pub records: u64,
    pub records_sealed: u64,
    pub checkpoints: u64,
    pub anchors: u64,
    /// Verification verdict at export time. A false here is not hidden and
    /// not repaired: an export that filtered or fixed on the way out would do
    /// exactly what the product exists to make impossible.
    pub valid: bool,
}

impl ExportManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.format).i64(self.ts_ms);
        e.u64(self.packs.len() as u64);
        for p in &self.packs {
            e.str(&p.chain_id)
                .str(&p.file)
                .hash(&p.sha256)
                .u64(p.records)
                .u64(p.records_sealed)
                .u64(p.checkpoints)
                .u64(p.anchors)
                .u8(p.valid as u8);
        }
        digest(domain::EXPORT_MANIFEST, e.finish())
            .as_bytes()
            .to_vec()
    }

    pub fn sign(self, key_id: impl Into<String>, key: &SigningKey) -> SignedExportManifest {
        let sig = key.sign(&self.signing_bytes());
        SignedExportManifest {
            manifest: self,
            key_id: key_id.into(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedExportManifest {
    pub manifest: ExportManifest,
    pub key_id: String,
    pub signature: String,
}

impl SignedExportManifest {
    pub fn verify(&self, key: &VerifyingKey) -> Result<&ExportManifest, Error> {
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

/// One exported chain, with its verification report.
#[derive(Debug)]
pub struct ChainExport {
    pub chain_id: String,
    pub file: String,
    pub report: Report,
}

/// Lists the chains a WAL directory holds, from the file names.
pub fn list_chains(wal_dir: &Path) -> Result<Vec<String>, Error> {
    let mut chains = Vec::new();
    if wal_dir.is_dir() {
        for entry in std::fs::read_dir(wal_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    chains.push(stem.to_string());
                }
            }
        }
    }
    chains.sort();
    Ok(chains)
}

/// Chains the store has sealed, read from its `<chain>.checkpoints.jsonl` files.
///
/// The store is the independent witness that a chain existed and was sealed. A
/// chain it names whose WAL file has since vanished is the "drop a whole chain
/// from the dossier" attack: `list_chains` reads only the WAL directory, so
/// without cross-checking the store the export would never see the missing
/// chain and would sign a smaller manifest that looks complete.
fn list_store_chains(store_dir: &Path) -> Result<Vec<String>, Error> {
    const SUFFIX: &str = ".checkpoints.jsonl";
    let mut chains = Vec::new();
    if store_dir.is_dir() {
        for entry in std::fs::read_dir(store_dir)? {
            let path = entry?.path();
            if let Some(chain) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(SUFFIX))
            {
                chains.push(chain.to_string());
            }
        }
    }
    chains.sort();
    Ok(chains)
}

/// Exports every chain and writes the signed manifest.
///
/// Packs that do not verify are written and listed anyway, marked invalid:
/// during an incident, the failing pack is precisely the one you want on
/// disk. The boolean says whether the whole dossier verified.
///
/// `pinned_seal_keys` is the auditor's out-of-band copy of the sealing keys.
/// Without it, each pack is verified against the store's own `keys.json`,
/// which proves the store agrees with itself and nothing more: a store
/// re-sealed under a substitute key exports as valid. With it, every store
/// key must be one of the pinned ones, and the packs are verified against
/// the pinned set only.
///
/// The dossier is all or nothing. It is assembled in a sibling directory and
/// renamed to `out_dir` once complete, the manifest written last inside it,
/// so a failure at any point leaves `out_dir` as it was. `out_dir` must be
/// absent or empty: packs from an earlier export left beside a new manifest
/// would sit in the dossier unlisted, and deleting files the operator put
/// there is not this command's call.
pub fn export_all(
    wal_dir: &Path,
    store_dir: &Path,
    out_dir: &Path,
    ops: &OpsKey,
    ts_ms: i64,
    pinned_seal_keys: Option<&[PublicKeyEntry]>,
) -> Result<(Vec<ChainExport>, bool), Error> {
    if !store_dir.is_dir() {
        // Store::open would silently create an empty store, and every chain
        // would export as "0 sealed", technically true, operationally a
        // mistyped path. Refuse instead.
        return Err(Error::Source(format!(
            "store directory {} does not exist",
            store_dir.display()
        )));
    }
    let chains = list_chains(wal_dir)?;
    if chains.is_empty() {
        return Err(Error::Source(format!(
            "no chain found in {}: an empty audit dossier is a mistyped path, \
             not a result",
            wal_dir.display()
        )));
    }

    // A sealed chain the store knows about but the WAL no longer holds is a
    // removed WAL file: the exact way to make a whole session disappear from
    // the dossier while every remaining pack still verifies. Refuse rather than
    // sign a manifest that silently omits it. (A chain in the WAL but not the
    // store is only unsealed, which the per-chain export already reports.)
    let dropped: Vec<String> = list_store_chains(store_dir)?
        .into_iter()
        .filter(|c| !chains.contains(c))
        .collect();
    if !dropped.is_empty() {
        return Err(Error::Source(format!(
            "store holds sealed chain(s) with no WAL file in {}: {} — a WAL was \
             removed; a dossier cannot omit a sealed chain",
            wal_dir.display(),
            dropped.join(", ")
        )));
    }

    let pinned: Option<Vec<PublicKeyEntry>> = pinned_seal_keys.map(|keys| {
        keys.iter()
            .filter(|k| k.role == KeyRole::Seal)
            .cloned()
            .collect()
    });
    if pinned.as_ref().is_some_and(|p| p.is_empty()) {
        return Err(Error::Source(
            "the pinned key file holds no key with role seal".to_string(),
        ));
    }

    let staging = staging_dir(out_dir)?;

    // Everything that can refuse runs before the first write.
    let mut exports = Vec::new();
    let mut entries = Vec::new();
    let mut packs = Vec::new();
    let mut all_valid = true;

    for chain_id in chains {
        let records = obsign_wal::read(wal_dir, &chain_id)?;
        let store = Store::open(store_dir, &chain_id)?;
        let trusted = match &pinned {
            None => store.keys().to_vec(),
            Some(pinned) => {
                if let Some(k) = store.keys().iter().find(|k| !pinned.contains(k)) {
                    return Err(Error::Source(format!(
                        "store {} records sealing key \"{}\", which is not one of \
                         the pinned seal keys — the store was sealed under a key \
                         you did not pin",
                        store_dir.display(),
                        k.key_id
                    )));
                }
                pinned.clone()
            }
        };
        let evidence = obsign_ledger::export(records, &store, &[], None);
        let report = obsign_audit_core::evidence::verify(&evidence, &trusted);

        let file = format!("{chain_id}.evidence.json");
        let bytes = serde_json::to_vec_pretty(&evidence)?;

        all_valid &= report.is_valid();
        entries.push(PackEntry {
            chain_id: chain_id.clone(),
            file: file.clone(),
            sha256: sha256(&bytes),
            records: evidence.records.len() as u64,
            records_sealed: report.records_sealed as u64,
            checkpoints: evidence.checkpoints.len() as u64,
            anchors: evidence.anchors.len() as u64,
            valid: report.is_valid(),
        });
        packs.push((file.clone(), bytes));
        exports.push(ChainExport {
            chain_id,
            file,
            report,
        });
    }

    let manifest = ExportManifest {
        format: FORMAT.to_string(),
        ts_ms,
        packs: entries,
    };
    let signed = manifest.sign(ops.key_id(), ops.signing_key());
    signed.verify(&ops.signing_key().verifying_key())?;
    let manifest_bytes = serde_json::to_vec_pretty(&signed)?;

    let written = (|| {
        std::fs::create_dir(&staging)?;
        for (file, bytes) in &packs {
            write_atomic(&staging.join(file), bytes)?;
        }
        // The manifest key is a trusted key the recipient can be given out
        // of band, in the same file format the verifier already accepts.
        record_key_file(&staging, ops)?;
        // Manifest last: a directory holding it holds every pack it names.
        write_atomic(&staging.join("export-manifest.json"), &manifest_bytes)?;
        if out_dir.exists() {
            // Checked empty above; `remove_dir` refuses anything else.
            std::fs::remove_dir(out_dir)?;
        }
        std::fs::rename(&staging, out_dir)?;
        crate::sync_parent_dir(out_dir)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    Ok((exports, all_valid))
}

/// The sibling directory the dossier is assembled in, after checking that
/// `out_dir` is absent or an empty directory.
fn staging_dir(out_dir: &Path) -> Result<std::path::PathBuf, Error> {
    match std::fs::read_dir(out_dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(Error::Source(format!(
                    "{} is not empty: a dossier is written to a new or empty \
                     directory, so that no file from an earlier export sits \
                     beside a manifest that does not list it",
                    out_dir.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let name = out_dir.file_name().ok_or_else(|| {
        Error::Source(format!("{}: not a directory name", out_dir.display()))
    })?;
    let parent = match out_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    std::fs::create_dir_all(&parent)?;
    Ok(parent.join(format!(
        ".{}.partial-{}",
        name.to_string_lossy(),
        std::process::id()
    )))
}

fn record_key_file(out_dir: &Path, ops: &OpsKey) -> Result<(), Error> {
    crate::record_trusted_key(&out_dir.join("export-keys.json"), &ops.public_entry())?;
    Ok(())
}
