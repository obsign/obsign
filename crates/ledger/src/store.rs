use crate::Error;
use audit_core::checkpoint::{PublicKeyEntry, SignedCheckpoint};
use audit_core::rfc3161::Anchor;
use audit_core::Hash;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Durable home of everything the ledger produces: checkpoints, anchors,
/// and the public halves of the keys that sealed.
///
/// Same file philosophy as the WAL — JSONL, readable with `tail` during an
/// incident — and the same trust model: the files prove nothing by
/// themselves. Every checkpoint is re-verified on load (signature, chaining,
/// gapless coverage), so a store whose disk was edited refuses to open
/// instead of quietly serving rewritten history.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    chain_id: String,
    checkpoints: Vec<SignedCheckpoint>,
    anchors: Vec<Anchor>,
    keys: Vec<PublicKeyEntry>,
}

impl Store {
    /// Opens (or creates) the store and re-verifies everything in it.
    pub fn open(dir: &Path, chain_id: &str) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;

        let keys: Vec<PublicKeyEntry> = {
            let path = dir.join("keys.json");
            if path.exists() {
                serde_json::from_str(&std::fs::read_to_string(&path)?)?
            } else {
                Vec::new()
            }
        };

        let checkpoints: Vec<SignedCheckpoint> =
            read_jsonl(&dir.join(format!("{chain_id}.checkpoints.jsonl")))?;

        // Full re-validation, not a format check. The threat is someone with
        // write access to this directory; the answer is that nothing loaded
        // from it is believed until it re-proves itself.
        let mut prev_hash: Option<Hash> = None;
        let mut next_from = 0u64;
        for (i, sc) in checkpoints.iter().enumerate() {
            let cp = &sc.checkpoint;
            let label = format!("checkpoint {} [{}..{}]", i, cp.from_seq, cp.to_seq);
            if cp.chain_id != chain_id {
                return Err(Error::StoreBroken(format!(
                    "{label} seals chain \"{}\", store belongs to \"{chain_id}\"",
                    cp.chain_id
                )));
            }
            if cp.prev_checkpoint_hash != prev_hash {
                return Err(Error::StoreBroken(format!(
                    "{label} does not chain from its predecessor: a seal was \
                     removed, reordered or forged"
                )));
            }
            if cp.from_seq != next_from || cp.to_seq < cp.from_seq {
                // Coverage must be gapless: an unsealed hole between two
                // seals is a place where history can be edited later.
                return Err(Error::StoreBroken(format!(
                    "{label}: sealed coverage expected to resume at seq {next_from}"
                )));
            }
            let key = keys
                .iter()
                .find(|k| k.key_id == cp.key_id)
                .ok_or_else(|| {
                    Error::StoreBroken(format!(
                        "{label} signed with unrecorded key \"{}\"",
                        cp.key_id
                    ))
                })?;
            sc.verify(&key.to_verifying_key()?)?;

            prev_hash = Some(cp.hash());
            next_from = cp.to_seq + 1;
        }

        let anchors: Vec<Anchor> =
            read_jsonl(&dir.join(format!("{chain_id}.anchors.jsonl")))?;
        for a in &anchors {
            if !checkpoints
                .iter()
                .any(|sc| sc.checkpoint.hash() == a.checkpoint_hash)
            {
                return Err(Error::StoreBroken(format!(
                    "anchor over unknown checkpoint {}",
                    a.checkpoint_hash
                )));
            }
        }

        Ok(Store {
            dir: dir.to_path_buf(),
            chain_id: chain_id.to_string(),
            checkpoints,
            anchors,
            keys,
        })
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn checkpoints(&self) -> &[SignedCheckpoint] {
        &self.checkpoints
    }

    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    pub fn keys(&self) -> &[PublicKeyEntry] {
        &self.keys
    }

    pub fn last(&self) -> Option<&SignedCheckpoint> {
        self.checkpoints.last()
    }

    /// Hash the next checkpoint must chain from.
    pub fn last_hash(&self) -> Option<Hash> {
        self.last().map(|sc| sc.checkpoint.hash())
    }

    pub fn find_checkpoint(&self, hash: &Hash) -> Option<&SignedCheckpoint> {
        self.checkpoints
            .iter()
            .find(|sc| sc.checkpoint.hash() == *hash)
    }

    /// Appends a checkpoint after checking it continues sealed history.
    ///
    /// The checks mirror `open`: what would be rejected on reload must be
    /// rejected on write, otherwise the store poisons itself for the next
    /// start.
    pub fn append_checkpoint(
        &mut self,
        signed: SignedCheckpoint,
        key: &PublicKeyEntry,
    ) -> Result<(), Error> {
        let cp = &signed.checkpoint;
        if cp.chain_id != self.chain_id {
            return Err(Error::StoreBroken(format!(
                "refusing a checkpoint for chain \"{}\"",
                cp.chain_id
            )));
        }
        if cp.prev_checkpoint_hash != self.last_hash() {
            return Err(Error::StoreBroken(
                "checkpoint does not chain from the current head".to_string(),
            ));
        }
        let next_from = self.last().map(|sc| sc.checkpoint.to_seq + 1).unwrap_or(0);
        if cp.from_seq != next_from || cp.to_seq < cp.from_seq {
            return Err(Error::StoreBroken(format!(
                "checkpoint covers [{}..{}], expected coverage to resume at \
                 seq {next_from}",
                cp.from_seq, cp.to_seq
            )));
        }

        self.record_key(key)?;
        signed.verify(&key.to_verifying_key()?)?;

        append_line(
            &self.dir.join(format!("{}.checkpoints.jsonl", self.chain_id)),
            &serde_json::to_string(&signed)?,
        )?;
        self.checkpoints.push(signed);
        Ok(())
    }

    /// Appends an anchor. Structural validation against the token happened in
    /// `validate_response`; here we only refuse anchors over checkpoints we
    /// do not hold.
    pub fn append_anchor(&mut self, anchor: Anchor) -> Result<(), Error> {
        if self.find_checkpoint(&anchor.checkpoint_hash).is_none() {
            return Err(Error::UnknownCheckpoint(anchor.checkpoint_hash));
        }
        append_line(
            &self.dir.join(format!("{}.anchors.jsonl", self.chain_id)),
            &serde_json::to_string(&anchor)?,
        )?;
        self.anchors.push(anchor);
        Ok(())
    }

    /// Records a sealing public key.
    ///
    /// A key id maps to exactly one key, forever: verification looks keys up
    /// by id, so re-binding an id would let a new key silently claim old
    /// seals. Rotation means a new id.
    fn record_key(&mut self, key: &PublicKeyEntry) -> Result<(), Error> {
        if let Some(existing) = self.keys.iter().find(|k| k.key_id == key.key_id) {
            if existing.public_key != key.public_key || existing.algo != key.algo {
                return Err(Error::KeyConflict(key.key_id.clone()));
            }
            return Ok(());
        }
        self.keys.push(key.clone());

        // Write-then-rename: a torn keys.json would make every checkpoint
        // unverifiable at the next open.
        let path = self.dir.join("keys.json");
        let tmp = self.dir.join("keys.json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(serde_json::to_string_pretty(&self.keys)?.as_bytes())?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Reads a JSONL file, tolerating exactly one torn line at the very end.
///
/// A torn final line is a crash mid-append: the seal (or anchor) was never
/// acknowledged, and the records it covered are still unsealed — sealing them
/// again is harmless. The torn line is trimmed so it does not poison every
/// future load. Anywhere else, an unreadable line is genuine corruption.
fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    let chunks: Vec<&str> = content.split_inclusive('\n').collect();

    let mut items = Vec::new();
    let mut offset = 0usize;
    for (i, chunk) in chunks.iter().enumerate() {
        let line = chunk.trim_end_matches('\n');
        if line.is_empty() {
            offset += chunk.len();
            continue;
        }
        match serde_json::from_str::<T>(line) {
            Ok(v) => {
                items.push(v);
                offset += chunk.len();
            }
            Err(e) => {
                if i + 1 == chunks.len() {
                    let f = OpenOptions::new().write(true).open(path)?;
                    f.set_len(offset as u64)?;
                    f.sync_data()?;
                    break;
                }
                return Err(Error::StoreBroken(format!(
                    "unreadable line {} in {}: {e}",
                    i + 1,
                    path.display()
                )));
            }
        }
    }
    Ok(items)
}

/// Append one line and make it durable before acknowledging.
fn append_line(path: &Path, line: &str) -> Result<(), Error> {
    let mut f = OpenOptions::new().append(true).create(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()?;
    f.sync_data()?;
    Ok(())
}
