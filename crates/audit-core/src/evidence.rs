use crate::checkpoint::{PublicKeyEntry, SignedCheckpoint};
use crate::hash::{Hash, GENESIS};
use crate::merkle::merkle_root;
use crate::record::Record;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FORMAT: &str = "probant-evidence/1";

/// Evidence pack: what we hand to an auditor.
///
/// Deliberately self-contained and in readable JSON. The auditor must be able
/// to open it in a text editor and check it with `probant verify` without any
/// access to our infrastructure. If verification needs a server, it is no
/// longer proof, it is a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub format: String,
    pub chain_id: String,
    pub records: Vec<Record>,
    pub checkpoints: Vec<SignedCheckpoint>,
    /// Sealing public keys. Including them is a reading convenience, not
    /// proof: `probant verify` must be run with a trusted key set obtained through
    /// another channel (--trusted-keys), otherwise a forged pack signed with a
    /// made-up key would validate itself.
    pub keys: Vec<PublicKeyEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable code, meant to be matched in scripts and CI pipelines.
    /// The message may change; the code may not.
    pub code: String,
    pub message: String,
}

impl Finding {
    fn error(code: &str, message: impl Into<String>) -> Self {
        Finding {
            severity: Severity::Error,
            code: code.to_string(),
            message: message.into(),
        }
    }
    fn warning(code: &str, message: impl Into<String>) -> Self {
        Finding {
            severity: Severity::Warning,
            code: code.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub chain_id: String,
    pub records_total: usize,
    pub records_sealed: usize,
    pub checkpoints_total: usize,
    pub checkpoints_valid: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// A single Error-severity finding invalidates the whole pack.
    pub fn is_valid(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
    }
}

/// Verifies an evidence pack.
///
/// `trusted`: public keys obtained outside the pack. If empty we fall back to
/// the embedded ones, but the whole verification becomes self-referential and
/// the report says so explicitly.
pub fn verify(ev: &Evidence, trusted: &[PublicKeyEntry]) -> Report {
    let mut findings = Vec::new();

    if ev.format != FORMAT {
        findings.push(Finding::error(
            "unknown_format",
            format!("format \"{}\", expected \"{}\"", ev.format, FORMAT),
        ));
    }

    // --- Trusted key set ----------------------------------------------
    let key_source = if trusted.is_empty() {
        findings.push(Finding::warning(
            "keys_not_anchored",
            "no trusted keys supplied: verification used the keys embedded in \
             the pack. This proves internal consistency, not authenticity. \
             Re-run with --trusted-keys.",
        ));
        &ev.keys
    } else {
        trusted
    };

    let mut keys = BTreeMap::new();
    for entry in key_source {
        match entry.to_verifying_key() {
            Ok(vk) => {
                keys.insert(entry.key_id.clone(), vk);
            }
            Err(e) => findings.push(Finding::error(
                "invalid_key",
                format!("key \"{}\" unusable: {e}", entry.key_id),
            )),
        }
    }

    // --- Integrity chain ----------------------------------------------
    // We do not sort the input: an audit tool that silently reorders what it
    // is given hides exactly what it is supposed to reveal.
    let mut records_by_seq: BTreeMap<u64, &Record> = BTreeMap::new();
    let mut hash_by_seq: BTreeMap<u64, Hash> = BTreeMap::new();

    if ev.records.is_empty() {
        findings.push(Finding::warning("empty_pack", "no records in the pack"));
    }

    let mut prev: Option<(u64, Hash)> = None;
    for (i, rec) in ev.records.iter().enumerate() {
        let h = rec.hash();

        match prev {
            None => {
                if rec.seq != 0 && rec.prev_hash.is_genesis() {
                    findings.push(Finding::error(
                        "inconsistent_anchor",
                        format!(
                            "record seq={} claims to head the chain (genesis \
                             prev_hash) without being seq=0",
                            rec.seq
                        ),
                    ));
                } else if rec.seq != 0 {
                    findings.push(Finding::warning(
                        "partial_chain",
                        format!(
                            "extract starts at seq={}: earlier records are not \
                             covered by this verification",
                            rec.seq
                        ),
                    ));
                } else if !rec.prev_hash.is_genesis() {
                    findings.push(Finding::error(
                        "invalid_genesis",
                        "seq=0 must have an all-zero prev_hash",
                    ));
                }
            }
            Some((pseq, phash)) => {
                if rec.seq <= pseq {
                    findings.push(Finding::error(
                        "invalid_order",
                        format!(
                            "seq not strictly increasing at position {i}: \
                             {} after {pseq}",
                            rec.seq
                        ),
                    ));
                } else if rec.seq != pseq + 1 {
                    findings.push(Finding::error(
                        "sequence_gap",
                        format!(
                            "gap between seq={pseq} and seq={}: {} record(s) \
                             missing or deleted",
                            rec.seq,
                            rec.seq - pseq - 1
                        ),
                    ));
                }
                if rec.prev_hash != phash {
                    findings.push(Finding::error(
                        "broken_link",
                        format!(
                            "seq={}: prev_hash={} while seq={pseq} hashes to \
                             {phash}. A record was modified, inserted or \
                             replaced.",
                            rec.seq, rec.prev_hash
                        ),
                    ));
                }
            }
        }

        if records_by_seq.insert(rec.seq, rec).is_some() {
            findings.push(Finding::error(
                "duplicate_sequence",
                format!("seq={} appears more than once", rec.seq),
            ));
        }
        hash_by_seq.insert(rec.seq, h);
        prev = Some((rec.seq, h));
    }

    // --- Checkpoints ---------------------------------------------------
    let mut checkpoints_valid = 0usize;
    let mut sealed: Vec<(u64, u64)> = Vec::new();
    let mut prev_cp_hash: Option<Hash> = None;

    for sc in &ev.checkpoints {
        let cp = &sc.checkpoint;
        let label = format!("[{}..{}]", cp.from_seq, cp.to_seq);
        let mut cp_ok = true;

        if cp.chain_id != ev.chain_id {
            findings.push(Finding::error(
                "foreign_chain",
                format!(
                    "checkpoint {label} seals chain \"{}\" while the pack covers \
                     \"{}\"",
                    cp.chain_id, ev.chain_id
                ),
            ));
            cp_ok = false;
        }

        // Checkpoint chaining: without this check, a whole checkpoint — and
        // therefore its whole interval — could be removed unnoticed.
        if sc.checkpoint.prev_checkpoint_hash != prev_cp_hash {
            findings.push(Finding::error(
                "broken_checkpoint_link",
                format!(
                    "checkpoint {label}: prev_checkpoint_hash does not match the \
                     preceding checkpoint. A seal was removed or reordered."
                ),
            ));
            cp_ok = false;
        }
        prev_cp_hash = Some(cp.hash());

        // Signature.
        match keys.get(&cp.key_id) {
            None => {
                findings.push(Finding::error(
                    "unknown_key",
                    format!(
                        "checkpoint {label} signed with key \"{}\", absent from \
                         the trusted key set",
                        cp.key_id
                    ),
                ));
                cp_ok = false;
            }
            Some(vk) => {
                if let Err(e) = sc.verify(vk) {
                    findings.push(Finding::error("invalid_signature", e.to_string()));
                    cp_ok = false;
                }
            }
        }

        // Merkle root recomputed over the interval.
        if cp.to_seq < cp.from_seq {
            findings.push(Finding::error(
                "invalid_interval",
                format!("checkpoint {label}: upper bound below lower bound"),
            ));
            cp_ok = false;
        } else {
            let mut leaves = Vec::new();
            let mut missing = Vec::new();
            for seq in cp.from_seq..=cp.to_seq {
                match hash_by_seq.get(&seq) {
                    Some(h) => leaves.push(*h),
                    None => missing.push(seq),
                }
            }

            if !missing.is_empty() {
                findings.push(Finding::error(
                    "missing_records",
                    format!(
                        "checkpoint {label}: {} record(s) of the interval are \
                         absent from the pack, the root cannot be recomputed",
                        missing.len()
                    ),
                ));
                cp_ok = false;
            } else {
                match merkle_root(&leaves) {
                    None => {
                        findings.push(Finding::error(
                            "empty_seal",
                            format!("checkpoint {label} covers no record"),
                        ));
                        cp_ok = false;
                    }
                    Some(root) => {
                        if root != cp.root {
                            findings.push(Finding::error(
                                "root_mismatch",
                                format!(
                                    "checkpoint {label}: sealed root {} but \
                                     recomputed root {root}. The interval's \
                                     content does not match the seal.",
                                    cp.root
                                ),
                            ));
                            cp_ok = false;
                        }
                    }
                }

                if let Some(head) = hash_by_seq.get(&cp.to_seq) {
                    if *head != cp.head_hash {
                        findings.push(Finding::error(
                            "head_mismatch",
                            format!(
                                "checkpoint {label}: head_hash does not match the \
                                 hash of seq={}",
                                cp.to_seq
                            ),
                        ));
                        cp_ok = false;
                    }
                }
            }
        }

        if cp_ok {
            checkpoints_valid += 1;
            sealed.push((cp.from_seq, cp.to_seq));
        }
    }

    // --- Coverage ------------------------------------------------------
    // Frequently overlooked property: a record that is present and consistent
    // but covered by no valid seal is not proven. It may have been appended
    // after the fact. The report has to say so.
    let sealed_count = records_by_seq
        .keys()
        .filter(|seq| sealed.iter().any(|(a, b)| *seq >= a && *seq <= b))
        .count();

    let unsealed = records_by_seq.len() - sealed_count;
    if unsealed > 0 {
        findings.push(Finding::warning(
            "unsealed_records",
            format!(
                "{unsealed} record(s) are covered by no valid checkpoint: \
                 consistent with the chain, but not proven"
            ),
        ));
    }

    Report {
        chain_id: ev.chain_id.clone(),
        records_total: ev.records.len(),
        records_sealed: sealed_count,
        checkpoints_total: ev.checkpoints.len(),
        checkpoints_valid,
        first_seq: records_by_seq.keys().next().copied(),
        last_seq: records_by_seq.keys().next_back().copied(),
        findings,
    }
}

/// Expected hash for the first record of a chain.
pub fn genesis() -> Hash {
    GENESIS
}
