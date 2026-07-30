use crate::checkpoint::{PublicKeyEntry, SignedCheckpoint};
use crate::hash::{Hash, GENESIS};
use crate::merkle::merkle_root;
use crate::record::Record;
use crate::rfc3161::{parse_timestamp_response, Anchor};
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
#[serde(deny_unknown_fields)]
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
    /// RFC 3161 timestamp tokens over checkpoint hashes. Optional (`default`):
    /// packs produced before anchoring existed stay readable, and an absent
    /// field is an absent proof, not a format break.
    #[serde(default)]
    pub anchors: Vec<Anchor>,
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
    #[serde(default)]
    pub anchors_total: usize,
    /// Anchors that are structurally consistent: granted by the TSA and
    /// imprinting the hash of a checkpoint present in the pack. The CMS
    /// signature itself is validated out of band (see `anchor_not_validated`).
    #[serde(default)]
    pub anchors_ok: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// True when no trusted keys were supplied and verification fell back to
    /// the keys embedded in the pack. A valid report then proves internal
    /// consistency only: a forged pack signed with a made-up key embedded in
    /// the same pack yields the exact same result. Callers must not present
    /// such a run as proof of authenticity.
    #[serde(default)]
    pub self_referential: bool,
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
/// the report says so explicitly (`self_referential` flag, `keys_not_anchored`
/// warning).
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

    // --- Anchors -------------------------------------------------------
    // A checkpoint signature proves who sealed, not when: the key holder
    // could backdate ts_ms. An RFC 3161 token makes the date enforceable.
    // The check here is structural — granted status, imprint equal to the
    // checkpoint hash — and says so; presenting it as cryptographic
    // validation of the token would be a lie in the one place lying is
    // fatal.
    let checkpoint_labels: BTreeMap<Hash, String> = ev
        .checkpoints
        .iter()
        .map(|sc| {
            let cp = &sc.checkpoint;
            (cp.hash(), format!("[{}..{}]", cp.from_seq, cp.to_seq))
        })
        .collect();

    let mut anchors_ok = 0usize;
    for anchor in &ev.anchors {
        let Some(label) = checkpoint_labels.get(&anchor.checkpoint_hash) else {
            findings.push(Finding::error(
                "anchor_orphan",
                format!(
                    "timestamp token for checkpoint {} which is absent from \
                     the pack: it anchors nothing",
                    anchor.checkpoint_hash
                ),
            ));
            continue;
        };

        let der = match hex::decode(&anchor.token_hex) {
            Ok(d) => d,
            Err(_) => {
                findings.push(Finding::error(
                    "anchor_bad_encoding",
                    format!("anchor of checkpoint {label}: token is not valid hex"),
                ));
                continue;
            }
        };

        match parse_timestamp_response(&der) {
            Err(crate::Error::TimestampRejected(status)) => {
                findings.push(Finding::error(
                    "anchor_rejected",
                    format!(
                        "anchor of checkpoint {label}: the TSA refused the \
                         request (status {status}); a rejection is not an anchor"
                    ),
                ));
            }
            Err(e) => {
                findings.push(Finding::error(
                    "anchor_unreadable",
                    format!("anchor of checkpoint {label}: {e}"),
                ));
            }
            Ok(info) => {
                if info.hashed_message != anchor.checkpoint_hash.as_bytes() {
                    findings.push(Finding::error(
                        "anchor_mismatch",
                        format!(
                            "anchor of checkpoint {label}: the token imprints \
                             different bytes than the checkpoint hash. It \
                             timestamps something else."
                        ),
                    ));
                } else {
                    anchors_ok += 1;
                }
            }
        }
    }

    if anchors_ok > 0 {
        findings.push(Finding::warning(
            "anchor_not_validated",
            format!(
                "{anchors_ok} timestamp token(s) are structurally consistent \
                 (granted, imprint matches the checkpoint). This tool does not \
                 validate the TSA's CMS signature: check the token against the \
                 TSA certificate, e.g. `openssl ts -verify`."
            ),
        ));
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
        anchors_total: ev.anchors.len(),
        anchors_ok,
        first_seq: records_by_seq.keys().next().copied(),
        last_seq: records_by_seq.keys().next_back().copied(),
        self_referential: trusted.is_empty(),
        findings,
    }
}

/// Expected hash for the first record of a chain.
pub fn genesis() -> Hash {
    GENESIS
}

#[cfg(test)]
mod tests {
    //! Anchor verification lives here rather than in `tests/tamper.rs`
    //! because the DER synthesizer is `#[cfg(test)]` — a helper able to forge
    //! TSA responses must never be reachable from shipped code.

    use super::*;
    use crate::record::{Effect, EffectStatus, Payload};
    use crate::rfc3161::testutil::granted_response;
    use crate::ChainWriter;
    use ed25519_dalek::SigningKey;

    fn sealed_pack() -> (Evidence, PublicKeyEntry) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let entry = PublicKeyEntry {
            key_id: "k1".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        };
        let mut chain = ChainWriter::new("c1");
        let records: Vec<Record> = (0..3)
            .map(|i| {
                chain.append(
                    i,
                    format!("r{i}"),
                    None,
                    "s",
                    Payload::Effect(Effect {
                        status: EffectStatus::Ok,
                        result_hash: None,
                        latency_ms: i as u64,
                    }),
                )
            })
            .collect();
        let cp = chain.seal(99, "k1").unwrap().sign(&key);
        (
            Evidence {
                format: FORMAT.to_string(),
                chain_id: "c1".into(),
                records,
                checkpoints: vec![cp],
                keys: vec![entry.clone()],
                anchors: Vec::new(),
            },
            entry,
        )
    }

    fn anchor_over(ev: &Evidence, imprint: &[u8]) -> Anchor {
        Anchor {
            checkpoint_hash: ev.checkpoints[0].checkpoint.hash(),
            token_hex: hex::encode(granted_response(imprint, b"20260728120000Z")),
            tsa: Some("demo-tsa".into()),
        }
    }

    #[test]
    fn consistent_anchor_is_counted_and_flagged_unvalidated() {
        let (mut ev, entry) = sealed_pack();
        let hash = ev.checkpoints[0].checkpoint.hash();
        ev.anchors.push(anchor_over(&ev, hash.as_bytes()));

        let r = verify(&ev, &[entry]);
        assert!(r.is_valid());
        assert_eq!((r.anchors_total, r.anchors_ok), (1, 1));
        // The degradation must stay visible: structural consistency is not
        // cryptographic validation of the token.
        assert!(r.warnings().any(|f| f.code == "anchor_not_validated"));
    }

    #[test]
    fn anchor_imprinting_other_bytes_is_an_error() {
        let (mut ev, entry) = sealed_pack();
        ev.anchors.push(anchor_over(&ev, &[0xEE; 32]));

        let r = verify(&ev, &[entry]);
        assert!(!r.is_valid(), "a token over foreign bytes anchors nothing");
        assert!(r.errors().any(|f| f.code == "anchor_mismatch"));
        assert_eq!(r.anchors_ok, 0);
    }

    #[test]
    fn anchor_without_its_checkpoint_is_an_error() {
        let (mut ev, entry) = sealed_pack();
        let mut a = anchor_over(&ev, &[0u8; 32]);
        a.checkpoint_hash = Hash([0x42; 32]);
        ev.anchors.push(a);

        let r = verify(&ev, &[entry]);
        assert!(!r.is_valid());
        assert!(r.errors().any(|f| f.code == "anchor_orphan"));
    }

    #[test]
    fn rejected_tsa_response_is_an_error() {
        let (mut ev, entry) = sealed_pack();
        let mut a = anchor_over(&ev, &[0u8; 32]);
        a.token_hex = hex::encode(crate::rfc3161::testutil::rejected_response());
        ev.anchors.push(a);

        let r = verify(&ev, &[entry]);
        assert!(!r.is_valid(), "a TSA rejection must not pass as an anchor");
        assert!(r.errors().any(|f| f.code == "anchor_rejected"));
    }

    #[test]
    fn unknown_fields_in_a_pack_are_refused() {
        // A field nobody defined is not ignorable noise in a proof format:
        // two parsers that disagree on what a pack contains is exactly the
        // ambiguity an attacker wants. deny_unknown_fields makes the refusal
        // uniform — at the top level, on a record, and inside a payload
        // (the internally-tagged case, where serde strips only `kind`).
        let (ev, _) = sealed_pack();

        let mut v = serde_json::to_value(&ev).unwrap();
        v["smuggled"] = serde_json::json!("x");
        assert!(serde_json::from_value::<Evidence>(v).is_err());

        let mut v = serde_json::to_value(&ev).unwrap();
        v["records"][0]["smuggled"] = serde_json::json!("x");
        assert!(serde_json::from_value::<Evidence>(v).is_err());

        let mut v = serde_json::to_value(&ev).unwrap();
        v["records"][0]["payload"]["smuggled"] = serde_json::json!("x");
        assert!(serde_json::from_value::<Evidence>(v).is_err());

        // The untouched pack still parses: the refusal is the fields', not
        // the format's.
        let v = serde_json::to_value(&ev).unwrap();
        assert!(serde_json::from_value::<Evidence>(v).is_ok());
    }

    #[test]
    fn pack_without_anchors_stays_valid_and_silent() {
        // The paired counter-check: adding the anchor pass must not degrade
        // packs that never claimed to be anchored.
        let (ev, entry) = sealed_pack();
        let r = verify(&ev, &[entry]);
        assert!(r.is_valid());
        assert_eq!((r.anchors_total, r.anchors_ok), (0, 0));
        assert!(r.findings.iter().all(|f| !f.code.starts_with("anchor")));
    }
}
