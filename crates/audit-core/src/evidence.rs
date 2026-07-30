use crate::checkpoint::{KeyRole, PublicKeyEntry, SignedCheckpoint};
use crate::deployment::SignedDeploymentBundle;
use crate::hash::{Hash, GENESIS};
use crate::merkle::merkle_root;
use crate::origin::SignedRecord;
use crate::record::Record;
use crate::rfc3161::{parse_timestamp_response, Anchor};
use ed25519_dalek::VerifyingKey;
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
    /// Records with their origin signatures. Packs written before origin
    /// authentication carry bare records and deserialize identically; the
    /// format string does not change for an additive field, the `anchors`
    /// precedent.
    pub records: Vec<SignedRecord>,
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
    /// The ops-signed deployment bundle whose origin keys were trusted when
    /// this pack was sealed. Optional and `default`, the `anchors` precedent:
    /// packs from before the deployment bundle stay readable. Embedding it
    /// makes the pack self-describing — the auditor verifies the whole origin
    /// chain of trust (ops key → bundle → origin keys → records) with nothing
    /// but the ops key obtained out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<SignedDeploymentBundle>,
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
    /// Records whose origin signature verified against a trusted origin key.
    #[serde(default)]
    pub records_origin_ok: usize,
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

/// Knobs the caller sets according to what the deployment claims.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOptions {
    /// The deployment mandates origin authentication: a record with no
    /// verifiable origin signature becomes an error instead of a warning.
    /// This is what defeats signature stripping — an attacker who removes
    /// `origin_sig` fields produces a pack that merely *lacks* proof, and
    /// only the caller knows whether lacking it is acceptable.
    pub require_origin: bool,
    /// The deployment mandates remote attestation: an enrolled identity key
    /// with no attestation becomes an error instead of a warning. The
    /// signature-stripping argument, one rung up — an attacker who removes
    /// attestations produces a bundle that merely *lacks* the boot/binary
    /// proof.
    pub require_attestation: bool,
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
    verify_with(ev, trusted, &VerifyOptions::default())
}

/// [`verify`], with explicit options.
pub fn verify_with(ev: &Evidence, trusted: &[PublicKeyEntry], opts: &VerifyOptions) -> Report {
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

    // One map per role. A key is only ever resolved within its role: a
    // sealing key that "validates" a record signature, or an origin key that
    // "validates" a checkpoint, would collapse writer and certifier into one
    // authority — the exact confusion the two roles exist to prevent.
    let mut keys = BTreeMap::new();
    let mut origin_keys = BTreeMap::new();
    for entry in key_source {
        match entry.to_verifying_key() {
            Ok(vk) => {
                match entry.role {
                    KeyRole::Seal => keys.insert(entry.key_id.clone(), vk),
                    KeyRole::Origin => origin_keys.insert(entry.key_id.clone(), vk),
                };
            }
            Err(e) => findings.push(Finding::error(
                "invalid_key",
                format!("key \"{}\" unusable: {e}", entry.key_id),
            )),
        }
    }

    // --- Deployment bundle --------------------------------------------
    // The origin chain of trust: an ops-signed bundle names the origin keys.
    // Verified here so its keys join the origin set before the origin pass —
    // one artifact and one root (the ops key) instead of hand-listed origin
    // keys. The ops key is resolved from the trusted set by the key id the
    // bundle names; it is not itself an origin or sealing key, so no role
    // gate applies to it (as with the policy/identity bundles the gateway
    // already trusts by key id).
    if let Some(sdb) = &ev.deployment {
        resolve_deployment_bundle(sdb, key_source, &mut origin_keys, opts, &mut findings);
    }

    // --- Session certificates (v2) ------------------------------------
    // At this point `origin_keys` holds the enrolled *identity* keys. Each
    // session certificate is signed by one of them and authorizes an
    // ephemeral session key; validating the certificate adds that session key
    // to the set records resolve against. So a v2 record verifies against a
    // key the identity key vouched for, while a v0/v1 record still verifies
    // against a bundle key directly — the set is the union, which keeps older
    // packs working.
    resolve_session_certs(&ev.records, &ev.chain_id, &mut origin_keys, opts, &mut findings);

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

        if records_by_seq.insert(rec.seq, &rec.record).is_some() {
            findings.push(Finding::error(
                "duplicate_sequence",
                format!("seq={} appears more than once", rec.seq),
            ));
        }
        hash_by_seq.insert(rec.seq, h);
        prev = Some((rec.seq, h));
    }

    // --- Origin ---------------------------------------------------------
    // The chain above proves the records are consistent with each other; it
    // says nothing about who wrote them, because every input to a record
    // hash is public. The origin signature is the only element of the pack
    // an attacker with disk access cannot regenerate.
    //
    // Severity is calibrated to what each state proves. An *invalid*
    // signature under a trusted key, or a key used outside its role, is
    // positive evidence of tampering: always an error. An *absent or
    // unresolvable* signature is an absence of proof — indistinguishable
    // from a log written before origin authentication existed — so it is a
    // warning, upgraded to an error when the caller states the deployment
    // mandates origin (`require_origin`). Anything softer would let an
    // attacker strip signatures back into silence.
    let mut records_origin_ok = 0usize;
    let mut origin_unverified = 0usize;
    for sr in &ev.records {
        match (&sr.origin_sig, &sr.origin_key_id) {
            (None, None) => origin_unverified += 1,
            (Some(_), Some(kid)) => match origin_keys.get(kid) {
                Some(vk) => match sr.verify_origin(&ev.chain_id, vk) {
                    Ok(()) => records_origin_ok += 1,
                    Err(e) => findings.push(Finding::error("origin_invalid", e.to_string())),
                },
                None if keys.contains_key(kid) => findings.push(Finding::error(
                    "key_role_mismatch",
                    format!(
                        "record seq={} claims origin key \"{kid}\", which is a \
                         sealing key. A sealing key authenticating records \
                         would collapse writer and certifier into one \
                         authority.",
                        sr.seq
                    ),
                )),
                None => origin_unverified += 1,
            },
            _ => findings.push(Finding::error(
                "origin_invalid",
                format!(
                    "record seq={}: origin signature and key id must come \
                     together; half of the pair can only be produced by \
                     tampering",
                    sr.seq
                ),
            )),
        }
    }
    if origin_unverified > 0 {
        let msg = format!(
            "{origin_unverified} record(s) have no verifiable origin \
             signature: nothing proves the gateway wrote them. Expected for \
             logs written before origin authentication; otherwise supply the \
             origin keys (--trusted-keys, role \"origin\")."
        );
        findings.push(if opts.require_origin {
            Finding::error("origin_unverified", msg)
        } else {
            Finding::warning("origin_unverified", msg)
        });
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
            None if origin_keys.contains_key(&cp.key_id) => {
                findings.push(Finding::error(
                    "key_role_mismatch",
                    format!(
                        "checkpoint {label} signed with key \"{}\", which is an \
                         origin key. The writer certifying its own log is the \
                         cohabitation sealing exists to prevent.",
                        cp.key_id
                    ),
                ));
                cp_ok = false;
            }
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
        records_origin_ok,
        first_seq: records_by_seq.keys().next().copied(),
        last_seq: records_by_seq.keys().next_back().copied(),
        self_referential: trusted.is_empty(),
        findings,
    }
}

/// Validates each session certificate and folds the session keys it
/// authorizes into the origin set.
///
/// The identity key that certifies a session key is resolved among the keys
/// already in the origin set (the enrolled identity keys); the session key it
/// authorizes is then keyed by [`key_id_for`], the id its records name. A
/// certificate whose identity key is unknown is unverified (a warning, an
/// error under `require_origin`), the self-referential logic; one whose
/// signature is *wrong* is invalid (always an error) — only tampering
/// produces that.
///
/// The validity window (`not_before`/`not_after`) is carried but not enforced
/// here: enforcing it needs trusted time, and the pack's RFC 3161 anchors are
/// validated out of band (see `anchor_not_validated`). Checking the window
/// against the verifier's own clock would fail a pack read years later, so it
/// is left informational until offline anchored-time validation exists.
fn resolve_session_certs(
    records: &[SignedRecord],
    chain_id: &str,
    origin_keys: &mut BTreeMap<String, VerifyingKey>,
    opts: &VerifyOptions,
    findings: &mut Vec<Finding>,
) {
    // Certificates name identity keys, never each other: resolve against the
    // identity set as it stands before any session key is added.
    let identity_keys = origin_keys.clone();
    let mut unverified = 0usize;
    for sr in records {
        let crate::record::Payload::SessionCert(cert) = &sr.record.payload else {
            continue;
        };
        match identity_keys.get(&cert.identity_key_id) {
            None => unverified += 1,
            Some(identity_vk) => {
                match crate::origin::verify_session_cert(chain_id, cert, identity_vk) {
                    Ok(session_vk) => {
                        origin_keys.insert(crate::key_id_for(&session_vk), session_vk);
                    }
                    Err(e) => findings.push(Finding::error(
                        "session_cert_invalid",
                        format!("session certificate at seq={}: {e}", sr.record.seq),
                    )),
                }
            }
        }
    }
    if unverified > 0 {
        let msg = format!(
            "{unverified} session certificate(s) are signed by an identity key \
             absent from the trusted set: the session keys they authorize prove \
             nothing. Supply the deployment bundle enrolling that identity key."
        );
        findings.push(if opts.require_origin {
            Finding::error("session_cert_unverified", msg)
        } else {
            Finding::warning("session_cert_unverified", msg)
        });
    }
}

/// Verifies an embedded deployment bundle under the trusted ops key and folds
/// its origin keys into the origin set.
///
/// The bundle names the ops key that signed it; we resolve that key id from
/// the trusted set. A bundle we cannot anchor to a supplied key is a warning,
/// not an error — indistinguishable from the self-referential case the pack
/// already warns about (`keys_not_anchored`); a bundle whose signature is
/// *wrong*, or whose keys are role-confused, is an error, because only
/// tampering produces those.
fn resolve_deployment_bundle(
    sdb: &SignedDeploymentBundle,
    key_source: &[PublicKeyEntry],
    origin_keys: &mut BTreeMap<String, VerifyingKey>,
    opts: &VerifyOptions,
    findings: &mut Vec<Finding>,
) {
    let ops_vk: Option<VerifyingKey> = key_source
        .iter()
        .find(|k| k.key_id == sdb.key_id)
        .and_then(|k| k.to_verifying_key().ok());

    let Some(ops_vk) = ops_vk else {
        findings.push(Finding::warning(
            "deployment_bundle_unverified",
            format!(
                "the pack embeds a deployment bundle signed by ops key \"{}\", \
                 absent from the trusted key set: its origin keys prove nothing \
                 on their own. Supply the ops key (--trusted-keys).",
                sdb.key_id
            ),
        ));
        return;
    };

    match sdb.verify(&ops_vk) {
        Err(e) => findings.push(Finding::error(
            "deployment_bundle_invalid",
            format!("deployment bundle \"{}\": {e}", sdb.bundle.version),
        )),
        Ok(bundle) => match bundle.active_origin_keys() {
            Err(e) => findings.push(Finding::error(
                "deployment_bundle_invalid",
                format!("deployment bundle \"{}\": {e}", bundle.version),
            )),
            Ok(active) => {
                // The bundle's keys join those listed directly. A key id that
                // appears in both must not disagree: same id, same material,
                // or the pack is self-contradictory about who a gateway is.
                for (kid, vk) in active {
                    if let Some(existing) = origin_keys.get(&kid) {
                        if existing.to_bytes() != vk.to_bytes() {
                            findings.push(Finding::error(
                                "deployment_bundle_invalid",
                                format!(
                                    "deployment bundle \"{}\": origin key \"{kid}\" \
                                     disagrees with a key of the same id elsewhere \
                                     in the pack",
                                    bundle.version
                                ),
                            ));
                        }
                    } else {
                        origin_keys.insert(kid, vk);
                    }
                }
                resolve_attestations(bundle, opts, findings);
            }
        },
    }
}

/// Checks each identity key's remote attestation (v3), offline and
/// structurally, and reports what each enrolled key can prove about the
/// software that ran under it.
///
/// The out-of-band caveat is stated whenever anything attests, the exact
/// shape of `anchor_not_validated`: this tool proves the identity key is
/// bound to a TPM reporting the enrolled measurements, not that the TPM is
/// genuine silicon — that is the EK-certificate check, which needs a vendor
/// PKI an air-gapped verifier does not carry.
fn resolve_attestations(
    bundle: &crate::deployment::DeploymentBundle,
    opts: &VerifyOptions,
    findings: &mut Vec<Finding>,
) {
    let mut attested = 0usize;
    let mut unattested = 0usize;
    for entry in &bundle.origin_keys {
        match bundle.attestations.iter().find(|a| a.key_id == entry.key_id) {
            None => unattested += 1,
            Some(att) => match crate::attestation::verify_attestation(entry, att) {
                Ok(()) => attested += 1,
                Err(e) => findings.push(Finding::error(
                    "attestation_invalid",
                    format!(
                        "identity key \"{}\" in bundle \"{}\": {e}",
                        entry.key_id, bundle.version
                    ),
                )),
            },
        }
    }

    if attested > 0 {
        findings.push(Finding::warning(
            "attestation_not_rooted",
            format!(
                "{attested} identity key(s) carry a structurally consistent \
                 attestation (the quote binds the key and matches the enrolled \
                 measurements). This tool does not validate the EK certificate \
                 against a TPM vendor root, so it does not prove the TPM is \
                 genuine silicon: check the EK chain out of band."
            ),
        ));
    }
    if unattested > 0 {
        let msg = format!(
            "{unattested} enrolled identity key(s) carry no attestation: nothing \
             proves which software ran under them. Expected before attestation \
             was enrolled; otherwise the bundle is missing it."
        );
        findings.push(if opts.require_attestation {
            Finding::error("identity_not_attested", msg)
        } else {
            Finding::warning("identity_not_attested", msg)
        });
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
            role: KeyRole::Seal,
        };
        let mut chain = ChainWriter::new("c1");
        let records: Vec<SignedRecord> = (0..3)
            .map(|i| {
                SignedRecord::unsigned(chain.append(
                    i,
                    format!("r{i}"),
                    None,
                    "s",
                    Payload::Effect(Effect {
                        status: EffectStatus::Ok,
                        result_hash: None,
                        latency_ms: i as u64,
                    }),
                ))
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
                deployment: None,
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
    // --- v3: remote attestation, end to end through verify -------------

    use crate::attestation::{testutil as att_testutil, PcrExpectation};
    use crate::deployment::{DeploymentBundle, FORMAT as DFMT};

    fn ops_and_bundle(
        origin: &SigningKey,
        with_attestation: bool,
    ) -> (SignedDeploymentBundle, PublicKeyEntry, SigningKey) {
        let ops = SigningKey::from_bytes(&[50u8; 32]);
        let origin_entry = PublicKeyEntry {
            key_id: "id-gw".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(origin.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        };
        let attestations = if with_attestation {
            let ak = SigningKey::from_bytes(&[60u8; 32]);
            let pcrs = vec![PcrExpectation {
                index: 7,
                digest: hex::encode(crate::hash::sha256(b"gateway-binary").as_bytes()),
            }];
            vec![att_testutil::attestation(
                "id-gw",
                &origin.verifying_key(),
                &ak,
                pcrs,
            )]
        } else {
            Vec::new()
        };
        let bundle = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@v3".into(),
            origin_keys: vec![origin_entry.clone()],
            attestations,
        }
        .sign("ops-1", &ops);
        let ops_entry = PublicKeyEntry {
            key_id: "ops-1".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(ops.verifying_key().to_bytes()),
            role: KeyRole::Seal,
        };
        (bundle, ops_entry, ops)
    }

    fn pack_with_bundle(bundle: SignedDeploymentBundle, seal: &PublicKeyEntry) -> Evidence {
        Evidence {
            format: FORMAT.to_string(),
            chain_id: "c1".into(),
            records: Vec::new(),
            checkpoints: Vec::new(),
            keys: vec![seal.clone()],
            anchors: Vec::new(),
            deployment: Some(bundle),
        }
    }

    #[test]
    fn a_valid_attestation_verifies_and_flags_the_out_of_band_root() {
        let origin = SigningKey::from_bytes(&[40u8; 32]);
        let (bundle, ops_entry, _ops) = ops_and_bundle(&origin, true);
        let ev = pack_with_bundle(bundle, &ops_entry);

        let r = verify_with(
            &ev,
            &[ops_entry],
            &VerifyOptions { require_origin: false, require_attestation: true },
        );
        assert!(
            !r.errors().any(|f| f.code.starts_with("attestation")),
            "a valid attestation must raise no error: {:?}", r.findings
        );
        // The honest caveat is always surfaced.
        assert!(r.warnings().any(|f| f.code == "attestation_not_rooted"));
    }

    #[test]
    fn a_tampered_attestation_is_an_error() {
        let origin = SigningKey::from_bytes(&[40u8; 32]);
        let (mut bundle, ops_entry, ops) = ops_and_bundle(&origin, true);
        // Relax the expected PCR to a malicious binary's measurement; the
        // quote still reports the original, so they disagree. Re-sign the
        // bundle so only the attestation, not the ops signature, is at fault.
        bundle.bundle.attestations[0].expected_pcrs[0].digest =
            hex::encode(crate::hash::sha256(b"malicious").as_bytes());
        let resigned = DeploymentBundle {
            ..bundle.bundle.clone()
        }
        .sign("ops-1", &ops);

        let ev = pack_with_bundle(resigned, &ops_entry);
        let r = verify_with(&ev, &[ops_entry], &VerifyOptions::default());
        assert!(!r.is_valid());
        assert!(r.errors().any(|f| f.code == "attestation_invalid"));
    }

    #[test]
    fn an_unattested_identity_key_is_a_warning_until_required() {
        let origin = SigningKey::from_bytes(&[40u8; 32]);
        let (bundle, ops_entry, _ops) = ops_and_bundle(&origin, false);
        let ev = pack_with_bundle(bundle, &ops_entry);

        let permissive = verify_with(&ev, std::slice::from_ref(&ops_entry), &VerifyOptions::default());
        assert!(permissive.warnings().any(|f| f.code == "identity_not_attested"));

        let strict = verify_with(
            &ev,
            &[ops_entry],
            &VerifyOptions { require_origin: false, require_attestation: true },
        );
        assert!(!strict.is_valid());
        assert!(strict.errors().any(|f| f.code == "identity_not_attested"));
    }
}
