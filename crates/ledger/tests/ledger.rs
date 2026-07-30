//! The ledger's job is to make one attack visible: rewriting the log on the
//! gateway host after it was sealed. Every test here either performs that
//! attack (or a cousin: truncation, store edition, key substitution) and
//! asserts detection, or exercises the legitimate path and asserts it still
//! works — a control that only ever says "blocked" proves nothing.

use audit_core::evidence;
use audit_core::record::{Effect, EffectStatus, Payload};
use audit_core::SignedRecord;
use ledger::{
    export, seal_pass, timestamp_request, validate_response, FileSealer, OriginPolicy, Sealer,
    Store,
};
use std::path::{Path, PathBuf};
use wal::Wal;

fn payload(n: u64) -> Payload {
    Payload::Effect(Effect {
        status: EffectStatus::Ok,
        result_hash: None,
        latency_ms: n,
    })
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ledger-test-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Appends `n` records to the chain's WAL, resuming where it left off.
fn grow_wal(dir: &Path, n: u64) {
    let (mut wal, mut chain) = Wal::open(dir, "c1").unwrap();
    let start = chain.next_seq();
    for i in start..start + n {
        let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
        wal.append(&SignedRecord::unsigned(r)).unwrap();
    }
}

/// The pre-origin-auth behaviour, for tests about sealing mechanics.
fn no_origin() -> OriginPolicy {
    OriginPolicy::permissive()
}

fn sealer() -> FileSealer {
    FileSealer::from_seed([7u8; 32], "seal-k1")
}

/// Test-only DER builder for synthetic TSA responses. Duplicated from
/// audit-core's `#[cfg(test)]` helper on purpose: a forgery helper must not
/// be exported from the crate that verifies, and this is throwaway test
/// scaffolding, not proof logic.
mod tsa {
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const OID_TST_INFO: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
    ];

    pub fn granted_response(imprint: &[u8]) -> Vec<u8> {
        let message_imprint = tlv(
            0x30,
            &[tlv(0x30, &tlv(0x06, OID_SHA256)), tlv(0x04, imprint)].concat(),
        );
        let tst_info = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x06, &[0x2A, 0x03, 0x04]),
                message_imprint,
                tlv(0x02, &[0x2A]),
                tlv(0x18, b"20260728120000Z"),
            ]
            .concat(),
        );
        let encap = tlv(
            0x30,
            &[tlv(0x06, OID_TST_INFO), tlv(0xA0, &tlv(0x04, &tst_info))].concat(),
        );
        let signed_data = tlv(
            0x30,
            &[
                tlv(0x02, &[3]),
                tlv(0x31, &[]),
                encap,
                tlv(0x31, &[]),
            ]
            .concat(),
        );
        let content_info = tlv(
            0x30,
            &[tlv(0x06, OID_SIGNED_DATA), tlv(0xA0, &signed_data)].concat(),
        );
        tlv(
            0x30,
            &[tlv(0x30, &tlv(0x02, &[0])), content_info].concat(),
        )
    }
}

#[test]
fn seal_export_verify_roundtrip() {
    let wal_dir = tmpdir("roundtrip-wal");
    let store_dir = tmpdir("roundtrip-store");
    grow_wal(&wal_dir, 5);

    let mut store = Store::open(&store_dir, "c1").unwrap();
    let s = sealer();
    let records = wal::read(&wal_dir, "c1").unwrap();

    let sc = seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (0, 4));

    // Nothing new: no empty seal gets manufactured.
    assert!(seal_pass(&records, &mut store, &s, &no_origin(), 1001, 1).unwrap().is_none());

    // More activity, second seal: the checkpoints must chain.
    grow_wal(&wal_dir, 3);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc2 = seal_pass(&records, &mut store, &s, &no_origin(), 1002, 1).unwrap().unwrap();
    assert_eq!((sc2.checkpoint.from_seq, sc2.checkpoint.to_seq), (5, 7));
    assert_eq!(
        sc2.checkpoint.prev_checkpoint_hash,
        Some(sc.checkpoint.hash())
    );

    // The whole thing survives the auditor's tooling, with real trusted keys.
    let ev = export(records, &store, &[], None);
    let report = evidence::verify(&ev, &[s.public_key()]);
    assert!(report.is_valid(), "findings: {:?}", report.findings);
    assert_eq!(report.records_sealed, 8);
    assert_eq!(report.checkpoints_valid, 2);

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn restart_resumes_sealing_without_gap_or_reseal() {
    let wal_dir = tmpdir("restart-wal");
    let store_dir = tmpdir("restart-store");
    grow_wal(&wal_dir, 4);

    let s = sealer();
    {
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    }

    // Restart: the store reloads and re-verifies everything.
    let mut store = Store::open(&store_dir, "c1").unwrap();
    assert_eq!(store.checkpoints().len(), 1);
    let records = wal::read(&wal_dir, "c1").unwrap();
    assert!(
        seal_pass(&records, &mut store, &s, &no_origin(), 2000, 1).unwrap().is_none(),
        "already-sealed records must not be sealed again"
    );

    grow_wal(&wal_dir, 2);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, &no_origin(), 3000, 1).unwrap().unwrap();
    assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (4, 5));

    let ev = export(records, &store, &[], None);
    assert!(evidence::verify(&ev, &[s.public_key()]).is_valid());

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn rewritten_wal_is_refused_before_any_new_seal() {
    // The attack the ledger exists for: a compromised gateway host rewrites
    // the WAL and recomputes every hash. The log is internally consistent —
    // wal::read is happy — but it is no longer the history the checkpoints
    // certify.
    let wal_dir = tmpdir("rewrite-wal");
    let store_dir = tmpdir("rewrite-store");
    grow_wal(&wal_dir, 5);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();

    // Rewrite history: same length, different content, valid chain.
    std::fs::remove_file(wal_dir.join("c1.jsonl")).unwrap();
    {
        let (mut wal, mut chain) = Wal::open(&wal_dir, "c1").unwrap();
        for i in 0..5u64 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i + 100));
            wal.append(&SignedRecord::unsigned(r)).unwrap();
        }
    }

    let records = wal::read(&wal_dir, "c1").unwrap();
    let err = seal_pass(&records, &mut store, &s, &no_origin(), 2000, 1).unwrap_err();
    assert!(
        matches!(err, ledger::Error::DivergedLog { seq: 4 }),
        "got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn wal_shorter_than_sealed_history_is_refused() {
    let wal_dir = tmpdir("truncate-wal");
    let store_dir = tmpdir("truncate-store");
    grow_wal(&wal_dir, 5);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();

    // Sealed records disappear.
    std::fs::remove_file(wal_dir.join("c1.jsonl")).unwrap();
    grow_wal(&wal_dir, 3);

    let records = wal::read(&wal_dir, "c1").unwrap();
    let err = seal_pass(&records, &mut store, &s, &no_origin(), 2000, 1).unwrap_err();
    assert!(
        matches!(err, ledger::Error::TruncatedLog { sealed_to: 4, .. }),
        "got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn edited_store_refuses_to_open() {
    let wal_dir = tmpdir("storetamper-wal");
    let store_dir = tmpdir("storetamper-store");
    grow_wal(&wal_dir, 3);

    let s = sealer();
    {
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    }

    let path = store_dir.join("c1.checkpoints.jsonl");
    let line = std::fs::read_to_string(&path).unwrap();
    // Shrink the sealed interval by one record: the signature no longer
    // covers what the line claims.
    let edited = line.replace("\"to_seq\":2", "\"to_seq\":1");
    assert_ne!(line, edited, "the edit must have happened");
    std::fs::write(&path, edited).unwrap();

    let err = Store::open(&store_dir, "c1").unwrap_err();
    assert!(
        matches!(err, ledger::Error::Core(audit_core::Error::BadSignature { .. })),
        "got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn removed_checkpoint_breaks_the_store_chain() {
    let wal_dir = tmpdir("storedrop-wal");
    let store_dir = tmpdir("storedrop-store");
    grow_wal(&wal_dir, 2);

    let s = sealer();
    {
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
        grow_wal(&wal_dir, 2);
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &no_origin(), 2000, 1).unwrap().unwrap();
    }

    // Drop the first seal: its interval would silently stop being proven.
    let path = store_dir.join("c1.checkpoints.jsonl");
    let content = std::fs::read_to_string(&path).unwrap();
    let last_line = content.lines().last().unwrap();
    std::fs::write(&path, format!("{last_line}\n")).unwrap();

    let err = Store::open(&store_dir, "c1").unwrap_err();
    assert!(matches!(err, ledger::Error::StoreBroken(_)), "got {err:?}");

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn torn_final_store_line_is_survivable() {
    // Crash mid-append: the seal was never acknowledged, so trimming it and
    // resealing the same records is the correct recovery, not data loss.
    let wal_dir = tmpdir("torn-wal");
    let store_dir = tmpdir("torn-store");
    grow_wal(&wal_dir, 3);

    let s = sealer();
    {
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    }

    let path = store_dir.join("c1.checkpoints.jsonl");
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(b"{\"chain_id\":\"c1\",\"from_se").unwrap();
    drop(f);

    let mut store = Store::open(&store_dir, "c1").unwrap();
    assert_eq!(store.checkpoints().len(), 1, "the torn line is not a seal");

    // And sealing can resume on the trimmed file.
    grow_wal(&wal_dir, 1);
    let records = wal::read(&wal_dir, "c1").unwrap();
    assert!(seal_pass(&records, &mut store, &s, &no_origin(), 2000, 1).unwrap().is_some());

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn min_new_batches_sealing() {
    let wal_dir = tmpdir("batch-wal");
    let store_dir = tmpdir("batch-store");
    grow_wal(&wal_dir, 2);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    assert!(
        seal_pass(&records, &mut store, &s, &no_origin(), 1000, 5).unwrap().is_none(),
        "below the floor, no checkpoint"
    );

    grow_wal(&wal_dir, 3);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, &no_origin(), 2000, 5).unwrap().unwrap();
    assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (0, 4));

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn a_key_id_cannot_be_rebound_to_another_key() {
    let wal_dir = tmpdir("keyconflict-wal");
    let store_dir = tmpdir("keyconflict-store");
    grow_wal(&wal_dir, 2);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();

    // Same id, different key: accepting it would let the new key claim the
    // old seals at verification time.
    grow_wal(&wal_dir, 2);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let impostor = FileSealer::from_seed([9u8; 32], "seal-k1");
    let err = seal_pass(&records, &mut store, &impostor, &no_origin(), 2000, 1).unwrap_err();
    assert!(matches!(err, ledger::Error::KeyConflict(_)), "got {err:?}");

    // The paired check: the legitimate key still seals.
    assert!(seal_pass(&records, &mut store, &s, &no_origin(), 3000, 1).unwrap().is_some());

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn anchor_roundtrip_reaches_the_evidence_pack() {
    let wal_dir = tmpdir("anchor-wal");
    let store_dir = tmpdir("anchor-store");
    grow_wal(&wal_dir, 3);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    let cp_hash = sc.checkpoint.hash();

    // The request imprints the checkpoint hash.
    let req = timestamp_request(&cp_hash);
    assert!(
        req.windows(32).any(|w| w == cp_hash.as_bytes()),
        "the request must carry the checkpoint hash as its imprint"
    );

    // Simulated TSA grants; the response validates and attaches.
    let resp = tsa::granted_response(cp_hash.as_bytes());
    let info = validate_response(&store, &cp_hash, &resp).unwrap();
    assert_eq!(info.gen_time.as_deref(), Some("20260728120000Z"));
    store
        .append_anchor(audit_core::rfc3161::Anchor {
            checkpoint_hash: cp_hash,
            token_hex: hex::encode(&resp),
            tsa: Some("demo-tsa".into()),
        })
        .unwrap();

    // Survives a restart and lands in the pack.
    let store = Store::open(&store_dir, "c1").unwrap();
    let ev = export(records, &store, &[], None);
    let report = evidence::verify(&ev, &[s.public_key()]);
    assert!(report.is_valid(), "findings: {:?}", report.findings);
    assert_eq!((report.anchors_total, report.anchors_ok), (1, 1));

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn foreign_or_orphan_tokens_do_not_attach() {
    let wal_dir = tmpdir("anchorbad-wal");
    let store_dir = tmpdir("anchorbad-store");
    grow_wal(&wal_dir, 2);

    let s = sealer();
    let mut store = Store::open(&store_dir, "c1").unwrap();
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, &no_origin(), 1000, 1).unwrap().unwrap();
    let cp_hash = sc.checkpoint.hash();

    // Token over other bytes: refused.
    let foreign = tsa::granted_response(&[0xEE; 32]);
    let err = validate_response(&store, &cp_hash, &foreign).unwrap_err();
    assert!(matches!(err, ledger::Error::AnchorMismatch(_)), "got {err:?}");

    // Token for a checkpoint this store does not hold: refused.
    let ghost = audit_core::Hash([0x42; 32]);
    let resp = tsa::granted_response(ghost.as_bytes());
    let err = validate_response(&store, &ghost, &resp).unwrap_err();
    assert!(
        matches!(err, ledger::Error::UnknownCheckpoint(_)),
        "got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

// =====================================================================
// Origin authentication at the seal
// =====================================================================
//
// Exit-0 gap #2, the sealer-side half: every input to a record's hash is
// public, so an attacker with disk write could fabricate a consistent
// extension after the sealed head and the honest key would seal it. With an
// origin policy, the sealer refuses to lend its authority to records the
// gateway did not sign.

mod origin {
    use super::*;
    use audit_core::checkpoint::{KeyRole, PublicKeyEntry};
    use audit_core::origin_signing_bytes;
    use audit_core::ChainWriter;
    use ed25519_dalek::{Signer, SigningKey};

    fn gw_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn gw_entry() -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: "gw-origin".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(gw_key().verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }

    fn policy(require: bool) -> OriginPolicy {
        OriginPolicy::new(&[gw_entry()], require).unwrap()
    }

    /// Appends `n` gateway-signed records, resuming where the chain left off.
    fn grow_signed(dir: &Path, n: u64) {
        let (mut wal, mut chain) = Wal::open(dir, "c1").unwrap();
        let start = chain.next_seq();
        for i in start..start + n {
            let rec = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
            let msg = origin_signing_bytes("c1", &rec.hash());
            let sr = SignedRecord::signed(rec, "gw-origin", gw_key().sign(&msg).to_bytes());
            wal.append(&sr).unwrap();
        }
    }

    /// The attack: a well-formed unsigned record appended after the head.
    fn append_forged(dir: &Path) {
        let records = wal::read(dir, "c1").unwrap();
        let last = records.last().unwrap();
        let mut chain = ChainWriter::resume("c1", last.seq + 1, last.record.hash(), None);
        let forged =
            SignedRecord::unsigned(chain.append(9_999, "rX", None, "s", payload(9_999)));
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("c1.jsonl"))
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&forged).unwrap()).unwrap();
    }

    #[test]
    fn a_signed_chain_seals_and_verifies_end_to_end() {
        let wal_dir = tmpdir("og-roundtrip-wal");
        let store_dir = tmpdir("og-roundtrip-store");
        grow_signed(&wal_dir, 4);

        let s = sealer();
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        let sc = seal_pass(&records, &mut store, &s, &policy(true), 1000, 1)
            .unwrap()
            .unwrap();
        assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (0, 3));

        // And the pack proves origin offline, under the strict options.
        let ev = export(records, &store, &[gw_entry()], None);
        let report = evidence::verify_with(
            &ev,
            &[s.public_key(), gw_entry()],
            &evidence::VerifyOptions { require_origin: true, require_attestation: false },
        );
        assert!(report.is_valid(), "findings: {:?}", report.findings);
        assert_eq!(report.records_origin_ok, 4);

        let _ = std::fs::remove_dir_all(&wal_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn a_forged_tail_is_never_sealed_and_raises_the_alarm() {
        // The headline scenario of the gap: sealed head, then a fabricated
        // record. The pass must seal the authentic records — refusing them
        // too would turn the forgery into an anti-durability attack — and
        // error on the forgery, loudly.
        let wal_dir = tmpdir("og-forged-wal");
        let store_dir = tmpdir("og-forged-store");
        grow_signed(&wal_dir, 2);

        let s = sealer();
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, &policy(true), 1000, 1)
            .unwrap()
            .unwrap();

        // More honest activity, then the attacker appends.
        grow_signed(&wal_dir, 2);
        append_forged(&wal_dir);

        let records = wal::read(&wal_dir, "c1").unwrap();
        let err = seal_pass(&records, &mut store, &s, &policy(true), 2000, 1).unwrap_err();
        match err {
            ledger::Error::UnauthenticatedRecord {
                seq,
                prefix_sealed_to,
                ..
            } => {
                assert_eq!(seq, 4, "the forgery sits at seq 4");
                assert_eq!(
                    prefix_sealed_to,
                    Some(3),
                    "the authentic records before it must be sealed"
                );
            }
            other => panic!("expected UnauthenticatedRecord, got {other:?}"),
        }
        assert_eq!(
            store.last().unwrap().checkpoint.to_seq,
            3,
            "the store must stop at the last authentic record"
        );

        // The alarm does not self-heal: the next pass raises it again.
        let err = seal_pass(&records, &mut store, &s, &policy(true), 3000, 1).unwrap_err();
        assert!(matches!(
            err,
            ledger::Error::UnauthenticatedRecord { seq: 4, prefix_sealed_to: None, .. }
        ));

        let _ = std::fs::remove_dir_all(&wal_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn an_invalid_signature_under_a_trusted_key_refuses_even_in_rollout_mode() {
        // require=false tolerates absence, never forgery: a bad signature
        // under a key we trust is positive evidence of tampering.
        let wal_dir = tmpdir("og-badsig-wal");
        let store_dir = tmpdir("og-badsig-store");
        grow_signed(&wal_dir, 2);

        let path = wal_dir.join("c1.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        // Corrupt the second record's signature in place.
        let re_target = lines[1].clone();
        let sig_pos = re_target.find("origin_sig").unwrap();
        let mut edited = re_target.clone();
        let byte = sig_pos + "origin_sig\":\"".len() + 1;
        let replacement = if &re_target[byte..byte + 1] == "0" { "1" } else { "0" };
        edited.replace_range(byte..byte + 1, replacement);
        lines[1] = edited;
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let s = sealer();
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        let err = seal_pass(&records, &mut store, &s, &policy(false), 1000, 1).unwrap_err();
        assert!(
            matches!(err, ledger::Error::UnauthenticatedRecord { seq: 1, .. }),
            "got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&wal_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn rollout_mode_seals_unsigned_records() {
        // The migration window: origin keys configured, --require-origin
        // not yet flipped, pre-upgrade gateways still writing unsigned.
        let wal_dir = tmpdir("og-rollout-wal");
        let store_dir = tmpdir("og-rollout-store");
        grow_wal(&wal_dir, 3);

        let s = sealer();
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        assert!(seal_pass(&records, &mut store, &s, &policy(false), 1000, 1)
            .unwrap()
            .is_some());

        // Flip the requirement: the same unsigned records are now refused.
        grow_wal(&wal_dir, 1);
        let records = wal::read(&wal_dir, "c1").unwrap();
        let err = seal_pass(&records, &mut store, &s, &policy(true), 2000, 1).unwrap_err();
        assert!(matches!(
            err,
            ledger::Error::UnauthenticatedRecord { seq: 3, .. }
        ));

        let _ = std::fs::remove_dir_all(&wal_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn origin_trust_resolves_from_a_signed_deployment_bundle() {
        // v1: the ledger takes an ops-signed bundle instead of a flat file.
        // A gateway enrolled in the bundle seals; one revoked (removed and
        // the bundle republished) no longer does.
        use audit_core::deployment::{DeploymentBundle, FORMAT as DFMT};
        use ed25519_dalek::SigningKey;

        let wal_dir = tmpdir("og-bundle-wal");
        let store_dir = tmpdir("og-bundle-store");
        grow_signed(&wal_dir, 3);

        let ops = SigningKey::from_bytes(&[44u8; 32]);
        let enrolled = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@v1".into(),
            origin_keys: vec![gw_entry()],
            attestations: Vec::new(),
        }
        .sign("ops-1", &ops);

        let s = sealer();
        let mut store = Store::open(&store_dir, "c1").unwrap();
        let records = wal::read(&wal_dir, "c1").unwrap();
        let policy =
            OriginPolicy::from_bundle(&enrolled, &ops.verifying_key(), true).unwrap();
        seal_pass(&records, &mut store, &s, &policy, 1_000, 1)
            .unwrap()
            .expect("an enrolled gateway seals");
        // The bundle is retained for the pack.
        assert!(policy.bundle().is_some());

        // Republish a bundle that enrolls a DIFFERENT gateway: gw-origin is
        // revoked. Under require-origin its records no longer seal. (A key
        // simply absent under rollout tolerance would still seal — revocation
        // bites precisely when origin is required.)
        let other = SigningKey::from_bytes(&[77u8; 32]);
        let other_entry = audit_core::checkpoint::PublicKeyEntry {
            key_id: "gw-2".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(other.verifying_key().to_bytes()),
            role: audit_core::checkpoint::KeyRole::Origin,
        };
        let revoked = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@v2".into(),
            origin_keys: vec![other_entry],
            attestations: Vec::new(),
        }
        .sign("ops-1", &ops);
        let policy = OriginPolicy::from_bundle(&revoked, &ops.verifying_key(), true).unwrap();
        grow_signed(&wal_dir, 1);
        let records = wal::read(&wal_dir, "c1").unwrap();
        let err = seal_pass(&records, &mut store, &s, &policy, 2_000, 1).unwrap_err();
        assert!(
            matches!(err, ledger::Error::UnauthenticatedRecord { seq: 3, .. }),
            "a revoked gateway must not seal: {err:?}"
        );

        let _ = std::fs::remove_dir_all(&wal_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn a_bundle_signed_by_the_wrong_ops_key_is_refused() {
        use audit_core::deployment::{DeploymentBundle, FORMAT as DFMT};
        use ed25519_dalek::SigningKey;
        let ops = SigningKey::from_bytes(&[44u8; 32]);
        let attacker = SigningKey::from_bytes(&[45u8; 32]);
        let signed = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@rogue".into(),
            origin_keys: vec![gw_entry()],
            attestations: Vec::new(),
        }
        .sign("ops-1", &attacker);
        // Verified under the REAL ops key: the forgery collapses.
        assert!(OriginPolicy::from_bundle(&signed, &ops.verifying_key(), true).is_err());
    }

    #[test]
    fn the_trusted_origin_file_refuses_sealing_keys() {
        // A sealing key in the origin trust file is a config error that
        // would quietly merge the two authorities: stop, do not filter.
        let s = sealer();
        let err = OriginPolicy::new(&[s.public_key()], false).unwrap_err();
        assert!(matches!(err, ledger::Error::StoreBroken(_)), "got {err:?}");

        // And requiring origin with nothing to trust refuses everything by
        // construction: also a config error.
        let err = OriginPolicy::new(&[], true).unwrap_err();
        assert!(matches!(err, ledger::Error::StoreBroken(_)));
    }
}
