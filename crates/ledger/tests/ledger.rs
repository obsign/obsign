//! The ledger's job is to make one attack visible: rewriting the log on the
//! gateway host after it was sealed. Every test here either performs that
//! attack (or a cousin: truncation, store edition, key substitution) and
//! asserts detection, or exercises the legitimate path and asserts it still
//! works — a control that only ever says "blocked" proves nothing.

use audit_core::evidence;
use audit_core::record::{Effect, EffectStatus, Payload};
use ledger::{export, seal_pass, timestamp_request, validate_response, FileSealer, Sealer, Store};
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
        wal.append(&r).unwrap();
    }
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

    let sc = seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
    assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (0, 4));

    // Nothing new: no empty seal gets manufactured.
    assert!(seal_pass(&records, &mut store, &s, 1001, 1).unwrap().is_none());

    // More activity, second seal: the checkpoints must chain.
    grow_wal(&wal_dir, 3);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc2 = seal_pass(&records, &mut store, &s, 1002, 1).unwrap().unwrap();
    assert_eq!((sc2.checkpoint.from_seq, sc2.checkpoint.to_seq), (5, 7));
    assert_eq!(
        sc2.checkpoint.prev_checkpoint_hash,
        Some(sc.checkpoint.hash())
    );

    // The whole thing survives the auditor's tooling, with real trusted keys.
    let ev = export(records, &store);
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
        seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
    }

    // Restart: the store reloads and re-verifies everything.
    let mut store = Store::open(&store_dir, "c1").unwrap();
    assert_eq!(store.checkpoints().len(), 1);
    let records = wal::read(&wal_dir, "c1").unwrap();
    assert!(
        seal_pass(&records, &mut store, &s, 2000, 1).unwrap().is_none(),
        "already-sealed records must not be sealed again"
    );

    grow_wal(&wal_dir, 2);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, 3000, 1).unwrap().unwrap();
    assert_eq!((sc.checkpoint.from_seq, sc.checkpoint.to_seq), (4, 5));

    let ev = export(records, &store);
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
    seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();

    // Rewrite history: same length, different content, valid chain.
    std::fs::remove_file(wal_dir.join("c1.jsonl")).unwrap();
    {
        let (mut wal, mut chain) = Wal::open(&wal_dir, "c1").unwrap();
        for i in 0..5u64 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i + 100));
            wal.append(&r).unwrap();
        }
    }

    let records = wal::read(&wal_dir, "c1").unwrap();
    let err = seal_pass(&records, &mut store, &s, 2000, 1).unwrap_err();
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
    seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();

    // Sealed records disappear.
    std::fs::remove_file(wal_dir.join("c1.jsonl")).unwrap();
    grow_wal(&wal_dir, 3);

    let records = wal::read(&wal_dir, "c1").unwrap();
    let err = seal_pass(&records, &mut store, &s, 2000, 1).unwrap_err();
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
        seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
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
        seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
        grow_wal(&wal_dir, 2);
        let records = wal::read(&wal_dir, "c1").unwrap();
        seal_pass(&records, &mut store, &s, 2000, 1).unwrap().unwrap();
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
        seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
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
    assert!(seal_pass(&records, &mut store, &s, 2000, 1).unwrap().is_some());

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
        seal_pass(&records, &mut store, &s, 1000, 5).unwrap().is_none(),
        "below the floor, no checkpoint"
    );

    grow_wal(&wal_dir, 3);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let sc = seal_pass(&records, &mut store, &s, 2000, 5).unwrap().unwrap();
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
    seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();

    // Same id, different key: accepting it would let the new key claim the
    // old seals at verification time.
    grow_wal(&wal_dir, 2);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let impostor = FileSealer::from_seed([9u8; 32], "seal-k1");
    let err = seal_pass(&records, &mut store, &impostor, 2000, 1).unwrap_err();
    assert!(matches!(err, ledger::Error::KeyConflict(_)), "got {err:?}");

    // The paired check: the legitimate key still seals.
    assert!(seal_pass(&records, &mut store, &s, 3000, 1).unwrap().is_some());

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
    let sc = seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
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
    let ev = export(records, &store);
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
    let sc = seal_pass(&records, &mut store, &s, 1000, 1).unwrap().unwrap();
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
