//! Exit-code contract of the binary, exercised end to end.
//!
//! Exit 0 is the product: pipelines gate on `obsign verify … && deploy`.
//! The one scenario that must never happen is a fully forged pack — signed
//! with the attacker's own key, embedded in the pack itself — coming out
//! with exit 0. These tests run the real binary on real files.

use audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use audit_core::evidence::{Evidence, FORMAT};
use audit_core::origin::SignedRecord;
use audit_core::record::{Effect, EffectStatus, Payload};
use audit_core::ChainWriter;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::process::{Command, Output};

fn entry(key: &SigningKey, key_id: &str) -> PublicKeyEntry {
    PublicKeyEntry {
        key_id: key_id.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        role: KeyRole::Seal,
    }
}

/// A structurally impeccable pack sealed with `key`. Whether it is honest or
/// forged depends only on whose key that is — exactly the point.
fn pack(key: &SigningKey, key_id: &str) -> Evidence {
    let mut chain = ChainWriter::new("cli-chain");
    let records = (0..3)
        .map(|i| {
            chain.append(
                i,
                format!("r{i}"),
                None,
                "sess",
                Payload::Effect(Effect {
                    status: EffectStatus::Ok,
                    result_hash: None,
                    latency_ms: 0,
                }),
            )
        })
        .map(SignedRecord::unsigned)
        .collect();
    let cp = chain.seal(99, key_id).unwrap().sign(key);
    Evidence {
        format: FORMAT.to_string(),
        chain_id: "cli-chain".to_string(),
        records,
        checkpoints: vec![cp],
        keys: vec![entry(key, key_id)],
        anchors: Vec::new(),
        deployment: None,
    }
}

fn write_tmp(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("obsign-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn obsign(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_obsign"))
        .args(args)
        .output()
        .expect("running obsign")
}

#[test]
fn honest_pack_with_trusted_keys_is_proven() {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let ev = write_tmp("honest.json", &serde_json::to_string(&pack(&key, "k1")).unwrap());
    let keys = write_tmp(
        "honest.keys.json",
        &serde_json::to_string(&vec![entry(&key, "k1")]).unwrap(),
    );

    let out = obsign(&[
        "verify",
        "--allow-unsigned-legacy-chains",
        "--trusted-keys",
        keys.to_str().unwrap(),
        ev.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("chain intact"), "stdout: {stdout}");
}

#[test]
fn self_referential_run_exits_3_and_says_not_proven() {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let ev = write_tmp("selfref.json", &serde_json::to_string(&pack(&key, "k1")).unwrap());

    let out = obsign(&["verify", "--allow-unsigned-legacy-chains", ev.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "stdout: {stdout}");
    assert!(stdout.contains("NOT PROVEN"), "stdout: {stdout}");
    assert!(
        !stdout.contains("chain intact"),
        "the intact verdict is reserved for anchored runs; stdout: {stdout}"
    );
}

#[test]
fn forged_pack_without_trusted_keys_must_not_exit_0() {
    // The attack from the review: the pack validates itself with the
    // attacker's key. It stays internally consistent — but exit 0 would
    // turn that consistency into proof.
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let ev = write_tmp(
        "forged.json",
        &serde_json::to_string(&pack(&attacker, "k1")).unwrap(),
    );

    let out = obsign(&["verify", "--allow-unsigned-legacy-chains", ev.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "a self-validating forgery must not exit 0"
    );
}

#[test]
fn forged_pack_against_trusted_keys_exits_1() {
    let real = SigningKey::from_bytes(&[1u8; 32]);
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let ev = write_tmp(
        "forged-vs-real.json",
        &serde_json::to_string(&pack(&attacker, "k1")).unwrap(),
    );
    let keys = write_tmp(
        "real.keys.json",
        &serde_json::to_string(&vec![entry(&real, "k1")]).unwrap(),
    );

    let out = obsign(&[
        "verify",
        "--trusted-keys",
        keys.to_str().unwrap(),
        ev.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("TAMPERING"), "stdout: {stdout}");
}

#[test]
fn json_report_carries_the_self_referential_flag() {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let ev = write_tmp("json.json", &serde_json::to_string(&pack(&key, "k1")).unwrap());

    let out = obsign(&[
        "verify",
        "--json",
        "--allow-unsigned-legacy-chains",
        ev.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["self_referential"], serde_json::Value::Bool(true));
}
