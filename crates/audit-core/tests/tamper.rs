//! Tampering tests.
//!
//! This is the suite that matters: it does not check that the code "works",
//! it checks that it **detects**. Each test reproduces a realistic way of
//! dressing up a log.

use audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use audit_core::evidence::{self, Evidence, Severity, VerifyOptions, FORMAT};
use audit_core::origin::{origin_signing_bytes, SignedRecord};
use audit_core::record::*;
use audit_core::{content_hash, ChainWriter};
use ed25519_dalek::{Signer, SigningKey};

const KEY_ID: &str = "test-key";
const CHAIN_ID: &str = "test-chain";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn pubkey_entry(key: &SigningKey) -> PublicKeyEntry {
    PublicKeyEntry {
        key_id: KEY_ID.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        role: KeyRole::Seal,
    }
}

fn wrap(records: Vec<Record>) -> Vec<SignedRecord> {
    records.into_iter().map(SignedRecord::unsigned).collect()
}

fn tool_call(tool: &str) -> Payload {
    Payload::ToolCall(ToolCall {
        server: "mcp://test".into(),
        tool: tool.into(),
        args_hash: content_hash(tool.as_bytes()),
        args_sealed: None,
    })
}

fn decision(outcome: Outcome) -> Payload {
    Payload::Decision(Decision {
        outcome,
        policy_id: Some("p1".into()),
        bundle_version: "policies@test".into(),
        reason: None,
    })
}

/// Reference chain: 6 records, a single checkpoint.
fn sample() -> (Evidence, Vec<PublicKeyEntry>) {
    let key = signing_key();
    let mut chain = ChainWriter::new(CHAIN_ID);
    let mut records = Vec::new();

    for i in 0..3 {
        records.push(chain.append(
            1_000 + i as i64,
            format!("call-{i}"),
            None,
            "sess-1",
            tool_call(&format!("tool_{i}")),
        ));
        records.push(chain.append(
            1_001 + i as i64,
            format!("dec-{i}"),
            Some(format!("call-{i}")),
            "sess-1",
            decision(if i == 1 { Outcome::Deny } else { Outcome::Allow }),
        ));
    }

    let cp = chain.seal(9_000, KEY_ID).unwrap().sign(&key);
    let entry = pubkey_entry(&key);

    (
        Evidence {
            format: FORMAT.to_string(),
            chain_id: CHAIN_ID.to_string(),
            records: wrap(records),
            checkpoints: vec![cp],
            keys: vec![entry.clone()],
            anchors: Vec::new(),
            deployment: None,
        },
        vec![entry],
    )
}

fn codes(r: &evidence::Report) -> Vec<&str> {
    r.findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.code.as_str())
        .collect()
}

#[test]
fn intact_chain_is_valid() {
    let (ev, keys) = sample();
    let r = evidence::verify(&ev, &keys);
    assert!(r.is_valid(), "findings: {:?}", r.findings);
    assert_eq!(r.records_total, 6);
    assert_eq!(r.records_sealed, 6, "everything must be sealed");
    assert_eq!(r.checkpoints_valid, 1);
}

#[test]
fn editing_a_verdict_breaks_the_chain() {
    // The feared scenario: someone flips a Deny into an Allow after the fact
    // to make an awkward trace disappear.
    let (mut ev, keys) = sample();
    ev.records[3].record.payload = decision(Outcome::Allow);

    let r = evidence::verify(&ev, &keys);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"broken_link"));
    assert!(codes(&r).contains(&"root_mismatch"));
}

#[test]
fn deleting_a_record_is_visible() {
    let (mut ev, keys) = sample();
    ev.records.remove(2);

    let r = evidence::verify(&ev, &keys);
    assert!(!r.is_valid());
    let c = codes(&r);
    assert!(c.contains(&"sequence_gap"));
    assert!(c.contains(&"missing_records"));
}

#[test]
fn reordering_is_visible() {
    let (mut ev, keys) = sample();
    ev.records.swap(1, 2);

    let r = evidence::verify(&ev, &keys);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"invalid_order"));
}

#[test]
fn rewriting_the_whole_chain_is_stopped_by_the_signature() {
    // The serious attack: whoever holds the database rebuilds a fully
    // consistent chain. It is internally consistent, so the hash chain alone
    // is not enough — the signature stops it, because the key is not in the
    // database.
    let (_, keys) = sample();

    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let mut chain = ChainWriter::new(CHAIN_ID);
    let mut records = Vec::new();
    for i in 0..3 {
        records.push(chain.append(
            1_000 + i as i64,
            format!("call-{i}"),
            None,
            "sess-1",
            tool_call(&format!("tool_{i}")),
        ));
        // Every verdict "rewritten" to Allow.
        records.push(chain.append(
            1_001 + i as i64,
            format!("dec-{i}"),
            Some(format!("call-{i}")),
            "sess-1",
            decision(Outcome::Allow),
        ));
    }
    let cp = chain.seal(9_000, KEY_ID).unwrap().sign(&attacker);

    let forged = Evidence {
        format: FORMAT.to_string(),
        chain_id: CHAIN_ID.to_string(),
        records: wrap(records),
        checkpoints: vec![cp],
        keys: vec![pubkey_entry(&attacker)], // the forger supplies their key
        anchors: Vec::new(),
        deployment: None,
    };

    // Verified against the REAL trusted keys: the forgery collapses.
    let r = evidence::verify(&forged, &keys);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"invalid_signature"));

    // And with no key anchoring, the same pack would pass — hence the
    // mandatory warning.
    let unanchored = evidence::verify(&forged, &[]);
    assert!(unanchored.is_valid());
    assert!(unanchored.warnings().any(|f| f.code == "keys_not_anchored"));
}

#[test]
fn removing_a_checkpoint_is_visible() {
    let key = signing_key();
    let mut chain = ChainWriter::new(CHAIN_ID);
    let mut records = Vec::new();
    let mut cps = Vec::new();

    for batch in 0..3 {
        for i in 0..2 {
            records.push(chain.append(
                batch * 100 + i,
                format!("r-{batch}-{i}"),
                None,
                "sess-1",
                tool_call("t"),
            ));
        }
        cps.push(chain.seal(9_000 + batch, KEY_ID).unwrap().sign(&key));
    }

    let entry = pubkey_entry(&key);
    let mut ev = Evidence {
        format: FORMAT.to_string(),
        chain_id: CHAIN_ID.to_string(),
        records: wrap(records),
        checkpoints: cps,
        keys: vec![entry.clone()],
        anchors: Vec::new(),
        deployment: None,
    };
    assert!(evidence::verify(&ev, std::slice::from_ref(&entry)).is_valid());

    // Remove the middle checkpoint.
    ev.checkpoints.remove(1);
    let r = evidence::verify(&ev, &[entry]);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"broken_checkpoint_link"));
}

#[test]
fn records_appended_after_sealing_are_reported() {
    // Consistent with the chain but covered by no seal: they are not proven,
    // and the report must say so instead of concluding "all good".
    let key = signing_key();
    let mut chain = ChainWriter::new(CHAIN_ID);
    let mut records = Vec::new();

    for i in 0..2 {
        records.push(chain.append(i, format!("r-{i}"), None, "s", tool_call("t")));
    }
    let cp = chain.seal(9_000, KEY_ID).unwrap().sign(&key);
    for i in 2..5 {
        records.push(chain.append(i, format!("r-{i}"), None, "s", tool_call("t")));
    }

    let entry = pubkey_entry(&key);
    let ev = Evidence {
        format: FORMAT.to_string(),
        chain_id: CHAIN_ID.to_string(),
        records: wrap(records),
        checkpoints: vec![cp],
        keys: vec![entry.clone()],
        anchors: Vec::new(),
        deployment: None,
    };

    let r = evidence::verify(&ev, &[entry]);
    assert!(r.is_valid(), "not tampering: a coverage gap");
    assert_eq!(r.records_total, 5);
    assert_eq!(r.records_sealed, 2);
    assert!(r.warnings().any(|f| f.code == "unsealed_records"));
}

#[test]
fn flipping_one_content_byte_changes_the_hash() {
    let a = content_hash(br#"{"database":"customers"}"#);
    let b = content_hash(br#"{"database":"customer5"}"#);
    assert_ne!(a, b);
}

#[test]
fn payload_types_are_not_confusable() {
    // Two different payloads must never produce the same hash, even when
    // crafted to look alike.
    let mut c1 = ChainWriter::new("c");
    let r1 = c1.append(0, "x", None, "s", tool_call("a"));

    let mut c2 = ChainWriter::new("c");
    let r2 = c2.append(
        0,
        "x",
        None,
        "s",
        Payload::Effect(Effect {
            status: EffectStatus::Ok,
            result_hash: None,
            latency_ms: 0,
        }),
    );

    assert_ne!(r1.hash(), r2.hash());
}

// =====================================================================
// Format reference vectors
// =====================================================================

/// The record format is frozen: these hashes must NEVER change.
///
/// Any change to the canonical encoding, to field order or to a discriminant
/// makes this test fail — which is the point. The day it breaks, the question
/// is not "how do I update the constants" but "which already-sealed logs have
/// just been invalidated".
///
/// Extending the format stays possible: add a *new* payload type with the next
/// free discriminant, do not touch the existing ones. `Payload::Actor` (tag 7)
/// then `Payload::ConfigReload` (tag 8) were added that way after the fact,
/// without any of the earlier hashes below moving.
#[test]
fn record_format_is_frozen() {
    use audit_core::{Hash, GENESIS};

    let cases: Vec<(&str, Record, &str)> = vec![
        (
            "delegation",
            Record {
                seq: 0,
                ts_ms: 1_700_000_000_000,
                prev_hash: GENESIS,
                id: "deleg-1".into(),
                parent_id: None,
                session_id: "s1".into(),
                payload: Payload::Delegation(Delegation {
                    principal_sub: "u:marie".into(),
                    principal_issuer: "https://idp".into(),
                    scopes: vec!["a".into(), "b".into()],
                    expires_at_ms: 1_700_000_060_000,
                    approved_by: None,
                    approval_mode: ApprovalMode::Implicit,
                }),
            },
            "05817ef5fcd502705f82e1e3b17b69dfbb7054860ee61a3151e5e61506dabfc7",
        ),
        (
            "tool_call",
            Record {
                seq: 1,
                ts_ms: 1_700_000_000_001,
                prev_hash: Hash([0xAB; 32]),
                id: "call-1".into(),
                parent_id: Some("agent-1".into()),
                session_id: "s1".into(),
                payload: Payload::ToolCall(ToolCall {
                    server: "mcp://x".into(),
                    tool: "drop".into(),
                    args_hash: Hash([0x11; 32]),
                    args_sealed: None,
                }),
            },
            "4f2978c45837293530c1c720b8bacc37759187b5b358da87fa881af08a2e1ad6",
        ),
        (
            "effect",
            Record {
                seq: 2,
                ts_ms: 1_700_000_000_002,
                prev_hash: Hash([0xCD; 32]),
                id: "eff-1".into(),
                parent_id: Some("dec-1".into()),
                session_id: "s1".into(),
                payload: Payload::Effect(Effect {
                    status: EffectStatus::Blocked,
                    result_hash: None,
                    latency_ms: 3,
                }),
            },
            "e8da73fd8187fba5c7b0438ef550f192669322f86cff8b079fa9f5e082e7d31e",
        ),
        (
            "actor",
            Record {
                seq: 3,
                ts_ms: 1_700_000_000_003,
                prev_hash: Hash([0xEF; 32]),
                id: "actor-1".into(),
                parent_id: Some("deleg-1".into()),
                session_id: "s1".into(),
                payload: Payload::Actor(Actor {
                    chain: vec!["agent".into(), "u:marie".into()],
                    principal_kind: PrincipalKind::DelegatedHuman,
                }),
            },
            "aebd19fa48503ee85f15838657480a39e04c9d7f61dfd9c322f7d0ecfaf85c1b",
        ),
        (
            "config_reload",
            Record {
                seq: 4,
                ts_ms: 1_700_000_000_004,
                prev_hash: Hash([0x12; 32]),
                id: "reload-1".into(),
                parent_id: None,
                session_id: "s1".into(),
                payload: Payload::ConfigReload(ConfigReload {
                    config_kind: ConfigKind::IdentityBundle,
                    status: ReloadStatus::Applied,
                    bundle_version: "identity@2".into(),
                    bundle_hash: Some(Hash([0x34; 32])),
                    reason: None,
                }),
            },
            "1a688bc4d21c20a4e377f96828508421b953707d0f0eddb6198fcac0b537f8e4",
        ),
        (
            "session_cert",
            Record {
                seq: 5,
                ts_ms: 1_700_000_000_005,
                prev_hash: Hash([0x56; 32]),
                id: "sesscert-1".into(),
                parent_id: None,
                session_id: "s1".into(),
                payload: Payload::SessionCert(SessionCert {
                    session_pubkey: "aa".repeat(32),
                    identity_key_id: "id-gw-1".into(),
                    gateway_id: "gw-1".into(),
                    not_before_ms: 1_700_000_000_000,
                    not_after_ms: 1_700_000_060_000,
                    identity_sig: "bb".repeat(64),
                }),
            },
            "2266c6b5d3d5e8d84ecb28263d9946eaf4e70bbfa589d4a10300b643e1fa2e55",
        ),
    ];

    for (name, rec, expected) in cases {
        assert_eq!(
            rec.hash().to_hex(),
            expected,
            "the hash of payload \"{name}\" changed: the format has been broken"
        );
    }
}

#[test]
fn every_payload_survives_a_json_round_trip() {
    // Regression: `Payload` is serialized with `#[serde(tag = "kind")]`. A
    // field called `kind` inside a variant collides with the discriminant
    // serde injects — the value gets written twice and reading it back fails
    // with `duplicate field`.
    //
    // The bug shows up neither at compile time nor on write: only when the WAL
    // reads itself back, i.e. on gateway restart or when generating the
    // evidence pack. This test surfaces it immediately.
    use audit_core::Hash;

    let payloads = vec![
        Payload::Delegation(Delegation {
            principal_sub: "u:marie".into(),
            principal_issuer: "https://idp".into(),
            scopes: vec!["a".into()],
            expires_at_ms: 1,
            approved_by: Some("u:boss".into()),
            approval_mode: ApprovalMode::FourEyes,
        }),
        Payload::Actor(Actor {
            chain: vec!["agent".into(), "u:marie".into()],
            principal_kind: PrincipalKind::DelegatedHuman,
        }),
        Payload::AgentSession(AgentSession {
            agent_id: "a".into(),
            agent_version: "1".into(),
            config_hash: Hash([1; 32]),
        }),
        Payload::LlmTurn(LlmTurn {
            provider: "anthropic".into(),
            model: "claude-sonnet-5".into(),
            prompt_hash: Hash([2; 32]),
            response_hash: Hash([3; 32]),
            input_tokens: Some(10),
            output_tokens: None,
            cost_micros: Some(5),
        }),
        tool_call("t"),
        decision(Outcome::AllowFailOpen),
        Payload::Effect(Effect {
            status: EffectStatus::Timeout,
            result_hash: Some(Hash([4; 32])),
            latency_ms: 7,
        }),
        Payload::ConfigReload(ConfigReload {
            config_kind: ConfigKind::IdentityBundle,
            status: ReloadStatus::Rejected,
            bundle_version: "identity@1".into(),
            bundle_hash: Some(Hash([5; 32])),
            reason: Some("bad signature".into()),
        }),
    ];

    for p in payloads {
        let rec = Record {
            seq: 0,
            ts_ms: 0,
            prev_hash: audit_core::GENESIS,
            id: "r".into(),
            parent_id: None,
            session_id: "s".into(),
            payload: p.clone(),
        };

        let json = serde_json::to_string(&rec).expect("serialization");
        let back: Record = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("cannot read {p:?} back: {e}\n{json}"));

        assert_eq!(back, rec, "round trip not faithful for {p:?}");
        assert_eq!(
            back.hash(),
            rec.hash(),
            "hash changed after round trip for {p:?}"
        );
    }
}

// =====================================================================
// Origin authentication
// =====================================================================
//
// The gap these tests pin down: every input to a record's hash is public,
// so the hash chain never proved WHO wrote a record — only that the set is
// internally consistent. The origin signature is the one element a disk
// attacker cannot regenerate.

const ORIGIN_KEY_ID: &str = "gw-origin";

fn origin_key() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

fn origin_entry(key: &SigningKey) -> PublicKeyEntry {
    PublicKeyEntry {
        key_id: ORIGIN_KEY_ID.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        role: KeyRole::Origin,
    }
}

fn sign_origin(rec: Record, chain_id: &str, key: &SigningKey) -> SignedRecord {
    let msg = origin_signing_bytes(chain_id, &rec.hash());
    SignedRecord::signed(rec, ORIGIN_KEY_ID, key.sign(&msg).to_bytes())
}

/// Fully signed chain: origin on every record, one seal.
fn origin_sample() -> (Evidence, Vec<PublicKeyEntry>) {
    let seal_key = signing_key();
    let og = origin_key();
    let mut chain = ChainWriter::new(CHAIN_ID);
    let records: Vec<SignedRecord> = (0..4)
        .map(|i| {
            let rec = chain.append(1_000 + i, format!("call-{i}"), None, "sess-1", tool_call("t"));
            sign_origin(rec, CHAIN_ID, &og)
        })
        .collect();
    let cp = chain.seal(9_000, KEY_ID).unwrap().sign(&seal_key);
    let trusted = vec![pubkey_entry(&seal_key), origin_entry(&og)];

    (
        Evidence {
            format: FORMAT.to_string(),
            chain_id: CHAIN_ID.to_string(),
            records,
            checkpoints: vec![cp],
            keys: trusted.clone(),
            anchors: Vec::new(),
            deployment: None,
        },
        trusted,
    )
}

const REQUIRE_ORIGIN: VerifyOptions = VerifyOptions {
    require_origin: true,
    require_attestation: false,
};

#[test]
fn a_fully_signed_chain_verifies_clean_under_require_origin() {
    let (ev, trusted) = origin_sample();
    let r = evidence::verify_with(&ev, &trusted, &REQUIRE_ORIGIN);
    assert!(r.is_valid(), "findings: {:?}", r.findings);
    assert_eq!(r.records_origin_ok, 4);
    assert!(
        !r.findings.iter().any(|f| f.code.starts_with("origin")),
        "a fully proven origin must stay silent"
    );
}

#[test]
fn a_fabricated_record_cannot_carry_a_valid_origin_signature() {
    // Exit-0 gap #2, the record-level half: an attacker with disk write
    // appends a well-formed record after the head. Without origin auth the
    // pack verified clean; now the forgery is visible — as an absence under
    // the default posture, as an error when the deployment mandates origin.
    let (mut ev, trusted) = origin_sample();
    let last = ev.records.last().unwrap();
    let mut chain = ChainWriter::resume(CHAIN_ID, last.seq + 1, last.record.hash(), None);
    let forged = chain.append(2_000, "call-x", None, "sess-1", tool_call("drop_tables"));
    ev.records.push(SignedRecord::unsigned(forged));

    let permissive = evidence::verify(&ev, &trusted);
    assert!(permissive
        .warnings()
        .any(|f| f.code == "origin_unverified"));

    let r = evidence::verify_with(&ev, &trusted, &REQUIRE_ORIGIN);
    assert!(!r.is_valid(), "a record nobody signed must not pass");
    assert!(codes(&r).contains(&"origin_unverified"));
}

#[test]
fn an_attacker_signature_under_an_unknown_key_proves_nothing() {
    let (mut ev, trusted) = origin_sample();
    let last = ev.records.last().unwrap();
    let mut chain = ChainWriter::resume(CHAIN_ID, last.seq + 1, last.record.hash(), None);
    let forged = chain.append(2_000, "call-x", None, "sess-1", tool_call("drop_tables"));
    // The attacker signs with their own key and embeds it nowhere trusted.
    let attacker = SigningKey::from_bytes(&[66u8; 32]);
    let msg = origin_signing_bytes(CHAIN_ID, &forged.hash());
    ev.records.push(SignedRecord::signed(
        forged,
        "attacker-key",
        attacker.sign(&msg).to_bytes(),
    ));

    let r = evidence::verify_with(&ev, &trusted, &REQUIRE_ORIGIN);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"origin_unverified"));
}

#[test]
fn a_tampered_signature_under_a_trusted_key_is_always_an_error() {
    // Unlike an absent signature, an INVALID one under a trusted key is
    // positive evidence of tampering: error even without require_origin.
    let (mut ev, trusted) = origin_sample();
    ev.records[2].origin_sig = Some(hex::encode([0u8; 64]));

    let r = evidence::verify(&ev, &trusted);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"origin_invalid"));
}

#[test]
fn stripping_signatures_downgrades_the_proof_visibly() {
    // The attacker cannot forge a signature, so they remove them all and
    // hope the pack reads like a pre-origin-auth log. It does — and that
    // downgrade is exactly what the warning (or the error, under
    // require_origin) surfaces.
    let (mut ev, trusted) = origin_sample();
    for sr in &mut ev.records {
        sr.origin_sig = None;
        sr.origin_key_id = None;
    }

    let permissive = evidence::verify(&ev, &trusted);
    assert!(permissive.is_valid(), "absence of proof is not tampering");
    assert!(permissive
        .warnings()
        .any(|f| f.code == "origin_unverified"));
    assert_eq!(permissive.records_origin_ok, 0);

    let strict = evidence::verify_with(&ev, &trusted, &REQUIRE_ORIGIN);
    assert!(!strict.is_valid(), "a deployment that mandates origin must refuse");
}

#[test]
fn a_signed_record_transplanted_from_another_chain_is_refused() {
    // Same position, same content, honestly signed — but for another chain.
    // Only the chain id in the signed message stops the transplant, because
    // the record itself does not carry its chain id (the WAL filename does,
    // and filenames are what a disk attacker rewrites).
    let (mut ev, trusted) = origin_sample();
    let og = origin_key();

    let mut other = ChainWriter::new("other-chain");
    let mut donor = None;
    for i in 0..ev.records.len() as u64 {
        let rec = other.append(1_000 + i as i64, format!("call-{i}"), None, "sess-1", tool_call("t"));
        if i == 2 {
            donor = Some(sign_origin(rec, "other-chain", &og));
        }
    }
    let donor = donor.unwrap();
    assert_eq!(donor.record.hash(), ev.records[2].record.hash(),
        "the transplant only makes sense if the records are byte-identical");
    ev.records[2] = donor;

    let r = evidence::verify_with(&ev, &trusted, &REQUIRE_ORIGIN);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"origin_invalid"));
}

#[test]
fn key_roles_do_not_substitute_for_each_other() {
    // One key pair, presented under both roles by the pack: whichever way
    // the confusion runs, writer and certifier must stay distinct
    // authorities.
    let (ev, _) = origin_sample();

    // The sealing key offered as an origin key…
    let seal_as_origin = PublicKeyEntry {
        role: KeyRole::Origin,
        ..pubkey_entry(&signing_key())
    };
    // …and the origin key offered as a sealing key.
    let origin_as_seal = PublicKeyEntry {
        role: KeyRole::Seal,
        ..origin_entry(&origin_key())
    };

    let r = evidence::verify(&ev, &[seal_as_origin, origin_as_seal]);
    assert!(!r.is_valid());
    assert!(codes(&r).contains(&"key_role_mismatch"),
        "findings: {:?}", r.findings);
}

// =====================================================================
// Deployment bundle — the origin chain of trust
// =====================================================================
//
// v1: origin keys arrive through an ops-signed bundle embedded in the pack,
// so the auditor verifies ops key -> bundle -> origin keys -> records with
// nothing but the ops key out of band.

mod deployment {
    use super::*;
    use audit_core::deployment::{DeploymentBundle, FORMAT as DFMT};
    use audit_core::origin_signing_bytes;
    use ed25519_dalek::{Signer, SigningKey};

    fn origin_entry(key_id: &str, key: &SigningKey) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: key_id.into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }

    fn ops_entry(key_id: &str, key: &SigningKey) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: key_id.into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: KeyRole::Seal, // ops key wears the default role; resolved by id
        }
    }

    /// Chain signed by `gw_key`, sealed by `seal_key`, with an ops-signed
    /// deployment bundle enrolling the gateway, all embedded in the pack.
    fn pack_with_bundle(
        gw_key: &SigningKey,
        seal_key: &SigningKey,
        ops_key: &SigningKey,
        enrolled_key_id: &str,
    ) -> Evidence {
        let mut chain = ChainWriter::new(CHAIN_ID);
        let records: Vec<SignedRecord> = (0..3)
            .map(|i| {
                let rec = chain.append(1_000 + i, format!("r{i}"), None, "s", tool_call("t"));
                let msg = origin_signing_bytes(CHAIN_ID, &rec.hash());
                SignedRecord::signed(rec, "gw-1", gw_key.sign(&msg).to_bytes())
            })
            .collect();
        let cp = chain.seal(9_000, KEY_ID).unwrap().sign(seal_key);

        let bundle = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@v1".into(),
            origin_keys: vec![origin_entry(enrolled_key_id, gw_key)],
            attestations: Vec::new(),
        }
        .sign("ops-1", ops_key);

        Evidence {
            format: FORMAT.to_string(),
            chain_id: CHAIN_ID.to_string(),
            records,
            checkpoints: vec![cp],
            // The pack embeds seal + ops keys; the origin key rides the bundle.
            keys: vec![pubkey_entry(seal_key), ops_entry("ops-1", ops_key)],
            anchors: Vec::new(),
            deployment: Some(bundle),
        }
    }

    fn trust(seal_key: &SigningKey, ops_key: &SigningKey) -> Vec<PublicKeyEntry> {
        vec![pubkey_entry(seal_key), ops_entry("ops-1", ops_key)]
    }

    const REQUIRE: VerifyOptions = VerifyOptions { require_origin: true, require_attestation: false };

    #[test]
    fn ops_key_alone_anchors_the_whole_origin_chain() {
        let gw = SigningKey::from_bytes(&[21u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[22u8; 32]);
        let ev = pack_with_bundle(&gw, &seal, &ops, "gw-1");

        // No origin key supplied out of band — only seal + ops. The bundle
        // provides the origin key, and the whole chain verifies.
        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(r.is_valid(), "findings: {:?}", r.findings);
        assert_eq!(r.records_origin_ok, 3);
    }

    #[test]
    fn a_forged_bundle_is_rejected() {
        let gw = SigningKey::from_bytes(&[21u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[22u8; 32]);
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        // The attacker enrolls their own gateway key, signing the bundle with
        // their own key but claiming the real ops key id.
        let mut ev = pack_with_bundle(&gw, &seal, &ops, "gw-1");
        ev.deployment = Some(
            DeploymentBundle {
                format: DFMT.into(),
                version: "deployment@rogue".into(),
                origin_keys: vec![origin_entry("gw-evil", &attacker)],
                attestations: Vec::new(),
            }
            .sign("ops-1", &attacker),
        );

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid());
        assert!(codes(&r).contains(&"deployment_bundle_invalid"));
    }

    #[test]
    fn a_revoked_gateway_no_longer_anchors_its_records() {
        // Revocation = the gateway's key is no longer in the bundle. Its
        // records then have no trusted origin key: unproven, refused under
        // require-origin. (The old pack that embedded the key still verifies;
        // this is a *fresh* verification against the current bundle.)
        let gw = SigningKey::from_bytes(&[21u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[22u8; 32]);
        let mut ev = pack_with_bundle(&gw, &seal, &ops, "gw-1");
        // Republish a bundle that enrolls a *different* gateway: gw-1 revoked.
        let other = SigningKey::from_bytes(&[23u8; 32]);
        ev.deployment = Some(
            DeploymentBundle {
                format: DFMT.into(),
                version: "deployment@v2".into(),
                origin_keys: vec![origin_entry("gw-2", &other)],
                attestations: Vec::new(),
            }
            .sign("ops-1", &ops),
        );

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid(), "a revoked key must not anchor records");
        assert!(codes(&r).contains(&"origin_unverified"));
    }

    #[test]
    fn a_bundle_without_its_ops_key_is_a_warning_not_a_proof() {
        let gw = SigningKey::from_bytes(&[21u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[22u8; 32]);
        let ev = pack_with_bundle(&gw, &seal, &ops, "gw-1");

        // Trust only the seal key: the bundle cannot be anchored, so its
        // origin keys prove nothing — a warning, and the records fall to
        // unverified.
        let r = evidence::verify_with(&ev, &[pubkey_entry(&seal)], &REQUIRE);
        assert!(!r.is_valid());
        assert!(r
            .warnings()
            .any(|f| f.code == "deployment_bundle_unverified"));
    }
}

// =====================================================================
// Session certificates (v2) — two-tier keys
// =====================================================================
//
// Records are signed by an ephemeral session key; a session certificate,
// signed by the gateway's identity key (enrolled in the deployment bundle),
// is what a verifier resolves that session key against. The identity key
// never signs records; the session key never leaves memory.

mod session_certs {
    use super::*;
    use audit_core::deployment::{DeploymentBundle, FORMAT as DFMT};
    use audit_core::{key_id_for, session_cert_signing_bytes};
    use ed25519_dalek::{Signer, SigningKey};

    const IDENTITY_ID: &str = "id-gw-1";

    fn origin_entry(key_id: &str, key: &SigningKey) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: key_id.into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }

    fn ops_entry(key: &SigningKey) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: "ops-1".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: KeyRole::Seal,
        }
    }

    fn make_cert(
        chain_id: &str,
        session: &SigningKey,
        identity: &SigningKey,
        identity_id: &str,
    ) -> SessionCert {
        let mut cert = SessionCert {
            session_pubkey: hex::encode(session.verifying_key().to_bytes()),
            identity_key_id: identity_id.into(),
            gateway_id: "gw-1".into(),
            not_before_ms: 0,
            not_after_ms: 1_000_000,
            identity_sig: String::new(),
        };
        let sig = identity.sign(&session_cert_signing_bytes(chain_id, &cert));
        cert.identity_sig = hex::encode(sig.to_bytes());
        cert
    }

    fn sign_record(rec: Record, chain_id: &str, session: &SigningKey) -> SignedRecord {
        let msg = audit_core::origin_signing_bytes(chain_id, &rec.hash());
        SignedRecord::signed(rec, key_id_for(&session.verifying_key()), session.sign(&msg).to_bytes())
    }

    /// A v2 chain: session cert first, then records, all signed by the session
    /// key; the identity key enrolled in an embedded ops-signed bundle.
    fn v2_pack(
        session: &SigningKey,
        identity: &SigningKey,
        seal: &SigningKey,
        ops: &SigningKey,
        cert: SessionCert,
    ) -> Evidence {
        let mut chain = ChainWriter::new(CHAIN_ID);
        let mut records = Vec::new();
        let rec0 = chain.append(0, "sesscert", None, "s", Payload::SessionCert(cert));
        records.push(sign_record(rec0, CHAIN_ID, session));
        for i in 1..3 {
            let rec = chain.append(i, format!("call-{i}"), None, "s", tool_call("t"));
            records.push(sign_record(rec, CHAIN_ID, session));
        }
        let cp = chain.seal(9_000, KEY_ID).unwrap().sign(seal);

        let bundle = DeploymentBundle {
            format: DFMT.into(),
            version: "deployment@v2".into(),
            origin_keys: vec![origin_entry(IDENTITY_ID, identity)],
            attestations: Vec::new(),
        }
        .sign("ops-1", ops);

        Evidence {
            format: FORMAT.to_string(),
            chain_id: CHAIN_ID.to_string(),
            records,
            checkpoints: vec![cp],
            keys: vec![pubkey_entry(seal), ops_entry(ops)],
            anchors: Vec::new(),
            deployment: Some(bundle),
        }
    }

    fn trust(seal: &SigningKey, ops: &SigningKey) -> Vec<PublicKeyEntry> {
        vec![pubkey_entry(seal), ops_entry(ops)]
    }

    const REQUIRE: VerifyOptions = VerifyOptions { require_origin: true, require_attestation: false };

    #[test]
    fn a_certified_session_key_verifies_the_whole_chain() {
        let session = SigningKey::from_bytes(&[31u8; 32]);
        let identity = SigningKey::from_bytes(&[32u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[33u8; 32]);
        let cert = make_cert(CHAIN_ID, &session, &identity, IDENTITY_ID);
        let ev = v2_pack(&session, &identity, &seal, &ops, cert);

        // Only ops + seal keys out of band: the bundle names the identity
        // key, the cert authorizes the session key, the session key signs the
        // records. The whole chain of trust resolves.
        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(r.is_valid(), "findings: {:?}", r.findings);
        assert_eq!(r.records_origin_ok, 3, "cert record included");
    }

    #[test]
    fn a_forged_certificate_is_rejected() {
        // The attacker mints their own session key and signs the cert with a
        // key that is not the enrolled identity key.
        let session = SigningKey::from_bytes(&[31u8; 32]);
        let identity = SigningKey::from_bytes(&[32u8; 32]);
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[33u8; 32]);
        // Cert claims the real identity id but is signed by the attacker.
        let cert = make_cert(CHAIN_ID, &session, &attacker, IDENTITY_ID);
        let ev = v2_pack(&session, &identity, &seal, &ops, cert);

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid());
        assert!(codes(&r).contains(&"session_cert_invalid"));
    }

    #[test]
    fn a_certificate_for_another_chain_does_not_transfer() {
        // A cert honestly signed by the identity key, but for a different
        // chain id: the chain_id binding stops the transplant.
        let session = SigningKey::from_bytes(&[31u8; 32]);
        let identity = SigningKey::from_bytes(&[32u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[33u8; 32]);
        let cert = make_cert("other-chain", &session, &identity, IDENTITY_ID);
        let ev = v2_pack(&session, &identity, &seal, &ops, cert);

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid(), "a cert bound to another chain must not verify");
        assert!(codes(&r).contains(&"session_cert_invalid"));
    }

    #[test]
    fn an_unenrolled_identity_key_leaves_the_session_unproven() {
        // The identity key is genuine and its signature valid, but it is not
        // enrolled in the bundle: the session keys it vouches for prove
        // nothing, and the records fall to unverified under require-origin.
        let session = SigningKey::from_bytes(&[31u8; 32]);
        let identity = SigningKey::from_bytes(&[32u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[33u8; 32]);
        // The bundle enrolls a DIFFERENT identity, but the cert names IDENTITY_ID.
        let other_identity = SigningKey::from_bytes(&[40u8; 32]);
        let cert = make_cert(CHAIN_ID, &session, &identity, IDENTITY_ID);
        let mut ev = v2_pack(&session, &other_identity, &seal, &ops, cert);
        // Rebuild the bundle to enroll only the other identity under a name
        // the cert does not reference.
        ev.deployment = Some(
            DeploymentBundle {
                format: DFMT.into(),
                version: "deployment@v2".into(),
                origin_keys: vec![origin_entry("id-other", &other_identity)],
                attestations: Vec::new(),
            }
            .sign("ops-1", &ops),
        );

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid());
        assert!(codes(&r).contains(&"session_cert_unverified"));
    }

    #[test]
    fn a_record_signed_by_an_uncertified_session_key_is_unproven() {
        // The chain carries no certificate for the key that signed its
        // records: nothing links the session key to an identity key.
        let session = SigningKey::from_bytes(&[31u8; 32]);
        let seal = signing_key();
        let ops = SigningKey::from_bytes(&[33u8; 32]);
        let mut chain = ChainWriter::new(CHAIN_ID);
        let records: Vec<SignedRecord> = (0..2)
            .map(|i| {
                let rec = chain.append(i, format!("r{i}"), None, "s", tool_call("t"));
                sign_record(rec, CHAIN_ID, &session)
            })
            .collect();
        let cp = chain.seal(9_000, KEY_ID).unwrap().sign(&seal);
        let ev = Evidence {
            format: FORMAT.to_string(),
            chain_id: CHAIN_ID.to_string(),
            records,
            checkpoints: vec![cp],
            keys: vec![pubkey_entry(&seal), ops_entry(&ops)],
            anchors: Vec::new(),
            deployment: None,
        };

        let r = evidence::verify_with(&ev, &trust(&seal, &ops), &REQUIRE);
        assert!(!r.is_valid(), "an uncertified session key proves nothing");
        assert!(codes(&r).contains(&"origin_unverified"));
    }
}
