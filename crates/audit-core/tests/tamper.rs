//! Tampering tests.
//!
//! This is the suite that matters: it does not check that the code "works",
//! it checks that it **detects**. Each test reproduces a realistic way of
//! dressing up a log.

use audit_core::checkpoint::PublicKeyEntry;
use audit_core::evidence::{self, Evidence, Severity, FORMAT};
use audit_core::record::*;
use audit_core::{content_hash, ChainWriter};
use ed25519_dalek::SigningKey;

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
    }
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
            records,
            checkpoints: vec![cp],
            keys: vec![entry.clone()],
            anchors: Vec::new(),
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
    ev.records[3].payload = decision(Outcome::Allow);

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
        records,
        checkpoints: vec![cp],
        keys: vec![pubkey_entry(&attacker)], // the forger supplies their key
        anchors: Vec::new(),
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
        records,
        checkpoints: cps,
        keys: vec![entry.clone()],
        anchors: Vec::new(),
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
        records,
        checkpoints: vec![cp],
        keys: vec![entry.clone()],
        anchors: Vec::new(),
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
/// was added that way after the fact, without any of the first three hashes
/// below moving.
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
