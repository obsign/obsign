//! Generates a sample evidence pack: the demo scenario.
//!
//! A support agent, acting for an identified human, tries to call
//! `delete_production_db`. The policy refuses. The call never reaches the
//! database. Everything is sealed and verifiable offline.
//!
//!     cargo run -p obsign-audit-core --example gen_sample -- /tmp/demo
//!
//! Three keys, three roles, as in a real deployment: the gateway signs each
//! record as it writes it (origin), the ledger signs the checkpoint over them
//! (seal), and the control plane signs the deployment bundle that enrols the
//! gateway (ops). The pack embeds that bundle, so the auditor verifies the
//! whole chain (ops key to bundle to origin key to records) holding nothing
//! but the two keys in `trusted-keys.json`.
//!
//! Every key is derived from a fixed seed: this is an example, not a
//! production setup where the sealing key lives in a KMS/HSM.

use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use obsign_audit_core::deployment::{DeploymentBundle, FORMAT as DEPLOYMENT_FORMAT};
use obsign_audit_core::evidence::{Evidence, FORMAT};
use obsign_audit_core::origin_signing_bytes;
use obsign_audit_core::record::*;
use obsign_audit_core::SignedRecord;
use obsign_audit_core::{content_hash, ChainWriter};
use ed25519_dalek::{Signer, SigningKey};
use std::path::PathBuf;

const KEY_ID: &str = "demo-2026-07";
const OPS_KEY_ID: &str = "ops-2026-07";
const CHAIN_ID: &str = "acme-prod-eu-west";

// Records are appended one by one, in scenario order: demo readability wins
// over concision here.
#[allow(clippy::vec_init_then_push)]
fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/demo".into())
        .into();
    std::fs::create_dir_all(&out).expect("creating the output directory");

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = PublicKeyEntry {
        key_id: KEY_ID.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        role: KeyRole::Seal,
    };

    // The gateway's own key. Its id follows the convention the gateway prints
    // at startup, `origin-<first 16 hex chars of the public key>`, so the
    // sample looks like something you could paste from a real deployment.
    let gw_key = SigningKey::from_bytes(&[11u8; 32]);
    let gw_public = hex::encode(gw_key.verifying_key().to_bytes());
    let gw_key_id = format!("origin-{}", &gw_public[..16]);
    let gw_pubkey = PublicKeyEntry {
        key_id: gw_key_id.clone(),
        algo: "ed25519".to_string(),
        public_key: gw_public,
        role: KeyRole::Origin,
    };

    // The control plane's key: it signs the bundle enrolling the gateway, and
    // nothing the auditor verifies directly, hence role `ops`, which admits
    // it to neither the sealing nor the origin set.
    let ops_key = SigningKey::from_bytes(&[13u8; 32]);
    let ops_pubkey = PublicKeyEntry {
        key_id: OPS_KEY_ID.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(ops_key.verifying_key().to_bytes()),
        role: KeyRole::Ops,
    };

    // Fixed clock: a reproducible example diffs cleanly.
    let t0: i64 = 1_785_312_000_000;
    let session = "sess-9f4c21";

    let mut chain = ChainWriter::new(CHAIN_ID);
    let mut records = Vec::new();

    // 1. A human delegates to the agent, for 30 minutes, a bounded scope.
    records.push(chain.append(
        t0,
        "deleg-1",
        None,
        session,
        Payload::Delegation(Delegation {
            principal_sub: "u:marie.dupont".into(),
            principal_issuer: "https://sso.acme.fr/realms/corp".into(),
            scopes: vec!["support:read".into(), "support:ticket_update".into()],
            expires_at_ms: t0 + 30 * 60 * 1000,
            approved_by: None,
            approval_mode: ApprovalMode::Implicit,
        }),
    ));

    // 2. The agent starts under that delegation.
    records.push(chain.append(
        t0 + 120,
        "agent-1",
        Some("deleg-1".into()),
        session,
        Payload::AgentSession(AgentSession {
            agent_id: "support-copilot".into(),
            agent_version: "2.4.1".into(),
            config_hash: content_hash(b"system=support v2.4.1;tools=[search,sql_query]"),
        }),
    ));

    // 3. The model turn: the context that produced the attempt.
    records.push(chain.append(
        t0 + 3_400,
        "turn-1",
        Some("agent-1".into()),
        session,
        Payload::LlmTurn(LlmTurn {
            provider: "anthropic".into(),
            model: "claude-sonnet-5".into(),
            prompt_hash: content_hash(b"the customer requests deletion of their data"),
            response_hash: content_hash(b"calling delete_production_db"),
            input_tokens: Some(2_310),
            output_tokens: Some(88),
            cost_micros: Some(14_200),
        }),
    ));

    // 4. The attempted act.
    records.push(chain.append(
        t0 + 3_450,
        "call-1",
        Some("turn-1".into()),
        session,
        Payload::ToolCall(ToolCall {
            server: "mcp://db-ops.internal".into(),
            tool: "delete_production_db".into(),
            args_hash: content_hash(br#"{"database":"customers","confirm":true}"#),
            // The hash, and nothing else. No component retains arguments, so
            // a sample carrying a `SealedRef` would advertise a capability
            // the gateway cannot produce, see `ToolCall::args_sealed`.
            args_sealed: None,
        }),
    ));

    // 5. The policy decides. This is the record the CISO wants to see.
    records.push(chain.append(
        t0 + 3_452,
        "dec-1",
        Some("call-1".into()),
        session,
        Payload::Decision(Decision {
            outcome: Outcome::Deny,
            policy_id: Some("forbid_destructive_prod".into()),
            bundle_version: "policies@a3f19c2".into(),
            reason: Some(
                "destructive tool in production, outside the delegation scope".into(),
            ),
        }),
    ));

    // 6. The effect: blocked. The call never reached the database.
    records.push(chain.append(
        t0 + 3_453,
        "eff-1",
        Some("dec-1".into()),
        session,
        Payload::Effect(Effect {
            status: EffectStatus::Blocked,
            result_hash: None,
            latency_ms: 3,
        }),
    ));

    // 7. The agent falls back to an allowed tool: business as usual.
    records.push(chain.append(
        t0 + 5_100,
        "call-2",
        Some("turn-1".into()),
        session,
        Payload::ToolCall(ToolCall {
            server: "mcp://crm.internal".into(),
            tool: "ticket_update".into(),
            args_hash: content_hash(br#"{"ticket":"T-8821","status":"escalated"}"#),
            args_sealed: None,
        }),
    ));
    records.push(chain.append(
        t0 + 5_101,
        "dec-2",
        Some("call-2".into()),
        session,
        Payload::Decision(Decision {
            outcome: Outcome::Allow,
            policy_id: Some("allow_support_scope".into()),
            bundle_version: "policies@a3f19c2".into(),
            reason: None,
        }),
    ));
    records.push(chain.append(
        t0 + 5_240,
        "eff-2",
        Some("dec-2".into()),
        session,
        Payload::Effect(Effect {
            status: EffectStatus::Ok,
            result_hash: Some(content_hash(br#"{"ok":true}"#)),
            latency_ms: 139,
        }),
    ));

    // Each record is signed as it is written, by the gateway that wrote it.
    // This is what `--allow-unsigned-legacy-chains` exists to tolerate the
    // absence of; a sample that skipped it would demo the exception.
    let records: Vec<SignedRecord> = records
        .into_iter()
        .map(|rec| {
            let msg = origin_signing_bytes(CHAIN_ID, &rec.hash());
            SignedRecord::signed(rec, &gw_key_id, gw_key.sign(&msg).to_bytes())
        })
        .collect();

    // Seal the whole batch.
    let cp = chain.seal(t0 + 60_000, KEY_ID).expect("non-empty batch");
    let signed = cp.sign(&key);

    // The ops-signed bundle that enrols the gateway. Embedding it is what
    // lets the auditor start from the ops key alone instead of being handed a
    // list of origin keys to trust on someone's word.
    let deployment = DeploymentBundle {
        format: DEPLOYMENT_FORMAT.to_string(),
        version: "deployment@8f21ac4".to_string(),
        origin_keys: vec![gw_pubkey],
        attestations: Vec::new(),
    }
    .sign(OPS_KEY_ID, &ops_key);

    let ev = Evidence {
        format: FORMAT.to_string(),
        chain_id: CHAIN_ID.to_string(),
        records,
        checkpoints: vec![signed],
        keys: vec![pubkey.clone(), ops_pubkey.clone()],
        anchors: Vec::new(),
        deployment: Some(deployment),
    };

    let ev_path = out.join("evidence.json");
    let keys_path = out.join("trusted-keys.json");

    std::fs::write(&ev_path, serde_json::to_string_pretty(&ev).unwrap()).unwrap();
    // Seal + ops only. The origin key is deliberately absent: it rides the
    // bundle, and the ops key is what proves the bundle. Two keys out of
    // band, however many gateways the deployment grows to.
    std::fs::write(
        &keys_path,
        serde_json::to_string_pretty(&vec![pubkey, ops_pubkey]).unwrap(),
    )
    .unwrap();

    println!("evidence pack : {}", ev_path.display());
    println!("trusted keys  : {}", keys_path.display());
    println!();
    println!("  obsign verify {} --trusted-keys {}", ev_path.display(), keys_path.display());
}
