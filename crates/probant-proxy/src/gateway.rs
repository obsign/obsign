//! The gateway's transport-independent half.
//!
//! Both transports — stdio and Streamable HTTP — funnel every message through
//! the two functions here. This is deliberate: arbitration and audit must not
//! depend on how the bytes travelled. A call refused and recorded over stdio
//! must be refused and recorded identically over HTTP, or the log's meaning
//! starts depending on deployment topology.

use crate::session::{self, now_ms, Pending};
use anyhow::{Context as _, Result};
use audit_core::content_hash;
use audit_core::record::{
    Decision as DecisionRec, Effect, EffectStatus, Outcome, Payload, ToolCall,
};
use crate::auth::Auth;
use policy::{Engine, ToolRequest};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Immutable context shared by both directions of the proxy.
pub(crate) struct Ctx {
    pub(crate) engine: Arc<Engine>,
    pub(crate) auth: Arc<Mutex<Auth>>,
    pub(crate) env: String,
    pub(crate) agent_id: String,
    pub(crate) bundle_version: String,
}

pub(crate) enum Forward {
    /// Forward to the MCP server.
    Pass(String),
    /// Answer the agent directly, without forwarding.
    Reply(String),
}

pub(crate) fn spawn_server(cmd: &[String]) -> Result<Child> {
    let (prog, args) = cmd.split_first().expect("non-empty command");
    Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Server stderr is not captured: it goes straight to the terminal,
        // where it stays diagnosable.
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning MCP server \"{prog}\""))
}

pub(crate) fn handle_from_agent(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
    bearer: Option<&str>,
) -> Result<Forward> {
    let raw = msg.to_string();

    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(Forward::Pass(raw));
    }

    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let tool = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let id = msg.get("id").cloned().unwrap_or(Value::Null);

    // --- Identity in force at this instant ---------------------------------
    //
    // Re-evaluated on every act. An agent session routinely outlives a token;
    // checking once at startup amounts to drawing unlimited authority from a
    // 30-minute token. Over stdio the fresh token is re-read from a file;
    // over HTTP it arrives with the request.
    //
    // The session lock comes *first* and stays held through the writes below:
    // the identity snapshot and the attribution parent (`agent_record_id`)
    // must be one atomic step. Released between the two, a concurrent request
    // on the same session presenting a different token records its delegation
    // and moves `agent_record_id` in the gap — and this call, whose token did
    // not change, attaches under the other principal's subtree. Lock order is
    // session then auth, everywhere: auth is only ever taken alone or nested
    // inside the session lock, never the other way around.
    let now = now_ms();
    let mut s = state.lock().unwrap();
    let (deleg, generation, renewed, reloads, auth_error) = {
        let mut a = ctx.auth.lock().unwrap();
        let outcome = match bearer {
            Some(token) => a.present(token, now),
            None => a.refresh(now),
        };
        // Drained whatever the outcome: a reload rejected while refusing this
        // token is exactly the event the log must keep.
        let reloads = a.take_reloads();
        match outcome {
            Ok(renewed) => (a.delegation().clone(), a.generation(), renewed, reloads, None),
            Err(e) => (a.delegation().clone(), a.generation(), false, reloads, Some(e)),
        }
    };

    // Reloads precede the delegation they may have enabled: the new bundle
    // was in force before the token it validated was accepted.
    session::record_config_reloads(&mut s, reloads)?;

    // Token renewed: a new delegation goes into the log, and subsequent
    // calls attach to it. Without this, an act performed under a renewed
    // token would appear authorized by an already-expired delegation.
    if renewed {
        session::record_delegation(
            &mut s,
            generation,
            &deleg,
            &ctx.agent_id,
            &ctx.bundle_version,
        )?;
        eprintln!(
            "[probant] delegation renewed (generation {generation}) — {} — expires in {} s",
            deleg.subject,
            deleg.remaining_secs(now)
        );
    }

    // --- Verdict ------------------------------------------------------------
    let verdict = match &auth_error {
        // Missing authority: it is not the policy that forbids, it is the
        // delegation that is no longer valid. The log must tell the two
        // apart, hence the absent policy_id.
        Some(e) => policy::Verdict {
            outcome: Outcome::Deny,
            policy_id: None,
            reason: Some(e.to_string()),
        },
        None => ctx.engine.evaluate(&ToolRequest {
            principal: deleg.subject.clone(),
            groups: deleg.groups.clone(),
            scopes: deleg.scopes.clone(),
            server: "mcp://encapsule".to_string(),
            tool: tool.clone(),
            env: ctx.env.clone(),
            session_id: s.session_id.clone(),
            actor_chain: deleg.actor_chain.clone(),
            has_human_delegation: deleg.has_human(),
            delegation_depth: deleg.delegation_depth() as u32,
            principal_kind: deleg.kind.as_str().to_string(),
        }),
    };

    let call_id = s.next_call_id();
    let parent = s.agent_record_id.clone();

    // The attempted call is recorded before the verdict: a refused attempt
    // is still an attempt, and often the one the CISO cares about.
    s.write(
        call_id.clone(),
        Some(parent),
        Payload::ToolCall(ToolCall {
            server: "mcp://encapsule".to_string(),
            tool: tool.clone(),
            args_hash: content_hash(args.to_string().as_bytes()),
            args_sealed: None,
        }),
    )?;

    // Identifiers derived from the same counter as the call: dec-N and eff-N
    // unambiguously belong to call-N, whatever order the responses come back
    // in.
    let decision_id = format!("dec-{}", s.counter);
    let effect_id = format!("eff-{}", s.counter);
    s.write(
        decision_id.clone(),
        Some(call_id),
        Payload::Decision(DecisionRec {
            outcome: verdict.outcome,
            policy_id: verdict.policy_id.clone(),
            bundle_version: ctx.bundle_version.clone(),
            reason: verdict.reason.clone(),
        }),
    )?;

    if verdict.is_allowed() {
        if verdict.outcome == Outcome::AllowFailOpen {
            eprintln!(
                "[probant] DEGRADED {tool}: {}",
                verdict.reason.clone().unwrap_or_default()
            );
        }
        if !id.is_null() {
            match s.pending.entry(id.to_string()) {
                // The agent reused a JSON-RPC id while its first call is
                // still in flight. Overwriting the slot would leave two
                // forwarded calls waiting on one id: whichever response
                // arrives first would close the wrong Effect record and the
                // displaced one would never be written. The in-flight call
                // keeps its slot; this one is refused, with its own Effect,
                // so every recorded call still ends in exactly one effect.
                std::collections::hash_map::Entry::Occupied(_) => {
                    s.write(
                        effect_id,
                        Some(decision_id),
                        Payload::Effect(Effect {
                            status: EffectStatus::Blocked,
                            result_hash: None,
                            latency_ms: 0,
                        }),
                    )?;
                    drop(s);
                    eprintln!(
                        "[probant] REFUSED {tool}: JSON-RPC id {id} is already in flight"
                    );
                    return Ok(Forward::Reply(
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": format!(
                                        "Call refused: JSON-RPC id {id} is already \
                                         awaiting a response on this session"
                                    )
                                }],
                                "isError": true
                            }
                        })
                        .to_string(),
                    ));
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(Pending {
                        decision_record_id: decision_id,
                        effect_record_id: effect_id,
                        started: Instant::now(),
                    });
                }
            }
        }
        return Ok(Forward::Pass(raw));
    }

    // Refusal: the effect is immediate and final.
    s.write(
        effect_id,
        Some(decision_id),
        Payload::Effect(Effect {
            status: EffectStatus::Blocked,
            result_hash: None,
            latency_ms: 0,
        }),
    )?;
    drop(s);

    let reason = verdict
        .reason
        .unwrap_or_else(|| "refused by policy".to_string());
    eprintln!("[probant] REFUSED {tool}: {reason}");

    // MCP convention: a tool failure is signalled by an `isError` result,
    // not by a JSON-RPC error. The agent receives it as a tool return and can
    // fall back to something else, instead of treating the session as
    // broken.
    Ok(Forward::Reply(
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Call refused by policy {}: {}",
                        ctx.bundle_version, reason
                    )
                }],
                "isError": true
            }
        })
        .to_string(),
    ))
}

pub(crate) fn handle_from_server(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
    session_id: &str,
) -> Value {
    // Response to an allowed call: we record what actually happened, not
    // what was requested.
    if let Some(key) = msg.get("id").map(|v| v.to_string()) {
        let pending = state.lock().unwrap().pending.remove(&key);
        if let Some(p) = pending {
            let result = msg.get("result");
            let is_error = msg.get("error").is_some()
                || result
                    .and_then(|r| r.get("isError"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

            let mut s = state.lock().unwrap();
            let _ = s.write(
                p.effect_record_id,
                Some(p.decision_record_id),
                Payload::Effect(Effect {
                    status: if is_error {
                        EffectStatus::Error
                    } else {
                        EffectStatus::Ok
                    },
                    result_hash: result.map(|r| content_hash(r.to_string().as_bytes())),
                    latency_ms: p.started.elapsed().as_millis() as u64,
                }),
            );
        }
    }

    // Filtering tools/list: the agent only discovers what it can call.
    //
    // More than a convenience: a tool an agent cannot see is a tool it will
    // not attempt — that many fewer refusals to handle, and that much less
    // surface offered to a prompt injection.
    if let Some(tools) = msg.pointer("/result/tools").and_then(Value::as_array) {
        let deleg = ctx.auth.lock().unwrap().delegation().clone();
        let expired = deleg.is_expired(now_ms());

        let mut kept = Vec::new();
        let mut removed = Vec::new();

        for t in tools {
            let name = t.get("name").and_then(Value::as_str).unwrap_or_default();
            // Expired delegation: nothing is callable any more, so nothing is
            // shown. Consistent with what `tools/call` will do.
            let allowed = !expired
                && ctx
                    .engine
                    .evaluate(&ToolRequest {
                        principal: deleg.subject.clone(),
                        groups: deleg.groups.clone(),
                        scopes: deleg.scopes.clone(),
                        server: "mcp://encapsule".to_string(),
                        tool: name.to_string(),
                        env: ctx.env.clone(),
                        session_id: session_id.to_string(),
                        actor_chain: deleg.actor_chain.clone(),
                        has_human_delegation: deleg.has_human(),
                        delegation_depth: deleg.delegation_depth() as u32,
                        principal_kind: deleg.kind.as_str().to_string(),
                    })
                    .is_allowed();

            if allowed {
                kept.push(t.clone());
            } else {
                removed.push(name.to_string());
            }
        }

        if !removed.is_empty() {
            eprintln!(
                "[probant] tools/list: {} hidden — {}",
                removed.len(),
                removed.join(", ")
            );
        }

        let mut filtered = msg.clone();
        if let Some(slot) = filtered.pointer_mut("/result/tools") {
            *slot = Value::Array(kept);
        }
        return filtered;
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Auth;
    use crate::session;
    use policy::bundle::{Bundle, FailBehaviour, FailMode, ToolDef, FORMAT};
    use wal::Wal;

    fn ctx() -> Ctx {
        let bundle = Bundle {
            format: FORMAT.to_string(),
            version: "policies@test".to_string(),
            cedar: "@id(\"allow_all\")\n\
                    permit (principal, action == Action::\"tool_call\", resource);\n"
                .to_string(),
            tools: vec![ToolDef {
                name: "search_docs".into(),
                server: "mcp://test".into(),
                destructive: false,
                required_scope: None,
            }],
            fail_mode: FailMode {
                default: FailBehaviour::Closed,
                tools: Default::default(),
            },
        };
        Ctx {
            engine: Arc::new(Engine::load(&bundle).unwrap()),
            auth: Arc::new(Mutex::new(Auth::declared("marie", Vec::new(), Vec::new()))),
            env: "prod".into(),
            agent_id: "agent-test".into(),
            bundle_version: "policies@test".into(),
        }
    }

    #[test]
    fn a_reused_in_flight_id_is_refused_and_no_effect_record_is_lost() {
        // Regression: `pending.insert` used to overwrite the slot when the
        // agent reused a JSON-RPC id, so the displaced call's Effect record
        // was never written — a forwarded act with no recorded outcome.
        let dir = std::env::temp_dir().join(format!(
            "probant-gw-id-collision-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let (wal, chain) = Wal::open(&dir, "t").unwrap();
        let state = Arc::new(Mutex::new(session::open(chain, wal, "sess".into(), None)));
        let ctx = ctx();

        let call = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "search_docs", "arguments": {} }
        });

        let first = handle_from_agent(call.clone(), &state, &ctx, None).unwrap();
        assert!(matches!(first, Forward::Pass(_)));

        let second = handle_from_agent(call, &state, &ctx, None).unwrap();
        match second {
            Forward::Reply(r) => {
                assert!(r.contains("isError"), "the agent must see a tool error");
                assert!(r.contains("already"), "the reason must name the collision");
            }
            Forward::Pass(_) => panic!("a colliding id must not be forwarded"),
        }

        // The in-flight call kept its slot and closes normally.
        let resp = json!({ "jsonrpc": "2.0", "id": 7, "result": { "content": [] } });
        handle_from_server(resp, &state, &ctx, "sess");

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let calls = recs
            .iter()
            .filter(|r| matches!(r.payload, Payload::ToolCall(_)))
            .count();
        let effects: Vec<&EffectStatus> = recs
            .iter()
            .filter_map(|r| match &r.payload {
                Payload::Effect(e) => Some(&e.status),
                _ => None,
            })
            .collect();
        assert_eq!(calls, 2);
        assert_eq!(
            effects.len(),
            2,
            "every recorded call must end in exactly one effect"
        );
        assert!(effects.contains(&&EffectStatus::Blocked));
        assert!(effects.contains(&&EffectStatus::Ok));

        let ids: std::collections::HashSet<&str> =
            recs.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), recs.len(), "record identifiers must stay unique");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
