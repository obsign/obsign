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
    Decision as DecisionRec, Effect, EffectStatus, McpAccess, Outcome, Payload, ToolCall,
};
use crate::auth::Auth;
use policy::{Capability, Engine, ToolRequest};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The wrapped server, as named in records and policy requests.
const SERVER: &str = "mcp://encapsule";

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

/// An inbound message the gateway arbitrates: identity verified, policy
/// evaluated, act recorded, then forwarded or refused.
///
/// Two shapes because refusals answer differently: a tool failure is an
/// `isError` *result* by MCP convention, while `resources/*` and `prompts/*`
/// fail with a JSON-RPC *error* — an `isError` result there would be
/// mistaken for resource content.
enum Act {
    Tool {
        tool: String,
    },
    Capability {
        cap: Capability,
        method: String,
        /// Resource URI or prompt name.
        target: String,
    },
}

impl Act {
    /// What the stderr lines and refusal messages call this act.
    fn label(&self) -> String {
        match self {
            Act::Tool { tool } => tool.clone(),
            Act::Capability { method, target, .. } => format!("{method} {target}"),
        }
    }
}

/// True when `handle_from_agent` arbitrates this method — and therefore
/// presents the bearer itself. The HTTP transport consults this to avoid
/// presenting the same token twice.
pub(crate) fn arbitrated(method: Option<&str>) -> bool {
    matches!(
        method,
        Some(
            "tools/call"
                | "resources/read"
                | "resources/subscribe"
                | "resources/unsubscribe"
                | "prompts/get"
        )
    )
}

/// The policy request for one act, under the delegation in force.
fn request(
    deleg: &identity::Delegation,
    ctx: &Ctx,
    session_id: &str,
    tool: String,
) -> ToolRequest {
    ToolRequest {
        principal: deleg.subject.clone(),
        groups: deleg.groups.clone(),
        scopes: deleg.scopes.clone(),
        server: SERVER.to_string(),
        tool,
        env: ctx.env.clone(),
        session_id: session_id.to_string(),
        actor_chain: deleg.actor_chain.clone(),
        has_human_delegation: deleg.has_human(),
        delegation_depth: deleg.delegation_depth() as u32,
        principal_kind: deleg.kind.as_str().to_string(),
    }
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

    let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    // What gets arbitrated: the acts that move data — a tool call, a
    // resource read or subscription, a prompt fetch. Discovery
    // (`tools/list`, `resources/list`, `prompts/list`) is filtered on the
    // response path instead; protocol machinery (initialize, notifications,
    // completions) passes untouched. Keep `arbitrated()` in sync with this
    // match.
    let target_of = |field: &str| {
        params
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let act = match method {
        "tools/call" => Act::Tool {
            tool: target_of("name"),
        },
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
            Act::Capability {
                cap: Capability::ResourceRead,
                method: method.to_string(),
                target: target_of("uri"),
            }
        }
        "prompts/get" => Act::Capability {
            cap: Capability::PromptGet,
            method: method.to_string(),
            target: target_of("name"),
        },
        _ => return Ok(Forward::Pass(raw)),
    };

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
        None => match &act {
            Act::Tool { tool } => ctx
                .engine
                .evaluate(&request(&deleg, ctx, &s.session_id, tool.clone())),
            Act::Capability { cap, target, .. } => ctx
                .engine
                .evaluate_capability(*cap, &request(&deleg, ctx, &s.session_id, target.clone())),
        },
    };

    let call_id = s.next_call_id();
    let parent = s.agent_record_id.clone();

    // The attempted act is recorded before the verdict: a refused attempt
    // is still an attempt, and often the one the CISO cares about.
    let payload = match &act {
        Act::Tool { tool } => Payload::ToolCall(ToolCall {
            server: SERVER.to_string(),
            tool: tool.clone(),
            args_hash: content_hash(
                params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}))
                    .to_string()
                    .as_bytes(),
            ),
            args_sealed: None,
        }),
        Act::Capability { method, target, .. } => Payload::McpAccess(McpAccess {
            server: SERVER.to_string(),
            method: method.clone(),
            target: target.clone(),
            params_hash: content_hash(params.to_string().as_bytes()),
        }),
    };
    s.write(call_id.clone(), Some(parent), payload)?;

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
                "[probant] DEGRADED {}: {}",
                act.label(),
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
                        "[probant] REFUSED {}: JSON-RPC id {id} is already in flight",
                        act.label()
                    );
                    return Ok(Forward::Reply(refusal_reply(
                        &act,
                        &id,
                        &format!(
                            "Call refused: JSON-RPC id {id} is already \
                             awaiting a response on this session"
                        ),
                    )));
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
    eprintln!("[probant] REFUSED {}: {reason}", act.label());

    Ok(Forward::Reply(refusal_reply(
        &act,
        &id,
        &format!("Call refused by policy {}: {}", ctx.bundle_version, reason),
    )))
}

/// The refusal the agent sees, shaped per act.
///
/// MCP convention: a tool failure is signalled by an `isError` result, not a
/// JSON-RPC error — the agent receives it as a tool return and can fall back
/// to something else, instead of treating the session as broken. Resource
/// and prompt requests have no such envelope: there a refusal is a JSON-RPC
/// error (server-defined code), since a fabricated `contents` would be
/// indistinguishable from the resource itself.
fn refusal_reply(act: &Act, id: &Value, text: &str) -> String {
    match act {
        Act::Tool { .. } => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": text }],
                "isError": true
            }
        }),
        Act::Capability { .. } => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": text }
        }),
    }
    .to_string()
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

    // Filtering discovery: the agent only sees what it can access. Applies
    // to tools/list, resources/list and prompts/list alike.
    //
    // More than a convenience: a tool an agent cannot see is a tool it will
    // not attempt — that many fewer refusals to handle, and that much less
    // surface offered to a prompt injection. (Resource *templates* are not
    // filtered: a template is a pattern, not a readable target; whatever URI
    // it expands to is arbitrated at read time.)
    //
    // Each listing names its items differently, and each item kind is
    // arbitrated by its own path: tools against the signed catalogue,
    // resources and prompts against the capability actions.
    type Listing<'a> = (
        &'a str,
        &'a str,
        &'a str,
        &'a dyn Fn(&str, &identity::Delegation) -> bool,
    );
    let listings: [Listing; 3] = [
        ("/result/tools", "name", "tools/list", &|name, deleg| {
            ctx.engine
                .evaluate(&request(deleg, ctx, session_id, name.to_string()))
                .is_allowed()
        }),
        ("/result/resources", "uri", "resources/list", &|uri, deleg| {
            ctx.engine
                .evaluate_capability(
                    Capability::ResourceRead,
                    &request(deleg, ctx, session_id, uri.to_string()),
                )
                .is_allowed()
        }),
        ("/result/prompts", "name", "prompts/list", &|name, deleg| {
            ctx.engine
                .evaluate_capability(
                    Capability::PromptGet,
                    &request(deleg, ctx, session_id, name.to_string()),
                )
                .is_allowed()
        }),
    ];

    for (pointer, id_field, label, allows) in listings {
        let Some(items) = msg.pointer(pointer).and_then(Value::as_array) else {
            continue;
        };
        let deleg = ctx.auth.lock().unwrap().delegation().clone();
        let expired = deleg.is_expired(now_ms());

        let mut kept = Vec::new();
        let mut removed = Vec::new();

        for item in items {
            let name = item.get(id_field).and_then(Value::as_str).unwrap_or_default();
            // Expired delegation: nothing is accessible any more, so nothing
            // is shown. Consistent with what the request path will do.
            if !expired && allows(name, &deleg) {
                kept.push(item.clone());
            } else {
                removed.push(name.to_string());
            }
        }

        if !removed.is_empty() {
            eprintln!(
                "[probant] {label}: {} hidden — {}",
                removed.len(),
                removed.join(", ")
            );
        }

        let mut filtered = msg.clone();
        if let Some(slot) = filtered.pointer_mut(pointer) {
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

    fn ctx_with(cedar: &str) -> Ctx {
        let bundle = Bundle {
            format: FORMAT.to_string(),
            version: "policies@test".to_string(),
            cedar: cedar.to_string(),
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

    fn ctx() -> Ctx {
        ctx_with(
            "@id(\"allow_all\")\n\
             permit (principal, action == Action::\"tool_call\", resource);\n",
        )
    }

    fn open_state(tag: &str) -> (std::path::PathBuf, Arc<Mutex<session::Session>>) {
        let dir = std::env::temp_dir().join(format!("probant-gw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (wal, chain) = Wal::open(&dir, "t").unwrap();
        (dir, Arc::new(Mutex::new(session::open(chain, wal, "sess".into(), None))))
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

    #[test]
    fn a_resource_read_nobody_permitted_is_refused_and_recorded() {
        // The scope gap this closes: resources/* used to pass through with
        // neither policy nor record — a read channel invisible to the proof.
        let (dir, state) = open_state("resource-deny");
        let ctx = ctx(); // permits tool_call only: capabilities stay refused

        let call = json!({
            "jsonrpc": "2.0", "id": 1, "method": "resources/read",
            "params": { "uri": "db://prod/customers" }
        });
        match handle_from_agent(call, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => {
                let v: Value = serde_json::from_str(&r).unwrap();
                // A refused resource is a JSON-RPC error, not an isError
                // result: fabricated contents would read as the resource.
                assert!(v.get("error").is_some(), "must refuse as a JSON-RPC error: {r}");
                assert!(r.contains("refused by policy") || r.contains("no rule"));
            }
            Forward::Pass(_) => panic!("an unpermitted resource read must not be forwarded"),
        }

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let access = recs
            .iter()
            .find_map(|r| match &r.payload {
                Payload::McpAccess(a) => Some(a.clone()),
                _ => None,
            })
            .expect("the attempt must be recorded even though it was refused");
        assert_eq!(access.method, "resources/read");
        assert_eq!(access.target, "db://prod/customers");
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Effect(e) if e.status == EffectStatus::Blocked
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_permitted_resource_read_is_forwarded_and_its_effect_recorded() {
        let (dir, state) = open_state("resource-allow");
        let ctx = ctx_with(
            "@id(\"allow_runbook\")\n\
             permit (principal, action == Action::\"resource_read\",\n\
                     resource == Resource::\"docs://runbook\");\n",
        );

        let call = json!({
            "jsonrpc": "2.0", "id": 3, "method": "resources/read",
            "params": { "uri": "docs://runbook" }
        });
        let fwd = handle_from_agent(call, &state, &ctx, None).unwrap();
        assert!(matches!(fwd, Forward::Pass(_)), "a permitted read must be forwarded");

        // The server answers: the effect closes with the result's hash.
        let resp = json!({ "jsonrpc": "2.0", "id": 3, "result": { "contents": [] } });
        handle_from_server(resp, &state, &ctx, "sess");

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Decision(d) if d.outcome == Outcome::Allow
                && d.policy_id.as_deref() == Some("allow_runbook")
        )));
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Effect(e) if e.status == EffectStatus::Ok && e.result_hash.is_some()
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_prompt_fetch_is_arbitrated_like_a_resource() {
        let (dir, state) = open_state("prompt");
        let ctx = ctx_with(
            "@id(\"allow_summarize\")\n\
             permit (principal, action == Action::\"prompt_get\",\n\
                     resource == Prompt::\"summarize\");\n",
        );

        let allowed = json!({
            "jsonrpc": "2.0", "id": 1, "method": "prompts/get",
            "params": { "name": "summarize" }
        });
        assert!(matches!(
            handle_from_agent(allowed, &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));

        let refused = json!({
            "jsonrpc": "2.0", "id": 2, "method": "prompts/get",
            "params": { "name": "exfiltrate" }
        });
        match handle_from_agent(refused, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => assert!(r.contains("\"error\"")),
            Forward::Pass(_) => panic!("an unpermitted prompt must not be forwarded"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resource_and_prompt_listings_are_filtered_like_tools() {
        let (dir, state) = open_state("listing");
        let ctx = ctx_with(
            "@id(\"allow_docs\")\n\
             permit (principal, action == Action::\"resource_read\", resource)\n\
             when { context.target like \"docs://*\" };\n",
        );

        let listing = json!({
            "jsonrpc": "2.0", "id": 9, "result": { "resources": [
                { "uri": "docs://runbook", "name": "Runbook" },
                { "uri": "db://prod/customers", "name": "Customer dump" }
            ]}
        });
        let out = handle_from_server(listing, &state, &ctx, "sess");
        let uris: Vec<&str> = out
            .pointer("/result/resources")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|r| r.get("uri").and_then(Value::as_str))
            .collect();
        assert_eq!(uris, vec!["docs://runbook"], "what you cannot read, you do not see");

        // No permit for prompts: the listing empties out entirely.
        let prompts = json!({
            "jsonrpc": "2.0", "id": 10, "result": { "prompts": [
                { "name": "summarize" }
            ]}
        });
        let out = handle_from_server(prompts, &state, &ctx, "sess");
        assert_eq!(
            out.pointer("/result/prompts").and_then(Value::as_array).unwrap().len(),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
