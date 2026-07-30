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
/// Several shapes because refusals answer differently: a tool failure is an
/// `isError` *result* by MCP convention, while `resources/*` and `prompts/*`
/// fail with a JSON-RPC *error* — an `isError` result there would be
/// mistaken for resource content — and a method the gateway does not know
/// fails with the standard "method not found" code, which every client
/// already handles.
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
    /// A method neither arbitrated nor on the machinery allowlist: a vendor
    /// extension, a future protocol revision, a typo. Never forwarded —
    /// recorded, then refused. No policy can permit it: permitting would
    /// require knowing what it does, and nobody here does.
    OutOfScope {
        method: String,
    },
}

impl Act {
    /// What the stderr lines and refusal messages call this act.
    fn label(&self) -> String {
        match self {
            Act::Tool { tool } => tool.clone(),
            Act::Capability { method, target, .. } => format!("{method} {target}"),
            Act::OutOfScope { method } => method.clone(),
        }
    }
}

/// Protocol machinery forwarded without arbitration: discovery (filtered on
/// the response path), lifecycle, liveness, log level. An explicit
/// allowlist — the method space is default-deny. Default-forward would mean
/// one server update, or one agent speaking a vendor dialect, opens a data
/// channel no policy ever saw and no record ever named.
///
/// Conscious exemption: what this allowlist relays is neither arbitrated nor
/// recorded, and two of these notifications carry free text —
/// `notifications/cancelled` (`reason`) and `notifications/progress`
/// (`message`). An agent can push text to a complicit server outside the
/// log. Accepted for now as liveness/UX machinery on a hot path; the mirror
/// exemption and the gating exit are on `server_notification`, the debt
/// entry in the README ("Allowlisted notifications…").
fn machinery(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "resources/list"
            | "resources/templates/list"
            | "prompts/list"
            | "logging/setLevel"
            | "notifications/initialized"
            | "notifications/cancelled"
            | "notifications/progress"
            | "notifications/roots/list_changed"
    )
}

/// True when `handle_from_agent` arbitrates this method — and therefore
/// presents the bearer itself. The HTTP transport consults this to avoid
/// presenting the same token twice.
///
/// The complement of `machinery`: whatever is not machinery is arbitrated,
/// including methods the gateway has never heard of. `None` — a response,
/// not a request — is not arbitrated: the act it answers already was.
pub(crate) fn arbitrated(method: Option<&str>) -> bool {
    match method {
        None => false,
        Some(m) => !machinery(m),
    }
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

    // No method: a *response* — the agent answering a server-initiated
    // request. Only two kinds are legitimate: the answer to an arbitrated
    // request (sampling, elicitation — closes the recorded effect, with the
    // hash of what actually crossed back) and the answer to relayed
    // machinery (ping, roots/list — passes like the request did). Anything
    // else is an arbitrary payload aimed at the server wearing a response's
    // shape, exactly the channel default-deny exists for: recorded, then
    // refused, never forwarded. A `method` that exists but is not a string
    // is not a response either — it flows into the out-of-scope refusal.
    let method: String = match msg.get("method") {
        Some(Value::String(m)) => m.clone(),
        Some(_) => "(non-string method)".to_string(),
        None => {
            let mut s = state.lock().unwrap();
            if let Some(id) = msg.get("id").filter(|v| !v.is_null()) {
                let key = id.to_string();
                if let Some(p) = s.pending_to_agent.remove(&key) {
                    let result = msg.get("result");
                    let is_error = msg.get("error").is_some();
                    let _ = s.write(
                        p.effect_record_id,
                        Some(p.decision_record_id),
                        Payload::Effect(Effect {
                            status: if is_error {
                                EffectStatus::Error
                            } else {
                                EffectStatus::Ok
                            },
                            result_hash: result
                                .map(|r| content_hash(r.to_string().as_bytes())),
                            latency_ms: p.started.elapsed().as_millis() as u64,
                        }),
                    );
                    return Ok(Forward::Pass(raw));
                }
                if s.relayed_to_agent.remove(&key) {
                    return Ok(Forward::Pass(raw));
                }
            }

            // Unsolicited. The record is written before the refusal, and a
            // WAL failure refuses too — the `?` propagates like any act's.
            let call_id = s.next_call_id();
            let parent = s.agent_record_id.clone();
            let decision_id = format!("dec-{}", s.counter);
            let effect_id = format!("eff-{}", s.counter);
            s.write(
                call_id.clone(),
                Some(parent),
                Payload::McpAccess(McpAccess {
                    server: SERVER.to_string(),
                    method: "(unsolicited response)".to_string(),
                    target: SERVER.to_string(),
                    params_hash: content_hash(raw.as_bytes()),
                }),
            )?;
            s.write(
                decision_id.clone(),
                Some(call_id),
                Payload::Decision(DecisionRec {
                    outcome: Outcome::Deny,
                    policy_id: None,
                    bundle_version: ctx.bundle_version.clone(),
                    reason: Some(
                        "response matches no in-flight server request (default-deny)"
                            .to_string(),
                    ),
                }),
            )?;
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
            eprintln!("[obsign] REFUSED unsolicited response-shaped message");
            return Ok(Forward::Reply(
                json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: response matches no in-flight \
                                    server request"
                    }
                })
                .to_string(),
            ));
        }
    };
    let method = method.as_str();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    // What gets arbitrated: the acts that move data — a tool call, a
    // resource read or subscription, a prompt fetch, a completion.
    // Discovery (`tools/list`, `resources/list`, `prompts/list`) is
    // filtered on the response path instead; the machinery allowlist
    // passes untouched; everything else is out of scope and refused.
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
        // A completion enumerates the values of the object it references:
        // argument values for a prompt, expansions for a resource template.
        // Left unarbitrated it walks around the `resources/list` filter —
        // what the listing hides, the completer spells out. It is therefore
        // held to the permission of the object itself: complete only what
        // you could read. A ref of any other shape names an object this
        // gateway cannot arbitrate, so it falls out of scope.
        "completion/complete" => {
            let reference = params.get("ref");
            let ref_of = |field: &str| {
                reference
                    .and_then(|r| r.get(field))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            match reference
                .and_then(|r| r.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "ref/prompt" => Act::Capability {
                    cap: Capability::PromptGet,
                    method: method.to_string(),
                    target: ref_of("name"),
                },
                "ref/resource" => Act::Capability {
                    cap: Capability::ResourceRead,
                    method: method.to_string(),
                    target: ref_of("uri"),
                },
                _ => Act::OutOfScope {
                    method: method.to_string(),
                },
            }
        }
        m if machinery(m) => return Ok(Forward::Pass(raw)),
        other => Act::OutOfScope {
            method: other.to_string(),
        },
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
            "[obsign] delegation renewed (generation {generation}) — {} — expires in {} s",
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
            // Not a policy decision: the engine is never consulted, because
            // there is nothing it could meaningfully permit. The absent
            // policy_id is what tells the log this refusal came from the
            // gateway's scope, not from a rule.
            Act::OutOfScope { .. } => policy::Verdict {
                outcome: Outcome::Deny,
                policy_id: None,
                reason: Some(
                    "method outside the arbitrated MCP surface (default-deny)".to_string(),
                ),
            },
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
        Act::OutOfScope { method } => Payload::McpAccess(McpAccess {
            server: SERVER.to_string(),
            method: method.clone(),
            // No target: the gateway does not know how to read one out of a
            // method it does not know. The params hash still pins what was
            // asked.
            target: String::new(),
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
                "[obsign] DEGRADED {}: {}",
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
                        "[obsign] REFUSED {}: JSON-RPC id {id} is already in flight",
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
    eprintln!("[obsign] REFUSED {}: {reason}", act.label());

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
/// indistinguishable from the resource itself. An out-of-scope method
/// answers -32601 — "method not found" — which is the truth as the agent
/// should understand it: through this gateway, the method does not exist.
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
        Act::OutOfScope { .. } => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": text }
        }),
    }
    .to_string()
}

/// What becomes of a message read from the wrapped server.
pub(crate) enum Downstream {
    /// Deliver to the agent (responses possibly filtered).
    Forward(Value),
    /// Answer the *server* in the gateway's place; nothing reaches the agent.
    Reply(Value),
    /// Neither deliverable nor answerable — a refused notification. The
    /// record is already written; the message itself goes nowhere.
    Drop,
}

/// Server-initiated notifications the gateway relays. The same default-deny
/// posture as the agent-side method space: a notification the protocol does
/// not define is dropped and recorded, not forwarded into the agent's
/// context.
///
/// Conscious exemption, mirror of `machinery`: what passes here is neither
/// arbitrated nor recorded, and `notifications/message` is arbitrary `data`
/// at any log level, delivered straight into the agent's context. A
/// complicit server can spell out the very names the listing filter hides,
/// or feed the agent text no record names; with `machinery`'s free-text
/// fields the channel is bidirectional. Accepted for now — these are
/// liveness/UX machinery, and arbitrating every progress tick would put a
/// policy decision and an fsync on an unbounded hot path. The exit, when
/// needed: gate `notifications/message` under its own per-server capability
/// action and hash what passes. Debt entry in the README.
fn server_notification(method: &str) -> bool {
    matches!(
        method,
        "notifications/message"
            | "notifications/progress"
            | "notifications/cancelled"
            | "notifications/resources/updated"
            | "notifications/resources/list_changed"
            | "notifications/tools/list_changed"
            | "notifications/prompts/list_changed"
    )
}

pub(crate) fn handle_from_server(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
    session_id: &str,
) -> Downstream {
    // A method means this is not a response: the server is speaking first.
    // Routed before the response-matching below — a server-initiated request
    // carries an id from the *server's* id space, and matching it against
    // `pending` (agent-side ids) would close an unrelated call's effect.
    if msg.get("method").is_some() {
        return handle_server_initiated(msg, state, ctx, session_id);
    }

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
                "[obsign] {label}: {} hidden — {}",
                removed.len(),
                removed.join(", ")
            );
        }

        let mut filtered = msg.clone();
        if let Some(slot) = filtered.pointer_mut(pointer) {
            *slot = Value::Array(kept);
        }
        return Downstream::Forward(filtered);
    }

    Downstream::Forward(msg)
}

/// Arbitrates the channels the *server* opens: `sampling/createMessage`
/// borrows the agent's model, `elicitation/create` puts a question to the
/// human — both move data across the boundary in the direction no policy
/// used to see. They are held to their own capability actions, granted per
/// server, under Cedar's default deny: absent an explicit
/// `permit (…, action == Action::"sampling", …)`, the request is refused in
/// the agent's place and the refusal recorded. When permitted, the request
/// is recorded before it is forwarded and its effect closes on the agent's
/// response — the same call/decision/effect triple as an agent act, because
/// to the investigation it is one.
///
/// The rest of the server-initiated surface: `ping` and `roots/list` pass
/// (liveness, and a question the agent client answers under its own
/// control), defined notifications pass, and anything else is refused —
/// the same default-deny as the agent-side method space.
fn handle_server_initiated(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
    session_id: &str,
) -> Downstream {
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);

    let cap = match method.as_str() {
        "sampling/createMessage" => Some(Capability::Sampling),
        "elicitation/create" => Some(Capability::Elicitation),
        "ping" | "roots/list" => {
            // Remember the id so the agent's reply passes the response
            // check: relayed machinery earns a relayed answer, nothing more.
            if let Some(id) = msg.get("id").filter(|v| !v.is_null()) {
                let mut s = state.lock().unwrap();
                if s.relayed_to_agent.len() < 1024 {
                    s.relayed_to_agent.insert(id.to_string());
                }
            }
            return Downstream::Forward(msg);
        }
        m if server_notification(m) => return Downstream::Forward(msg),
        _ => None,
    };
    let out_of_scope = cap.is_none();

    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    // The refusal the server sees; also what a WAL failure answers, because
    // an act whose record cannot be written must not proceed. The code
    // matches the agent-side convention: -32601 only for a method nobody
    // arbitrates, -32000 for a policy refusal, -32603 for the log failing.
    let refuse = |id: &Value, code: i64, text: &str| {
        if id.is_null() {
            // A notification cannot be answered; the record is the trace.
            Downstream::Drop
        } else {
            Downstream::Reply(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": code, "message": text }
                }),
            )
        }
    };

    // Same lock discipline as `handle_from_agent`: session first, auth
    // nested inside. No bearer arrives from the server — the delegation in
    // force is the one the agent's traffic last established.
    let mut s = state.lock().unwrap();
    let deleg = ctx.auth.lock().unwrap().delegation().clone();

    let verdict = match cap {
        None => policy::Verdict {
            outcome: Outcome::Deny,
            policy_id: None,
            reason: Some(
                "server-initiated method outside the arbitrated MCP surface (default-deny)"
                    .to_string(),
            ),
        },
        Some(_) if deleg.is_expired(now_ms()) => policy::Verdict {
            outcome: Outcome::Deny,
            policy_id: None,
            reason: Some("delegation expired".to_string()),
        },
        Some(cap) => ctx
            .engine
            .evaluate_capability(cap, &request(&deleg, ctx, session_id, SERVER.to_string())),
    };

    let call_id = s.next_call_id();
    let parent = s.agent_record_id.clone();
    let decision_id = format!("dec-{}", s.counter);
    let effect_id = format!("eff-{}", s.counter);

    let written = s
        .write(
            call_id.clone(),
            Some(parent),
            Payload::McpAccess(McpAccess {
                server: SERVER.to_string(),
                method: method.clone(),
                target: SERVER.to_string(),
                params_hash: content_hash(params.to_string().as_bytes()),
            }),
        )
        .and_then(|_| {
            s.write(
                decision_id.clone(),
                Some(call_id),
                Payload::Decision(DecisionRec {
                    outcome: verdict.outcome,
                    policy_id: verdict.policy_id.clone(),
                    bundle_version: ctx.bundle_version.clone(),
                    reason: verdict.reason.clone(),
                }),
            )
        });
    if let Err(e) = written {
        drop(s);
        eprintln!("[obsign] audit write failed, server-initiated {method} refused: {e}");
        return refuse(&id, -32603, "audit log unavailable");
    }

    if verdict.is_allowed() {
        if !id.is_null() {
            match s.pending_to_agent.entry(id.to_string()) {
                // Same collision rule as the agent direction: the in-flight
                // request keeps its slot, the newcomer is refused with its
                // own effect, and no recorded call is left without one.
                std::collections::hash_map::Entry::Occupied(_) => {
                    let _ = s.write(
                        effect_id,
                        Some(decision_id),
                        Payload::Effect(Effect {
                            status: EffectStatus::Blocked,
                            result_hash: None,
                            latency_ms: 0,
                        }),
                    );
                    drop(s);
                    eprintln!(
                        "[obsign] REFUSED server-initiated {method}: \
                         JSON-RPC id {id} is already in flight"
                    );
                    return refuse(
                        &id,
                        -32000,
                        &format!("Request refused: JSON-RPC id {id} is already in flight"),
                    );
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
        return Downstream::Forward(msg);
    }

    let _ = s.write(
        effect_id,
        Some(decision_id),
        Payload::Effect(Effect {
            status: EffectStatus::Blocked,
            result_hash: None,
            latency_ms: 0,
        }),
    );
    drop(s);

    let reason = verdict
        .reason
        .unwrap_or_else(|| "refused by policy".to_string());
    eprintln!("[obsign] REFUSED server-initiated {method}: {reason}");
    if out_of_scope {
        refuse(&id, -32601, &format!("Method not arbitrated: {reason}"))
    } else {
        refuse(
            &id,
            -32000,
            &format!("Request refused by policy {}: {}", ctx.bundle_version, reason),
        )
    }
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
        let dir = std::env::temp_dir().join(format!("obsign-gw-{tag}-{}", std::process::id()));
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
            "obsign-gw-id-collision-{}",
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
        let _ = handle_from_server(resp, &state, &ctx, "sess");

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
    fn an_unsolicited_response_is_refused_and_recorded() {
        // The bypass this closes: a message with no `method` matching no
        // in-flight server request was "just relayed" — an arbitrary
        // payload to the server wearing a response's shape, with no policy
        // and no record.
        let (dir, state) = open_state("unsolicited-resp");
        let ctx = ctx();

        let smuggle = json!({ "jsonrpc": "2.0", "id": 99,
                              "result": { "exfil": "arbitrary bytes" } });
        match handle_from_agent(smuggle, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => {
                assert!(r.contains("-32600"), "got: {r}");
                assert!(r.contains("no in-flight"), "got: {r}");
            }
            Forward::Pass(_) => panic!("an unsolicited response must not be forwarded"),
        }

        // A method that is not a string is not a response either.
        let odd = json!({ "jsonrpc": "2.0", "id": 100, "method": 42 });
        match handle_from_agent(odd, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => assert!(r.contains("-32601"), "got: {r}"),
            Forward::Pass(_) => panic!("a non-string method must not be forwarded"),
        }

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let denied = recs
            .iter()
            .filter(|r| {
                matches!(&r.payload, Payload::Decision(d) if d.outcome == Outcome::Deny)
            })
            .count();
        assert_eq!(denied, 2, "both refusals must leave a deny decision");
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::McpAccess(a) if a.method == "(unsolicited response)"
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reply_to_relayed_server_machinery_passes() {
        // The server pings; the relay remembers the id; the agent's pong
        // passes exactly once. A second message reusing the id is
        // unsolicited again.
        let (dir, state) = open_state("relayed-ping");
        let ctx = ctx();

        let ping = json!({ "jsonrpc": "2.0", "id": "srv-1", "method": "ping" });
        assert!(matches!(
            handle_from_server(ping, &state, &ctx, "sess"),
            Downstream::Forward(_)
        ));

        let pong = json!({ "jsonrpc": "2.0", "id": "srv-1", "result": {} });
        assert!(matches!(
            handle_from_agent(pong.clone(), &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));
        assert!(matches!(
            handle_from_agent(pong, &state, &ctx, None).unwrap(),
            Forward::Reply(_)
        ));

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
        let _ = handle_from_server(resp, &state, &ctx, "sess");

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
        let out = forwarded(handle_from_server(listing, &state, &ctx, "sess"));
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
        let out = forwarded(handle_from_server(prompts, &state, &ctx, "sess"));
        assert_eq!(
            out.pointer("/result/prompts").and_then(Value::as_array).unwrap().len(),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn forwarded(d: Downstream) -> Value {
        match d {
            Downstream::Forward(v) => v,
            Downstream::Reply(v) => panic!("expected a forward, got a reply: {v}"),
            Downstream::Drop => panic!("expected a forward, got a drop"),
        }
    }

    #[test]
    fn a_completion_is_held_to_the_permission_of_what_it_completes() {
        // The gap this closes: completion/complete used to pass unarbitrated,
        // so an agent could enumerate through the completer the very URIs the
        // resources/list filter was hiding from it.
        let (dir, state) = open_state("completion");
        let ctx = ctx_with(
            "@id(\"allow_docs\")\n\
             permit (principal, action == Action::\"resource_read\", resource)\n\
             when { context.target like \"docs://*\" };\n",
        );

        let hidden = json!({
            "jsonrpc": "2.0", "id": 1, "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "db://prod/{table}" },
                "argument": { "name": "table", "value": "cust" }
            }
        });
        match handle_from_agent(hidden, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => assert!(r.contains("\"error\""), "refused as JSON-RPC error: {r}"),
            Forward::Pass(_) => panic!("completing a hidden resource must not be forwarded"),
        }

        let visible = json!({
            "jsonrpc": "2.0", "id": 2, "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "docs://{page}" },
                "argument": { "name": "page", "value": "run" }
            }
        });
        assert!(matches!(
            handle_from_agent(visible, &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));

        // A ref shape the gateway cannot arbitrate falls out of scope.
        let odd = json!({
            "jsonrpc": "2.0", "id": 3, "method": "completion/complete",
            "params": { "ref": { "type": "ref/vendor", "thing": "x" } }
        });
        match handle_from_agent(odd, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => assert!(r.contains("-32601")),
            Forward::Pass(_) => panic!("an unknown ref shape must not be forwarded"),
        }

        // Both refusals and the pass are in the log.
        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let completions = recs
            .iter()
            .filter(|r| matches!(
                &r.payload,
                Payload::McpAccess(a) if a.method == "completion/complete"
            ))
            .count();
        assert_eq!(completions, 3, "every completion attempt must be recorded");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_method_is_refused_and_recorded_not_forwarded() {
        // Decision: the method space is default-deny. A vendor method passes
        // only by being added to the machinery allowlist or given an
        // arbitration path — never silently.
        let (dir, state) = open_state("unknown-method");
        let ctx = ctx(); // permits every tool_call — irrelevant here

        let call = json!({
            "jsonrpc": "2.0", "id": 4, "method": "vendor/exfiltrate",
            "params": { "payload": "everything" }
        });
        match handle_from_agent(call, &state, &ctx, None).unwrap() {
            Forward::Reply(r) => {
                let v: Value = serde_json::from_str(&r).unwrap();
                assert_eq!(
                    v.pointer("/error/code").and_then(Value::as_i64),
                    Some(-32601),
                    "through the gateway the method must not exist: {r}"
                );
            }
            Forward::Pass(_) => panic!("an unknown method must not be forwarded"),
        }

        // Machinery still passes.
        let ping = json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" });
        assert!(matches!(
            handle_from_agent(ping, &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let access = recs
            .iter()
            .find_map(|r| match &r.payload {
                Payload::McpAccess(a) => Some(a.clone()),
                _ => None,
            })
            .expect("the refused attempt must be recorded");
        assert_eq!(access.method, "vendor/exfiltrate");
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Decision(d) if d.outcome == Outcome::Deny && d.policy_id.is_none()
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sampling_is_refused_by_default_and_the_refusal_recorded() {
        // Decision: server-initiated channels are inside the perimeter.
        // Absent an explicit permit, the server's request never reaches the
        // agent — the gateway answers in its place, and the log keeps the
        // attempt.
        let (dir, state) = open_state("sampling-deny");
        let ctx = ctx(); // permits tool_call only

        let req = json!({
            "jsonrpc": "2.0", "id": 100, "method": "sampling/createMessage",
            "params": { "messages": [], "maxTokens": 8 }
        });
        match handle_from_server(req, &state, &ctx, "sess") {
            Downstream::Reply(v) => {
                assert_eq!(v.pointer("/id").and_then(Value::as_i64), Some(100));
                assert!(v.get("error").is_some());
            }
            Downstream::Forward(_) => panic!("unpermitted sampling must not reach the agent"),
            Downstream::Drop => panic!("a request has an id: it must be answered, not dropped"),
        }

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let access = recs
            .iter()
            .find_map(|r| match &r.payload {
                Payload::McpAccess(a) => Some(a.clone()),
                _ => None,
            })
            .expect("the server's attempt must be recorded");
        assert_eq!(access.method, "sampling/createMessage");
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Effect(e) if e.status == EffectStatus::Blocked
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn permitted_sampling_is_forwarded_and_closed_by_the_agents_response() {
        let (dir, state) = open_state("sampling-allow");
        let ctx = ctx_with(
            "@id(\"allow_sampling\")\n\
             permit (principal, action == Action::\"sampling\", resource);\n",
        );

        let req = json!({
            "jsonrpc": "2.0", "id": 100, "method": "sampling/createMessage",
            "params": { "messages": [], "maxTokens": 8 }
        });
        assert!(matches!(
            handle_from_server(req, &state, &ctx, "sess"),
            Downstream::Forward(_)
        ));

        // The agent answers: its response carries the generated text back to
        // the server, and that is the moment the effect closes.
        let resp = json!({
            "jsonrpc": "2.0", "id": 100,
            "result": { "role": "assistant", "content": { "type": "text", "text": "hi" } }
        });
        assert!(matches!(
            handle_from_agent(resp, &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));

        let recs = state.lock().unwrap().wal.read_all().unwrap();
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Decision(d) if d.outcome == Outcome::Allow
                && d.policy_id.as_deref() == Some("allow_sampling")
        )));
        assert!(recs.iter().any(|r| matches!(
            &r.payload,
            Payload::Effect(e) if e.status == EffectStatus::Ok && e.result_hash.is_some()
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_server_request_id_cannot_close_an_agent_calls_effect() {
        // Regression: any server message with an id used to be matched
        // against the agent-side pending map. A server-initiated request
        // whose id collided with an in-flight agent call closed that call's
        // effect as Ok — an outcome nobody observed.
        let (dir, state) = open_state("id-spaces");
        let ctx = ctx_with(
            "@id(\"allow_all\")\n\
             permit (principal, action == Action::\"tool_call\", resource);\n\
             @id(\"allow_sampling\")\n\
             permit (principal, action == Action::\"sampling\", resource);\n",
        );

        let call = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "search_docs", "arguments": {} }
        });
        assert!(matches!(
            handle_from_agent(call, &state, &ctx, None).unwrap(),
            Forward::Pass(_)
        ));

        // Server speaks first with the same id: routed as a request, not
        // matched as a response.
        let srv_req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage",
            "params": { "messages": [], "maxTokens": 8 }
        });
        assert!(matches!(
            handle_from_server(srv_req, &state, &ctx, "sess"),
            Downstream::Forward(_)
        ));

        // The agent's tool call is still pending: no effect closed yet.
        {
            let s = state.lock().unwrap();
            assert!(s.pending.contains_key("7"), "the tool call must still be in flight");
            assert!(s.pending_to_agent.contains_key("7"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_server_request_is_refused_and_an_unknown_notification_dropped() {
        let (dir, state) = open_state("srv-unknown");
        let ctx = ctx();

        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "vendor/pull" });
        match handle_from_server(req, &state, &ctx, "sess") {
            Downstream::Reply(v) => assert!(v.get("error").is_some()),
            _ => panic!("an unknown server request must be answered with an error"),
        }

        let notif = json!({ "jsonrpc": "2.0", "method": "notifications/vendor" });
        assert!(matches!(
            handle_from_server(notif, &state, &ctx, "sess"),
            Downstream::Drop
        ));

        // Known notifications still flow.
        let known = json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" });
        assert!(matches!(
            handle_from_server(known, &state, &ctx, "sess"),
            Downstream::Forward(_)
        ));

        // Both refusals are in the log.
        let recs = state.lock().unwrap().wal.read_all().unwrap();
        let refused: Vec<String> = recs
            .iter()
            .filter_map(|r| match &r.payload {
                Payload::McpAccess(a) => Some(a.method.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(refused, vec!["vendor/pull", "notifications/vendor"]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
