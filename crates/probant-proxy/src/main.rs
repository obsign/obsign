//! MCP gateway: a transparent proxy that enforces a signed policy and
//! engraves every act into an audit log.
//!
//! It sits between the agent and the MCP server, over stdio transport: the
//! gateway spawns the server as a child process and relays JSON-RPC. No agent
//! code is modified — you swap the MCP server command in its configuration,
//! that is all.
//!
//! Three interceptions:
//!
//! * `tools/list`: the response is filtered, the agent only sees the tools the
//!   policy allows it. What you cannot see, you do not attempt.
//! * `tools/call`: identity verified, policy evaluated, act logged, then
//!   forwarded or refused.
//! * everything else: relayed as-is.
//!
//! **All logging goes to stderr.** stdout is the MCP channel: one stray
//! `println!` and the protocol is broken.

mod auth;
#[cfg(test)]
mod testutil;
mod session;

use anyhow::{bail, Context as _, Result};
use audit_core::content_hash;
use audit_core::record::{
    Decision as DecisionRec, Effect, EffectStatus, Outcome, Payload, ToolCall,
};
use auth::Auth;
use clap::Parser;
use ed25519_dalek::SigningKey;
use identity::BundleSource;
use policy::{Engine, SignedBundle, ToolRequest};
use serde_json::{json, Value};
use session::{now_ms, Pending};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use wal::Wal;

#[derive(Parser)]
#[command(
    name = "probant-proxy",
    about = "MCP proxy enforcing a signed policy and logging every act",
    long_about = "Sits between an agent and an MCP server (stdio transport).\n\
                  Filters tools/list, arbitrates tools/call, and engraves\n\
                  everything into an offline-verifiable audit log."
)]
struct Cli {
    /// Signed policy bundle (JSON)
    #[arg(long)]
    policy: PathBuf,

    /// Trusted public keys, used to verify both bundles (JSON)
    #[arg(long)]
    trusted_keys: PathBuf,

    // --- Identity: OIDC (normal) --------------------------------------
    /// Signed identity bundle: issuer, audience, JWKS, claim mapping.
    ///
    /// Signed because the JWKS decides who can mint valid tokens, and the
    /// claim mapping decides which groups get assigned. Whoever can write this
    /// file can mint an identity for themselves.
    #[arg(long)]
    identity_bundle: Option<PathBuf>,

    /// File holding the access token. Re-read automatically on expiry.
    #[arg(long)]
    token_file: Option<PathBuf>,

    // --- Identity: declared (development only) -------------------------
    /// Accepts an unverified identity. The log will carry the issuer
    /// `cli://declared`, which tells the auditor nothing was proven.
    #[arg(long)]
    insecure_declared_identity: bool,

    /// Declared subject (with --insecure-declared-identity)
    #[arg(long)]
    principal: Option<String>,

    /// Declared groups (repeatable)
    #[arg(long = "group")]
    groups: Vec<String>,

    /// Declared scopes (repeatable)
    #[arg(long = "scope")]
    scopes: Vec<String>,

    // --- Log ------------------------------------------------------------
    /// Write-ahead log directory
    #[arg(long, default_value = "./wal")]
    wal: PathBuf,

    /// Audit chain identifier
    #[arg(long, default_value = "default")]
    chain_id: String,

    /// Declared environment, exposed to policies
    #[arg(long, default_value = "prod")]
    env: String,

    /// Agent identifier
    #[arg(long, default_value = "unknown-agent")]
    agent_id: String,

    /// Session identifier (end-to-end correlation)
    #[arg(long)]
    session_id: Option<String>,

    /// Sealing key seed, 32 bytes in hex.
    /// In production this key lives in a KMS/HSM, never in a file.
    #[arg(long)]
    signing_key: Option<PathBuf>,

    #[arg(long, default_value = "seal-dev")]
    key_id: String,

    /// Writes an evidence pack on shutdown
    #[arg(long)]
    evidence_out: Option<PathBuf>,

    /// MCP server command to wrap, after `--`
    #[arg(last = true, required = true)]
    server_cmd: Vec<String>,
}

/// Immutable context shared by both directions of the proxy.
struct Ctx {
    engine: Arc<Engine>,
    auth: Arc<Mutex<Auth>>,
    env: String,
    agent_id: String,
    bundle_version: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- Policy -------------------------------------------------------
    let signed: SignedBundle = serde_json::from_str(
        &std::fs::read_to_string(&cli.policy)
            .with_context(|| format!("lecture de {}", cli.policy.display()))?,
    )
    .context("unreadable policy bundle")?;

    let trusted: Vec<audit_core::checkpoint::PublicKeyEntry> = serde_json::from_str(
        &std::fs::read_to_string(&cli.trusted_keys)
            .with_context(|| format!("lecture de {}", cli.trusted_keys.display()))?,
    )
    .context("unreadable trusted keys")?;

    let vk = trusted
        .iter()
        .find(|k| k.key_id == signed.key_id)
        .with_context(|| {
            format!(
                "bundle signed with key \"{}\", absent from the trusted keys",
                signed.key_id
            )
        })?
        .to_verifying_key()
        .context("unusable trusted key")?;

    // An unverified bundle must never be loaded: otherwise changing the
    // rules amounts to writing a file on the gateway's disk.
    let bundle = signed
        .verify(&vk)
        .context("verifying the bundle signature")?;
    let engine = Arc::new(Engine::load(bundle).context("loading the policies")?);
    let bundle_version = engine.version().to_string();

    // --- Identity -------------------------------------------------------
    let auth = build_auth(&cli, &trusted)?;
    {
        let a = auth.lock().unwrap();
        let d = a.delegation();
        if a.is_proven() {
            eprintln!(
                "[probant] identity PROVEN — {} via {} — expires in {} s — bundle {}",
                d.subject,
                d.issuer,
                d.remaining_secs(now_ms()),
                a.identity_version()
            );
        } else {
            eprintln!(
                "[probant] WARNING: identity DECLARED, unverified — \"{}\". \
                 The log will carry the issuer cli://declared. \
                 Never use in production.",
                d.subject
            );
        }
    }

    // --- Sealing key ----------------------------------------------------
    let signing_key = match &cli.signing_key {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("lecture de {}", p.display()))?;
            let bytes = hex::decode(raw.trim()).context("invalid hex seed")?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("the seed must be 32 bytes"))?;
            SigningKey::from_bytes(&seed)
        }
        None => {
            eprintln!(
                "[probant] WARNING: no --signing-key supplied, development key in use. \
                 The seals produced have NO probative value."
            );
            SigningKey::from_bytes(&[0x2a; 32])
        }
    };

    // --- Log -------------------------------------------------------------
    let (wal, chain) = Wal::open(&cli.wal, &cli.chain_id).context("opening the log")?;
    if chain.next_seq() > 0 {
        eprintln!(
            "[probant] log resumed at seq={} (head {})",
            chain.next_seq(),
            chain.head()
        );
    }

    let session_id = cli
        .session_id
        .clone()
        .unwrap_or_else(|| format!("sess-{}", std::process::id()));

    let mut sess = session::open(chain, wal, session_id.clone());
    {
        let a = auth.lock().unwrap();
        session::record_delegation(
            &mut sess,
            a.generation(),
            a.delegation(),
            &cli.agent_id,
            &bundle_version,
        )?;
    }
    let state = Arc::new(Mutex::new(sess));

    let ctx = Arc::new(Ctx {
        engine: Arc::clone(&engine),
        auth: Arc::clone(&auth),
        env: cli.env.clone(),
        agent_id: cli.agent_id.clone(),
        bundle_version: bundle_version.clone(),
    });

    // --- Wrapped MCP server ----------------------------------------------
    let mut child = spawn_server(&cli.server_cmd)?;
    let mut child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    eprintln!(
        "[probant] policy {} — {} tool(s) in catalogue — env {}",
        bundle_version,
        engine.known_tools().count(),
        cli.env
    );

    // --- Downstream: server -> agent --------------------------------------
    let downstream = {
        let state = Arc::clone(&state);
        let ctx = Arc::clone(&ctx);
        let session_id = session_id.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(child_stdout);
            let stdout = std::io::stdout();
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(msg) => handle_from_server(msg, &state, &ctx, &session_id),
                    // Non-JSON line: relayed as-is rather than breaking a
                    // protocol we do not understand.
                    Err(_) => line.clone(),
                };
                let mut lock = stdout.lock();
                if writeln!(lock, "{out}").is_err() || lock.flush().is_err() {
                    break;
                }
            }
        })
    };

    // --- Upstream: agent -> server -----------------------------------------
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }

        let forward = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle_from_agent(msg, &state, &ctx)?,
            Err(_) => Forward::Pass(line.clone()),
        };

        match forward {
            Forward::Pass(raw) => {
                writeln!(child_stdin, "{raw}")?;
                child_stdin.flush()?;
            }
            Forward::Reply(resp) => {
                // Refusal: we answer in the server's place, the call never
                // leaves the gateway.
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                writeln!(lock, "{resp}")?;
                lock.flush()?;
            }
        }
    }

    // --- Shutdown -----------------------------------------------------------
    drop(child_stdin);
    let _ = downstream.join();
    let _ = child.wait();

    let mut s = state.lock().unwrap();
    let evidence = s.finish(&cli.key_id, &signing_key)?;
    eprintln!(
        "[probant] {} record(s), {} checkpoint(s)",
        evidence.records.len(),
        evidence.checkpoints.len()
    );

    if let Some(path) = &cli.evidence_out {
        std::fs::write(path, serde_json::to_string_pretty(&evidence)?)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("[probant] evidence pack: {}", path.display());
    }

    Ok(())
}

/// Builds the identity source and refuses any ambiguous configuration.
///
/// Declared mode requires a flag whose name says what it is: we do not want a
/// deployment to slip into unverified identity by simply forgetting an
/// option.
fn build_auth(
    cli: &Cli,
    trusted: &[audit_core::checkpoint::PublicKeyEntry],
) -> Result<Arc<Mutex<Auth>>> {
    let oidc_configured = cli.identity_bundle.is_some() || cli.token_file.is_some();

    if oidc_configured && cli.insecure_declared_identity {
        bail!(
            "--insecure-declared-identity is incompatible with the OIDC options: \
             pick a single identity source"
        );
    }

    if cli.insecure_declared_identity {
        let principal = cli
            .principal
            .clone()
            .context("--principal is required with --insecure-declared-identity")?;
        return Ok(Arc::new(Mutex::new(Auth::declared(
            &principal,
            cli.scopes.clone(),
            cli.groups.clone(),
        ))));
    }

    let (Some(bundle_path), Some(token)) = (&cli.identity_bundle, &cli.token_file) else {
        bail!(
            "identity not configured: supply --identity-bundle and --token-file, \
             or --insecure-declared-identity for development"
        );
    };

    // Reloadable source: the bundle is re-verified on every read, so hot
    // rotation cannot be used to inject a JWKS.
    let source = BundleSource::load(bundle_path, trusted).map_err(|e| {
        anyhow::anyhow!("loading {}: {e}", bundle_path.display())
    })?;

    Auth::oidc(source, token.clone())
        .map(|a| Arc::new(Mutex::new(a)))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

enum Forward {
    /// Forward to the MCP server.
    Pass(String),
    /// Answer the agent directly, without forwarding.
    Reply(String),
}

fn spawn_server(cmd: &[String]) -> Result<Child> {
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

fn handle_from_agent(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
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
    // 30-minute token.
    let now = now_ms();
    let (deleg, generation, renewed, auth_error) = {
        let mut a = ctx.auth.lock().unwrap();
        match a.refresh(now) {
            Ok(renewed) => (a.delegation().clone(), a.generation(), renewed, None),
            Err(e) => (a.delegation().clone(), a.generation(), false, Some(e)),
        }
    };

    let mut s = state.lock().unwrap();

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
            s.pending.insert(
                id.to_string(),
                Pending {
                    decision_record_id: decision_id,
                    effect_record_id: effect_id,
                    started: Instant::now(),
                },
            );
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

fn handle_from_server(
    msg: Value,
    state: &Arc<Mutex<session::Session>>,
    ctx: &Ctx,
    session_id: &str,
) -> String {
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
        return filtered.to_string();
    }

    msg.to_string()
}
