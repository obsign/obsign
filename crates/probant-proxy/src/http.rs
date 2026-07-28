//! Streamable HTTP transport (MCP specification, 2025-03-26 revision and
//! later).
//!
//! The gateway listens on a single endpoint, `/mcp`. Each `initialize`
//! request opens a session: its own instance of the wrapped stdio server, its
//! own audit chain, its own identity. The client gets an `Mcp-Session-Id`
//! back and presents it on every subsequent request; deleting the session
//! seals the chain and writes the evidence pack. One agent's session ending —
//! or misbehaving — never touches another's log.
//!
//! Identity travels in the `Authorization: Bearer` header of each request and
//! is verified against the same signed identity bundle as in stdio mode. The
//! header is where enterprise SSO puts it, and per-request presentation is
//! what lets a renewed token take effect mid-session.
//!
//! The HTTP layer is written by hand on `std::net`, one thread per
//! connection. Not bravado: the gateway's dependency list is part of the
//! product (an auditor must be able to read it end to end), and the subset of
//! HTTP/1.1 this transport needs — POST/GET/DELETE on one path,
//! `Content-Length` bodies, server-sent events — is small enough that a web
//! framework would cost more in tree than it saves in code. The parser
//! compensates by being strict: anything outside that subset is refused, not
//! interpreted.
//!
//! Inbound HTTP does not contradict "the gateway makes no network calls":
//! that invariant bans *outbound* dependencies (JWKS fetches, ledger RTTs),
//! which would break air-gapped deployment. Listening is the transport.

use crate::auth::Auth;
use crate::gateway::{self, Ctx, Forward};
use crate::session::{self, now_ms};
use anyhow::{Context as _, Result};
use ed25519_dalek::SigningKey;
use identity::BundleSource;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;
use wal::Wal;

/// The single MCP endpoint.
const ENDPOINT: &str = "/mcp";

/// Ceiling on request headers. Above this, someone is not speaking MCP.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Ceiling on a request body. Tool arguments are hashed into the log, not
/// stored, so there is no audit reason to accept arbitrarily large payloads.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Idle time after which a kept-alive connection is closed. Closing is always
/// safe: HTTP clients reconnect.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between comment lines on the GET stream, so that a dead client is
/// detected by the write failing rather than never.
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// How the gateway establishes the identity of each HTTP session.
pub enum Identity {
    /// Declared on the command line, unverified — development only. Every
    /// session carries the same declared principal.
    Declared {
        principal: String,
        scopes: Vec<String>,
        groups: Vec<String>,
    },
    /// Proven per request: the `Authorization: Bearer` token is verified
    /// against this signed identity bundle.
    Oidc { bundle_path: PathBuf },
}

/// Everything fixed for the gateway's lifetime, shared by all sessions.
pub struct Gateway {
    pub engine: Arc<policy::Engine>,
    pub trusted: Vec<audit_core::checkpoint::PublicKeyEntry>,
    pub bundle_version: String,
    pub identity: Identity,
    pub env: String,
    pub agent_id: String,
    pub wal_dir: PathBuf,
    pub chain_id: String,
    pub key_id: String,
    pub signing_key: SigningKey,
    pub evidence_dir: Option<PathBuf>,
    pub server_cmd: Vec<String>,
    pub allowed_origins: Vec<String>,
}

/// One MCP session: one agent, one wrapped server, one audit chain.
struct McpSession {
    id: String,
    ctx: Arc<Ctx>,
    state: Arc<Mutex<session::Session>>,
    child: Mutex<Child>,
    /// `None` once the session is closing: writes after that point answer
    /// "session terminated" instead of racing a dying process.
    child_stdin: Mutex<Option<ChildStdin>>,
    /// POST threads waiting for the response to a forwarded request, keyed by
    /// the serialized JSON-RPC id — the same key `Session::pending` uses.
    waiters: Mutex<HashMap<String, mpsc::Sender<Value>>>,
    /// Sink of the GET stream, when one is open. Server-initiated messages
    /// go there; without a stream they are dropped, loudly.
    events: Mutex<Option<mpsc::Sender<Value>>>,
    /// Signalled once the chain is sealed, so DELETE can return only after
    /// the evidence pack exists.
    sealed: (Mutex<bool>, Condvar),
}

type Registry = Arc<Mutex<HashMap<String, Arc<McpSession>>>>;

pub fn serve(gw: Gateway, addr: &str) -> Result<()> {
    let listener =
        TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    eprintln!(
        "[probant] Streamable HTTP on http://{}{}",
        listener.local_addr()?,
        ENDPOINT
    );

    let gw = Arc::new(gw);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let gw = Arc::clone(&gw);
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &gw, &registry);
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

/// What the connection loop does after a response.
enum Next {
    KeepAlive,
    Close,
}

fn handle_connection(
    stream: TcpStream,
    gw: &Arc<Gateway>,
    registry: &Registry,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IDLE_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut stream = stream;

    loop {
        let req = match read_request(&mut reader, &mut stream) {
            Ok(Some(r)) => r,
            // Clean close or idle timeout: nothing to answer.
            Ok(None) => return Ok(()),
            Err(e) => {
                let _ = respond_json(
                    &mut stream,
                    e.status,
                    e.reason,
                    &[],
                    &rpc_error(&Value::Null, -32700, &e.message),
                );
                return Ok(());
            }
        };

        match route(req, &mut stream, gw, registry) {
            Ok(Next::KeepAlive) => continue,
            Ok(Next::Close) | Err(_) => return Ok(()),
        }
    }
}

fn route(
    req: Request,
    stream: &mut TcpStream,
    gw: &Arc<Gateway>,
    registry: &Registry,
) -> std::io::Result<Next> {
    // The Origin check is the defence against DNS rebinding: a browser lured
    // to a hostile page will attach the page's Origin, which no allowlist
    // entry matches. Non-browser MCP clients send no Origin and pass.
    if let Some(origin) = req.header("origin") {
        if !gw.allowed_origins.iter().any(|o| o == origin) {
            respond_json(
                stream,
                403,
                "Forbidden",
                &[],
                &rpc_error(&Value::Null, -32600, "origin not allowed"),
            )?;
            return Ok(Next::KeepAlive);
        }
    }

    if req.path() != ENDPOINT {
        respond_json(
            stream,
            404,
            "Not Found",
            &[],
            &rpc_error(&Value::Null, -32600, "unknown endpoint"),
        )?;
        return Ok(Next::KeepAlive);
    }

    match req.method.as_str() {
        "POST" => handle_post(req, stream, gw, registry),
        "GET" => handle_get(req, stream, gw, registry),
        "DELETE" => handle_delete(req, stream, registry),
        _ => {
            respond(
                stream,
                405,
                "Method Not Allowed",
                &[("Allow", "POST, GET, DELETE")],
                None,
                b"",
            )?;
            Ok(Next::KeepAlive)
        }
    }
}

// ---------------------------------------------------------------------------
// POST: the request path
// ---------------------------------------------------------------------------

fn handle_post(
    req: Request,
    stream: &mut TcpStream,
    gw: &Arc<Gateway>,
    registry: &Registry,
) -> std::io::Result<Next> {
    let msg: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => {
            respond_json(
                stream,
                400,
                "Bad Request",
                &[],
                &rpc_error(&Value::Null, -32700, "body is not valid JSON"),
            )?;
            return Ok(Next::KeepAlive);
        }
    };

    // Batches were removed in the 2025-06-18 revision; supporting both
    // framings would double the arbitration surface for no client we care
    // about.
    if msg.is_array() {
        respond_json(
            stream,
            400,
            "Bad Request",
            &[],
            &rpc_error(&Value::Null, -32600, "JSON-RPC batching is not supported"),
        )?;
        return Ok(Next::KeepAlive);
    }

    let bearer = req.bearer();
    let method = msg.get("method").and_then(Value::as_str);
    let sid = req.header("mcp-session-id");

    // `initialize` without a session opens one. Anything else needs the
    // header.
    if method == Some("initialize") && sid.is_none() {
        return open_session(msg, bearer, stream, gw, registry);
    }

    let Some(sid) = sid else {
        respond_json(
            stream,
            400,
            "Bad Request",
            &[],
            &rpc_error(&Value::Null, -32600, "Mcp-Session-Id header required"),
        )?;
        return Ok(Next::KeepAlive);
    };
    let Some(sess) = registry.lock().unwrap().get(sid).cloned() else {
        respond_json(
            stream,
            404,
            "Not Found",
            &[],
            &rpc_error(&Value::Null, -32600, "unknown or terminated session"),
        )?;
        return Ok(Next::KeepAlive);
    };

    // In OIDC mode a request with no token at all cannot be attributed to
    // anyone; there is nothing meaningful to record. 401 per the MCP
    // authorization spec. A *presented but invalid* token on `tools/call`
    // goes through arbitration instead, because a refused attempt must leave
    // a record.
    if matches!(gw.identity, Identity::Oidc { .. }) && bearer.is_none() {
        respond_json(
            stream,
            401,
            "Unauthorized",
            &[("WWW-Authenticate", "Bearer")],
            &rpc_error(&Value::Null, -32600, "Authorization: Bearer required"),
        )?;
        return Ok(Next::KeepAlive);
    }

    let has_id = msg.get("id").is_some_and(|v| !v.is_null());

    // Requests other than tools/call never reach the auth path inside
    // `handle_from_agent`, but their *responses* consult the delegation —
    // tools/list filtering above all. Present the token here so a renewal
    // takes effect before the request is forwarded, not one call later.
    if method != Some("tools/call") {
        present_bearer(&sess, bearer);
    }

    if !has_id {
        // Notification, or a response to a server-initiated request: forward,
        // nothing to wait for. 202 per spec.
        return match forward_raw(&sess, &msg.to_string()) {
            Ok(()) => {
                respond(stream, 202, "Accepted", &[], None, b"")?;
                Ok(Next::KeepAlive)
            }
            Err(_) => {
                respond_json(
                    stream,
                    502,
                    "Bad Gateway",
                    &[],
                    &rpc_error(&Value::Null, -32603, "wrapped MCP server is gone"),
                )?;
                Ok(Next::KeepAlive)
            }
        };
    }

    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let fwd = match gateway::handle_from_agent(msg, &sess.state, &sess.ctx, bearer) {
        Ok(f) => f,
        Err(e) => {
            // WAL write failure: the act must not proceed without its record.
            eprintln!("[probant] audit write failed, call refused: {e}");
            respond_json(
                stream,
                500,
                "Internal Server Error",
                &[],
                &rpc_error(&id, -32603, "audit log unavailable"),
            )?;
            return Ok(Next::KeepAlive);
        }
    };

    match fwd {
        Forward::Reply(resp) => {
            respond_json(stream, 200, "OK", &[], resp.as_bytes())?;
        }
        Forward::Pass(raw) => match forward_and_wait(&sess, &raw, &id) {
            Ok(resp) => {
                respond_json(stream, 200, "OK", &[], resp.to_string().as_bytes())?;
            }
            Err(reason) => {
                respond_json(
                    stream,
                    502,
                    "Bad Gateway",
                    &[],
                    &rpc_error(&id, -32603, reason),
                )?;
            }
        },
    }
    Ok(Next::KeepAlive)
}

/// Forwards a request to the wrapped server and blocks until its response
/// comes back through the dispatcher.
///
/// No timeout of our own: a slow tool is the client's business, and a dead
/// server is detected structurally — the dispatcher clears the waiters map on
/// EOF, which disconnects the channel.
fn forward_and_wait(
    sess: &McpSession,
    raw: &str,
    id: &Value,
) -> std::result::Result<Value, &'static str> {
    let (tx, rx) = mpsc::channel();
    sess.waiters.lock().unwrap().insert(id.to_string(), tx);

    // The waiter is registered *before* the write: the response cannot lose
    // the race with its own registration.
    if forward_raw(sess, raw).is_err() {
        sess.waiters.lock().unwrap().remove(&id.to_string());
        return Err("wrapped MCP server is gone");
    }

    rx.recv()
        .map_err(|_| "session terminated before the server answered")
}

fn forward_raw(sess: &McpSession, raw: &str) -> std::io::Result<()> {
    let mut guard = sess.child_stdin.lock().unwrap();
    let Some(stdin) = guard.as_mut() else {
        return Err(std::io::Error::other("session closing"));
    };
    writeln!(stdin, "{raw}")?;
    stdin.flush()
}

/// Takes the bearer of a non-`tools/call` request into account, recording the
/// new delegation if it changed. Verification failure is not fatal here: the
/// previous delegation stays in force and its expiry does the enforcement —
/// tools/list hides everything, tools/call refuses and records.
fn present_bearer(sess: &McpSession, bearer: Option<&str>) {
    let Some(token) = bearer else { return };
    let now = now_ms();

    let renewed = {
        let mut a = sess.ctx.auth.lock().unwrap();
        matches!(a.present(token, now), Ok(true))
    };
    if !renewed {
        return;
    }

    let (deleg, generation) = {
        let a = sess.ctx.auth.lock().unwrap();
        (a.delegation().clone(), a.generation())
    };
    let mut s = sess.state.lock().unwrap();
    if let Err(e) = session::record_delegation(
        &mut s,
        generation,
        &deleg,
        &sess.ctx.agent_id,
        &sess.ctx.bundle_version,
    ) {
        eprintln!("[probant] failed to record renewed delegation: {e}");
    } else {
        eprintln!(
            "[probant] delegation renewed (generation {generation}) — {} — expires in {} s",
            deleg.subject,
            deleg.remaining_secs(now)
        );
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

fn open_session(
    init_msg: Value,
    bearer: Option<&str>,
    stream: &mut TcpStream,
    gw: &Arc<Gateway>,
    registry: &Registry,
) -> std::io::Result<Next> {
    // --- Identity first: no identity, no child, no chain -------------------
    let auth = match &gw.identity {
        Identity::Declared {
            principal,
            scopes,
            groups,
        } => Auth::declared(principal, scopes.clone(), groups.clone()),
        Identity::Oidc { bundle_path } => {
            let Some(token) = bearer else {
                respond_json(
                    stream,
                    401,
                    "Unauthorized",
                    &[("WWW-Authenticate", "Bearer")],
                    &rpc_error(&Value::Null, -32600, "Authorization: Bearer required"),
                )?;
                return Ok(Next::KeepAlive);
            };
            // The bundle is loaded per session rather than shared: each
            // session re-verifies its signature and follows rotations
            // independently, exactly as a stdio gateway restart would.
            let source = match BundleSource::load(bundle_path, &gw.trusted) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[probant] identity bundle unusable: {e}");
                    respond_json(
                        stream,
                        500,
                        "Internal Server Error",
                        &[],
                        &rpc_error(&Value::Null, -32603, "identity bundle unusable"),
                    )?;
                    return Ok(Next::KeepAlive);
                }
            };
            match Auth::oidc_presented(source, token) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[probant] session refused: {e}");
                    respond_json(
                        stream,
                        401,
                        "Unauthorized",
                        &[("WWW-Authenticate", "Bearer")],
                        &rpc_error(&Value::Null, -32600, "token rejected"),
                    )?;
                    return Ok(Next::KeepAlive);
                }
            }
        }
    };

    let sid = match new_session_id() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[probant] cannot generate a session id: {e}");
            respond_json(
                stream,
                500,
                "Internal Server Error",
                &[],
                &rpc_error(&Value::Null, -32603, "internal error"),
            )?;
            return Ok(Next::KeepAlive);
        }
    };

    // One chain per session. Sharing one chain would interleave sessions and
    // collide their record identifiers (deleg-1, call-1...); separate chains
    // keep each evidence pack self-contained: one agent, one delegation
    // history, one verdict trail.
    let chain_id = format!("{}-{}", gw.chain_id, sid);
    let opened = (|| -> Result<Arc<McpSession>> {
        let (wal, chain) = Wal::open(&gw.wal_dir, &chain_id).context("opening the log")?;
        let mut s = session::open(chain, wal, sid.clone());

        let ctx = Arc::new(Ctx {
            engine: Arc::clone(&gw.engine),
            auth: Arc::new(Mutex::new(auth)),
            env: gw.env.clone(),
            agent_id: gw.agent_id.clone(),
            bundle_version: gw.bundle_version.clone(),
        });
        {
            let a = ctx.auth.lock().unwrap();
            session::record_delegation(
                &mut s,
                a.generation(),
                a.delegation(),
                &gw.agent_id,
                &gw.bundle_version,
            )?;
            let d = a.delegation();
            eprintln!(
                "[probant] session {} opened — {} via {} ({})",
                &sid[..8],
                d.subject,
                d.issuer,
                if a.is_proven() { "PROVEN" } else { "DECLARED, unverified" }
            );
        }

        let mut child = gateway::spawn_server(&gw.server_cmd)?;
        let child_stdin = child.stdin.take().expect("child stdin");
        let child_stdout = child.stdout.take().expect("child stdout");

        let sess = Arc::new(McpSession {
            id: sid.clone(),
            ctx,
            state: Arc::new(Mutex::new(s)),
            child: Mutex::new(child),
            child_stdin: Mutex::new(Some(child_stdin)),
            waiters: Mutex::new(HashMap::new()),
            events: Mutex::new(None),
            sealed: (Mutex::new(false), Condvar::new()),
        });
        registry.lock().unwrap().insert(sid.clone(), Arc::clone(&sess));

        let dispatcher_sess = Arc::clone(&sess);
        let dispatcher_gw = Arc::clone(gw);
        let dispatcher_registry = Arc::clone(registry);
        std::thread::spawn(move || {
            dispatch_from_server(
                dispatcher_sess,
                child_stdout,
                dispatcher_gw,
                dispatcher_registry,
            )
        });

        Ok(sess)
    })();

    let sess = match opened {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[probant] session refused: {e:#}");
            respond_json(
                stream,
                500,
                "Internal Server Error",
                &[],
                &rpc_error(&Value::Null, -32603, "session could not be opened"),
            )?;
            return Ok(Next::KeepAlive);
        }
    };

    // The initialize request itself goes through the normal path; only the
    // response gains the session header.
    let id = init_msg.get("id").cloned().unwrap_or(Value::Null);
    match forward_and_wait(&sess, &init_msg.to_string(), &id) {
        Ok(resp) => {
            respond_json(
                stream,
                200,
                "OK",
                &[("Mcp-Session-Id", &sess.id)],
                resp.to_string().as_bytes(),
            )?;
        }
        Err(reason) => {
            respond_json(stream, 502, "Bad Gateway", &[], &rpc_error(&id, -32603, reason))?;
        }
    }
    Ok(Next::KeepAlive)
}

/// Reads the wrapped server's stdout for one session, records effects, and
/// routes each message: responses to the POST thread waiting for them,
/// server-initiated traffic to the GET stream.
///
/// This thread is also the only place a session is sealed. Everything that
/// ends a session — DELETE, a dying child, gateway shutdown via child exit —
/// converges here as an EOF on the child's stdout, after every last buffered
/// response has been processed. Sealing anywhere else would race the effects
/// still being written.
fn dispatch_from_server(
    sess: Arc<McpSession>,
    child_stdout: std::process::ChildStdout,
    gw: Arc<Gateway>,
    registry: Registry,
) {
    let reader = BufReader::new(child_stdout);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            // stdio relays unknown bytes as-is; HTTP has no channel for them.
            eprintln!("[probant] session {}: non-JSON server line dropped", &sess.id[..8]);
            continue;
        };

        let out = gateway::handle_from_server(msg, &sess.state, &sess.ctx, &sess.id);

        if out.get("method").is_some() {
            // Server-initiated request or notification: only the GET stream
            // can carry it. No stream, no delivery — said out loud, because a
            // lost `tools/list_changed` is a debugging session.
            let mut events = sess.events.lock().unwrap();
            let delivered = events.as_ref().map(|tx| tx.send(out.clone()).is_ok());
            match delivered {
                Some(true) => {}
                Some(false) => *events = None,
                None => eprintln!(
                    "[probant] session {}: server-initiated message dropped (no GET stream open)",
                    &sess.id[..8]
                ),
            }
        } else if let Some(id) = out.get("id") {
            let waiter = sess.waiters.lock().unwrap().remove(&id.to_string());
            match waiter {
                Some(tx) => {
                    let _ = tx.send(out);
                }
                None => eprintln!(
                    "[probant] session {}: unmatched response dropped (id {id})",
                    &sess.id[..8]
                ),
            }
        }
    }

    // --- EOF: the session is over ------------------------------------------
    registry.lock().unwrap().remove(&sess.id);
    // Disconnects every waiting POST; they answer 502 on their own threads.
    sess.waiters.lock().unwrap().clear();
    // Ends the GET stream.
    *sess.events.lock().unwrap() = None;
    *sess.child_stdin.lock().unwrap() = None;
    let _ = sess.child.lock().unwrap().wait();

    // In-flight calls whose response never came stay as call+decision records
    // with no effect. Deliberate: writing an effect would claim knowledge of
    // an outcome nobody observed. A truncated triple *is* the honest record.
    let mut s = sess.state.lock().unwrap();
    match s.finish(&gw.key_id, &gw.signing_key) {
        Ok(evidence) => {
            eprintln!(
                "[probant] session {} sealed — {} record(s), {} checkpoint(s)",
                &sess.id[..8],
                evidence.records.len(),
                evidence.checkpoints.len()
            );
            if let Some(dir) = &gw.evidence_dir {
                let path = dir.join(format!("{}.json", sess.id));
                match serde_json::to_string_pretty(&evidence)
                    .map_err(std::io::Error::other)
                    .and_then(|j| std::fs::write(&path, j))
                {
                    Ok(()) => eprintln!("[probant] evidence pack: {}", path.display()),
                    Err(e) => eprintln!("[probant] writing evidence pack failed: {e}"),
                }
            }
        }
        Err(e) => eprintln!("[probant] sealing session {} failed: {e}", &sess.id[..8]),
    }
    drop(s);

    let (lock, cvar) = &sess.sealed;
    *lock.lock().unwrap() = true;
    cvar.notify_all();
}

fn handle_delete(
    req: Request,
    stream: &mut TcpStream,
    registry: &Registry,
) -> std::io::Result<Next> {
    let Some(sid) = req.header("mcp-session-id") else {
        respond_json(
            stream,
            400,
            "Bad Request",
            &[],
            &rpc_error(&Value::Null, -32600, "Mcp-Session-Id header required"),
        )?;
        return Ok(Next::KeepAlive);
    };
    let Some(sess) = registry.lock().unwrap().remove(sid) else {
        respond_json(
            stream,
            404,
            "Not Found",
            &[],
            &rpc_error(&Value::Null, -32600, "unknown or terminated session"),
        )?;
        return Ok(Next::KeepAlive);
    };

    // Closing stdin is the whole termination protocol: the server exits, its
    // stdout reaches EOF, and the dispatcher seals the chain after the last
    // buffered response. We only wait for that seal so the client can rely on
    // the evidence pack existing when DELETE returns.
    *sess.child_stdin.lock().unwrap() = None;

    let (lock, cvar) = &sess.sealed;
    let sealed = cvar
        .wait_timeout_while(
            lock.lock().unwrap(),
            Duration::from_secs(10),
            |done| !*done,
        )
        .map(|(guard, timeout)| *guard && !timeout.timed_out())
        .unwrap_or(false);

    if !sealed {
        // The wrapped server is ignoring EOF. Killing it now would race the
        // dispatcher; better to say what is happening.
        eprintln!(
            "[probant] session {}: server has not exited, sealing pending",
            &sess.id[..8]
        );
        respond(stream, 202, "Accepted", &[], None, b"")?;
        return Ok(Next::KeepAlive);
    }

    respond(stream, 200, "OK", &[], None, b"")?;
    Ok(Next::KeepAlive)
}

// ---------------------------------------------------------------------------
// GET: the server-to-client stream
// ---------------------------------------------------------------------------

fn handle_get(
    req: Request,
    stream: &mut TcpStream,
    gw: &Arc<Gateway>,
    registry: &Registry,
) -> std::io::Result<Next> {
    // The spec requires the client to announce it accepts SSE; a GET without
    // it is a browser or a probe, not an MCP client.
    let accepts_sse = req
        .header("accept")
        .is_some_and(|a| a.contains("text/event-stream"));
    if !accepts_sse {
        respond(stream, 406, "Not Acceptable", &[], None, b"")?;
        return Ok(Next::KeepAlive);
    }

    let Some(sid) = req.header("mcp-session-id") else {
        respond(stream, 400, "Bad Request", &[], None, b"")?;
        return Ok(Next::KeepAlive);
    };
    let Some(sess) = registry.lock().unwrap().get(sid).cloned() else {
        respond(stream, 404, "Not Found", &[], None, b"")?;
        return Ok(Next::KeepAlive);
    };

    if matches!(gw.identity, Identity::Oidc { .. }) {
        if req.bearer().is_none() {
            respond(stream, 401, "Unauthorized", &[("WWW-Authenticate", "Bearer")], None, b"")?;
            return Ok(Next::KeepAlive);
        }
        present_bearer(&sess, req.bearer());
    }

    let (tx, rx) = mpsc::channel();
    {
        let mut events = sess.events.lock().unwrap();
        if events.is_some() {
            // One stream per session. A second one would silently split the
            // notification flow between two consumers.
            respond(stream, 409, "Conflict", &[], None, b"")?;
            return Ok(Next::KeepAlive);
        }
        *events = Some(tx);
    }

    stream.write_all(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/event-stream\r\n\
          Cache-Control: no-store\r\n\
          Connection: close\r\n\r\n",
    )?;
    stream.flush()?;

    loop {
        match rx.recv_timeout(SSE_KEEPALIVE) {
            Ok(msg) => {
                if write!(stream, "data: {msg}\n\n").and_then(|_| stream.flush()).is_err() {
                    // Client gone: free the slot for a reconnect.
                    *sess.events.lock().unwrap() = None;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if write!(stream, ": keep-alive\n\n").and_then(|_| stream.flush()).is_err() {
                    *sess.events.lock().unwrap() = None;
                    break;
                }
            }
            // Session closed: the dispatcher dropped our sender.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(Next::Close)
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    target: String,
    /// Names lowercased at parse time; values trimmed.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn bearer(&self) -> Option<&str> {
        self.header("authorization")?
            .strip_prefix("Bearer ")
            .map(str::trim)
    }

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

struct HttpError {
    status: u16,
    reason: &'static str,
    message: String,
}

impl HttpError {
    fn new(status: u16, reason: &'static str, message: impl Into<String>) -> Self {
        HttpError {
            status,
            reason,
            message: message.into(),
        }
    }
}

/// Reads one request. `Ok(None)` means the connection ended between requests
/// — closed by the client or idle past the timeout — which calls for silence,
/// not an error page.
fn read_request(
    reader: &mut BufReader<TcpStream>,
    stream: &mut TcpStream,
) -> std::result::Result<Option<Request>, HttpError> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Ok(None)
        }
        Err(_) => return Ok(None),
    }

    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::new(400, "Bad Request", "malformed request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::new(505, "HTTP Version Not Supported", "HTTP/1.x only"));
    }
    let method = method.to_string();
    let target = target.to_string();

    let mut headers = Vec::new();
    let mut total = line.len();
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(_) => return Ok(None),
        }
        total += h.len();
        if total > MAX_HEADER_BYTES {
            return Err(HttpError::new(431, "Request Header Fields Too Large", "headers too large"));
        }
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        let Some((k, v)) = t.split_once(':') else {
            return Err(HttpError::new(400, "Bad Request", "malformed header"));
        };
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }

    let mut req = Request {
        method,
        target,
        headers,
        body: Vec::new(),
    };

    // Strictness over completeness: this parser reads exactly the subset MCP
    // clients emit. Chunked bodies are refused, not implemented.
    if req.header("transfer-encoding").is_some() {
        return Err(HttpError::new(411, "Length Required", "chunked bodies are not supported"));
    }

    let len = match req.header("content-length") {
        None => 0,
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| HttpError::new(400, "Bad Request", "invalid Content-Length"))?,
    };
    if len > MAX_BODY_BYTES {
        return Err(HttpError::new(413, "Payload Too Large", "body too large"));
    }

    if len > 0 {
        if req
            .header("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        {
            let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = stream.flush();
        }
        let mut body = vec![0u8; len];
        reader
            .read_exact(&mut body)
            .map_err(|_| HttpError::new(400, "Bad Request", "body shorter than Content-Length"))?;
        req.body = body;
    }

    Ok(Some(req))
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
    content_type: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n", body.len());
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    respond(stream, status, reason, extra, Some("application/json"), body)
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Vec<u8> {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
    .into_bytes()
}

/// A fresh session identifier.
///
/// The identifier is a capability: whoever holds it speaks as the session.
/// The spec asks for a cryptographically secure value and that is not
/// pedantry — a guessable id lets a neighbour inject calls into someone
/// else's audited session.
fn new_session_id() -> std::result::Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)?;
    Ok(hex::encode(bytes))
}
