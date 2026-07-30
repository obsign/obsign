//! End-to-end tests of the Streamable HTTP transport.
//!
//! Same philosophy as `e2e.rs` — run the real binary, speak the real
//! protocol, check both what the client receives and what the audit log
//! contains — but the client here is a raw TCP socket writing HTTP/1.1 by
//! hand. Deliberate: the gateway's HTTP layer is hand-written, so the tests
//! must not share its assumptions through a common client library.

use audit_core::evidence::{self, Evidence};
use audit_core::record::Payload;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use policy::bundle::{Bundle, FailBehaviour, FailMode, ToolDef, FORMAT};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const ISSUER: &str = "https://sso.acme.fr/realms/corp";
const AUDIENCE: &str = "obsign-proxy";

/// PKCS8 v1 prefix of an Ed25519 private key.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

const IDENTITY_SEED: [u8; 32] = [0x22; 32];

const CEDAR: &str = r#"
@id("forbid_destructive_prod")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && context.env == "prod" };

@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope != "" && context.scopes.contains(resource.required_scope) };

@id("allow_unscoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope == "" };
"#;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn keyring(policy_key: &SigningKey) -> Vec<audit_core::checkpoint::PublicKeyEntry> {
    let ik = SigningKey::from_bytes(&IDENTITY_SEED);
    vec![
        audit_core::checkpoint::PublicKeyEntry {
            key_id: "policy-key".to_string(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(policy_key.verifying_key().to_bytes()),
            role: Default::default(),
        },
        audit_core::checkpoint::PublicKeyEntry {
            key_id: "identity-key".to_string(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(ik.verifying_key().to_bytes()),
            role: Default::default(),
        },
    ]
}

fn identity_bundle_json() -> String {
    let vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let jwks: identity::JwkSet = serde_json::from_value(json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1",
            "alg": "EdDSA", "x": b64(vk.as_bytes()),
        }]
    }))
    .unwrap();

    let bundle = identity::IdentityBundle {
        format: identity::bundle::FORMAT.to_string(),
        version: "identity@test".to_string(),
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks,
        claims: identity::ClaimMap::default(),
    };
    let signed = bundle.sign("identity-key", &SigningKey::from_bytes(&IDENTITY_SEED));
    serde_json::to_string(&signed).unwrap()
}

fn mint(exp_offset: i64, scopes: &str) -> String {
    mint_for("u:marie.dupont", exp_offset, scopes)
}

fn mint_for(sub: &str, exp_offset: i64, scopes: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&[9u8; 32]);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("k1".to_string());

    let claims = json!({
        "sub": sub, "iss": ISSUER, "aud": AUDIENCE,
        "azp": "obsign-proxy",
        "exp": now + exp_offset, "iat": now - 10,
        "scope": scopes,
        "realm_access": { "roles": ["support-n2"] },
    });
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der)).unwrap()
}

/// A running HTTP gateway, killed on drop.
struct Gateway {
    child: Child,
    addr: String,
    dir: PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Starts the gateway on an OS-assigned port and reads the port back from its
/// stderr announcement — the only place it exists.
fn start(name: &str, oidc: bool, extra: &[&str]) -> Gateway {
    let dir = std::env::temp_dir().join(format!("obsign-http-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[0x11; 32]);
    let bundle = Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".to_string(),
        cedar: CEDAR.to_string(),
        tools: vec![
            ToolDef {
                name: "delete_production_db".into(),
                server: "mcp://test".into(),
                destructive: true,
                required_scope: Some("db:admin".into()),
            },
            ToolDef {
                name: "ticket_update".into(),
                server: "mcp://test".into(),
                destructive: false,
                required_scope: Some("support:ticket_update".into()),
            },
            ToolDef {
                name: "search_docs".into(),
                server: "mcp://test".into(),
                destructive: false,
                required_scope: None,
            },
        ],
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    };
    let signed = bundle.sign("policy-key", &key);
    std::fs::write(dir.join("bundle.json"), serde_json::to_string(&signed).unwrap()).unwrap();
    std::fs::write(
        dir.join("keys.json"),
        serde_json::to_string(&keyring(&key)).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_obsign-proxy"));
    cmd.args(["--policy", dir.join("bundle.json").to_str().unwrap()])
        .args(["--trusted-keys", dir.join("keys.json").to_str().unwrap()])
        .args(["--wal", dir.join("wal").to_str().unwrap()])
        .args(["--chain-id", "http", "--env", "prod"])
        .args(["--http", "127.0.0.1:0"]);

    if oidc {
        std::fs::write(dir.join("identity-bundle.json"), identity_bundle_json()).unwrap();
        cmd.args([
            "--identity-bundle",
            dir.join("identity-bundle.json").to_str().unwrap(),
        ]);
    } else {
        cmd.args(["--insecure-declared-identity", "--principal", "marie.dupont"])
            .args(["--scope", "support:ticket_update"]);
    }
    cmd.args(extra);

    let mut child = cmd
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_mock-mcp-server"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning obsign-proxy");

    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut addr = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Some(rest) = line.trim().strip_prefix("[obsign] Streamable HTTP on http://") {
            addr = rest.strip_suffix("/mcp").map(str::to_string);
            break;
        }
        line.clear();
    }
    // Keep draining stderr so the gateway never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        let _ = reader.read_to_string(&mut sink);
    });

    Gateway {
        child,
        addr: addr.expect("the gateway never announced its address"),
        dir,
    }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One request on a fresh connection.
fn http(gw: &Gateway, method: &str, headers: &[(&str, &str)], body: &str) -> Response {
    let mut stream = TcpStream::connect(&gw.addr).expect("connecting to the gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut req = format!("{method} /mcp HTTP/1.1\r\nHost: {}\r\n", gw.addr);
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("malformed status line: {status_line:?}"));

    let mut headers = Vec::new();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("content-length") {
                len = v.parse().unwrap();
            }
            headers.push((k, v));
        }
    }

    let mut raw = vec![0u8; len];
    reader.read_exact(&mut raw).unwrap();
    let body = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw).expect("JSON response body")
    };

    Response {
        status,
        headers,
        body,
    }
}

fn post(gw: &Gateway, headers: &[(&str, &str)], msg: Value) -> Response {
    http(gw, "POST", headers, &msg.to_string())
}

fn initialize(gw: &Gateway, extra_headers: &[(&str, &str)]) -> (String, Response) {
    let r = post(
        gw,
        extra_headers,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let sid = r
        .header("mcp-session-id")
        .expect("initialize response must carry Mcp-Session-Id")
        .to_string();
    (sid, r)
}

fn call(gw: &Gateway, sid: &str, extra: &[(&str, &str)], id: u64, tool: &str) -> Response {
    let mut headers: Vec<(&str, &str)> = vec![("Mcp-Session-Id", sid)];
    headers.extend_from_slice(extra);
    post(
        gw,
        &headers,
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
               "params":{"name":tool,"arguments":{}}}),
    )
}

/// Seals a session's WAL and assembles its evidence pack.
///
/// The gateway holds no signing key; DELETE only guarantees the log is
/// complete when it returns. This helper is the ledger's job run in-process
/// over that finished chain — the exact division of trust a deployment has.
fn evidence(gw: &Gateway, sid: &str) -> Evidence {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let chain_id = format!("http-{sid}");
    let records = wal::read(&gw.dir.join("wal"), &chain_id).unwrap_or_else(|e| {
        panic!("reading the WAL for session {sid}: {e}")
    });
    let mut store = ledger::Store::open(&gw.dir.join("ledger").join(sid), &chain_id)
        .expect("opening the store");
    let sealer = ledger::FileSealer::from_seed([0x33; 32], "seal-ledger");
    ledger::seal_pass(
        &records,
        &mut store,
        &sealer,
        &ledger::OriginPolicy::permissive(),
        now,
        1,
    )
    .expect("sealing the log");
    ledger::export(records, &store, &[], None)
}

// ===========================================================================

#[test]
fn session_lifecycle_enforces_and_seals() {
    let gw = start("lifecycle", false, &[]);

    let (sid, r) = initialize(&gw, &[]);
    assert_eq!(r.status, 200);
    assert!(
        r.body.pointer("/result/serverInfo").is_some(),
        "initialize must reach the wrapped server: {}",
        r.body
    );

    // tools/list is filtered exactly as over stdio.
    let r = post(
        &gw,
        &[("Mcp-Session-Id", &sid)],
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let tools: Vec<&str> = r
        .body
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap())
        .collect();
    assert!(tools.contains(&"ticket_update"));
    assert!(!tools.contains(&"delete_production_db"));
    assert!(!tools.contains(&"exfiltrate_secrets"));

    // Arbitration: the destructive call is refused in the server's place, the
    // scoped one goes through.
    let r = call(&gw, &sid, &[], 3, "delete_production_db");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(true)));

    let r = call(&gw, &sid, &[], 4, "ticket_update");
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(false)));

    // Notifications are accepted without a body to answer.
    let r = post(
        &gw,
        &[("Mcp-Session-Id", &sid)],
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(r.status, 202);

    // DELETE closes the log: when it returns, the WAL holds the complete
    // session and a ledger pass seals it into a pack verifiable offline.
    let r = http(&gw, "DELETE", &[("Mcp-Session-Id", &sid)], "");
    assert_eq!(r.status, 200);

    let ev = evidence(&gw, &sid);
    let keys = ev.keys.clone();
    let report = evidence::verify(&ev, &keys);
    assert!(report.is_valid(), "findings: {:?}", report.findings);
    assert_eq!(report.records_sealed, report.records_total);

    let outcomes: Vec<String> = ev
        .records
        .iter()
        .filter_map(|r| match &r.payload {
            Payload::Decision(d) => Some(d.outcome.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(outcomes, vec!["deny", "allow"]);

    // The session is really gone.
    let r = call(&gw, &sid, &[], 9, "ticket_update");
    assert_eq!(r.status, 404);
}

#[test]
fn requests_without_a_session_are_refused() {
    let gw = start("no-session", false, &[]);

    // No header at all.
    let r = post(
        &gw,
        &[],
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.status, 400);

    // A guessed identifier. This is the whole reason session ids are random:
    // an id you did not receive is an id that does not work.
    let r = call(&gw, "0000feedbeef0000", &[], 1, "ticket_update");
    assert_eq!(r.status, 404);
}

#[test]
fn an_id_less_act_is_arbitrated_not_smuggled() {
    // Regression: request-shaped messages sent without an id took the
    // notification fast path and were forwarded raw — no policy, no record.
    // JSON-RPC says a server should not execute them, but the invariant must
    // not depend on the wrapped server's parser.
    let gw = start("noid", false, &[]);
    let (sid, _) = initialize(&gw, &[]);

    // A forbidden act is refused in the server's place, null id and all.
    let r = post(
        &gw,
        &[("Mcp-Session-Id", &sid)],
        json!({"jsonrpc":"2.0","method":"tools/call",
               "params":{"name":"delete_production_db","arguments":{}}}),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(true)));

    // An allowed act forwards — records written first, nothing to wait for.
    let r = post(
        &gw,
        &[("Mcp-Session-Id", &sid)],
        json!({"jsonrpc":"2.0","method":"tools/call",
               "params":{"name":"ticket_update","arguments":{}}}),
    );
    assert_eq!(r.status, 202);

    let r = http(&gw, "DELETE", &[("Mcp-Session-Id", &sid)], "");
    assert_eq!(r.status, 200);

    // Both acts left their decision in the sealed log.
    let ev = evidence(&gw, &sid);
    let outcomes: Vec<String> = ev
        .records
        .iter()
        .filter_map(|r| match &r.payload {
            Payload::Decision(d) => Some(d.outcome.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(outcomes, vec!["deny", "allow"]);
}

#[test]
fn sessions_are_isolated_from_each_other() {
    let gw = start("isolation", false, &[]);

    let (sid_a, _) = initialize(&gw, &[]);
    let (sid_b, _) = initialize(&gw, &[]);
    assert_ne!(sid_a, sid_b);

    call(&gw, &sid_a, &[], 2, "ticket_update");

    // Closing B must not disturb A.
    assert_eq!(http(&gw, "DELETE", &[("Mcp-Session-Id", &sid_b)], "").status, 200);
    let r = call(&gw, &sid_a, &[], 3, "ticket_update");
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(false)));

    assert_eq!(http(&gw, "DELETE", &[("Mcp-Session-Id", &sid_a)], "").status, 200);

    // Each chain seals independently and carries only its own session.
    let ev_a = evidence(&gw, &sid_a);
    let ev_b = evidence(&gw, &sid_b);
    assert!(ev_a.records.iter().all(|r| r.session_id == sid_a));
    assert!(ev_b.records.iter().all(|r| r.session_id == sid_b));
    assert_eq!(
        ev_a.records
            .iter()
            .filter(|r| matches!(r.payload, Payload::ToolCall(_)))
            .count(),
        2
    );
}

#[test]
fn oidc_identity_arrives_in_the_authorization_header() {
    let gw = start("oidc", true, &[]);
    let token = mint(1800, "support:ticket_update");
    let auth_header = format!("Bearer {token}");

    // No token, no session: nothing could be attributed.
    let r = post(
        &gw,
        &[],
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(r.status, 401);

    let (sid, r) = initialize(&gw, &[("Authorization", &auth_header)]);
    assert_eq!(r.status, 200);

    // Every request carries the token; the covered call passes, the
    // destructive one stays refused.
    let hdrs = [("Authorization", auth_header.as_str())];
    let r = call(&gw, &sid, &hdrs, 2, "ticket_update");
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(false)));
    let r = call(&gw, &sid, &hdrs, 3, "delete_production_db");
    assert_eq!(r.body.pointer("/result/isError"), Some(&Value::Bool(true)));

    // A request that drops the token gets 401, not a silent downgrade.
    let r = call(&gw, &sid, &[], 4, "ticket_update");
    assert_eq!(r.status, 401);

    http(
        &gw,
        "DELETE",
        &[("Mcp-Session-Id", &sid), ("Authorization", &auth_header)],
        "",
    );

    // The log carries the proven issuer, from the header token.
    let ev = evidence(&gw, &sid);
    let deleg = ev
        .records
        .iter()
        .find_map(|r| match &r.payload {
            Payload::Delegation(d) => Some(d.clone()),
            _ => None,
        })
        .expect("a delegation record");
    assert_eq!(deleg.principal_issuer, ISSUER);
    assert_eq!(deleg.principal_sub, "u:marie.dupont");
}

#[test]
fn an_expired_token_cannot_open_a_session() {
    let gw = start("oidc-expired", true, &[]);
    let auth_header = format!("Bearer {}", mint(-3600, "support:ticket_update"));
    let r = post(
        &gw,
        &[("Authorization", &auth_header)],
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(r.status, 401);
}

#[test]
fn the_get_stream_carries_server_notifications() {
    let gw = start("sse", false, &[]);
    let (sid, _) = initialize(&gw, &[]);

    // Open the stream on its own connection, as a client would.
    let mut stream = TcpStream::connect(&gw.addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET /mcp HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nMcp-Session-Id: {sid}\r\n\r\n",
        gw.addr
    )
    .unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("200"), "GET refused: {line:?}");
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        if h.trim_end().is_empty() {
            break;
        }
        if h.to_ascii_lowercase().starts_with("content-type") {
            assert!(h.contains("text/event-stream"), "wrong content type: {h:?}");
        }
    }

    // The mock server emits a notification while executing this tool; it has
    // nowhere to go but the stream.
    call(&gw, &sid, &[], 2, "ticket_update");

    let data = loop {
        let mut l = String::new();
        reader.read_line(&mut l).expect("the stream went silent");
        if let Some(payload) = l.trim_end().strip_prefix("data: ") {
            break payload.to_string();
        }
    };
    let notif: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        notif.get("method").and_then(Value::as_str),
        Some("notifications/resources/updated")
    );

    // A second stream on the same session would silently split the
    // notification flow: refused.
    let r = http(
        &gw,
        "GET",
        &[("Accept", "text/event-stream"), ("Mcp-Session-Id", &sid)],
        "",
    );
    assert_eq!(r.status, 409);
}

#[test]
fn concurrent_identities_keep_their_own_attribution_subtrees() {
    // Two principals share one MCP session — per-request bearers make that
    // legal — and their calls race on separate connections. The gateway once
    // snapshotted the identity under the auth lock, released it, then took
    // the session lock to write the call: in that gap the other principal
    // could record its delegation and move `agent_record_id`, and a call
    // whose token had not changed attached under the wrong subtree. The
    // invariant checked here is interleaving-independent: every call in the
    // log must climb, through its parents, to the delegation of the token
    // that carried it. Each principal calls a distinct tool so the log
    // itself says who was really calling.
    let gw = start("concurrent-ids", true, &[]);
    let alice = format!(
        "Bearer {}",
        mint_for("u:alice.durand", 1800, "support:ticket_update")
    );
    let bob = format!(
        "Bearer {}",
        mint_for("u:bob.martin", 1800, "support:ticket_update")
    );

    let (sid, r) = initialize(&gw, &[("Authorization", &alice)]);
    assert_eq!(r.status, 200);

    const N: u64 = 25;
    std::thread::scope(|scope| {
        let alice_thread = scope.spawn(|| {
            for i in 0..N {
                let r = call(&gw, &sid, &[("Authorization", &alice)], 1000 + i, "search_docs");
                assert_eq!(
                    r.body.pointer("/result/isError"),
                    Some(&Value::Bool(false)),
                    "alice call {i}: {}",
                    r.body
                );
            }
        });
        for i in 0..N {
            let r = call(&gw, &sid, &[("Authorization", &bob)], 2000 + i, "ticket_update");
            assert_eq!(
                r.body.pointer("/result/isError"),
                Some(&Value::Bool(false)),
                "bob call {i}: {}",
                r.body
            );
        }
        alice_thread.join().unwrap();
    });

    http(
        &gw,
        "DELETE",
        &[("Mcp-Session-Id", &sid), ("Authorization", &alice)],
        "",
    );

    // The interleaved writes must still seal into a valid pack.
    let ev = evidence(&gw, &sid);
    let keys = ev.keys.clone();
    let report = evidence::verify(&ev, &keys);
    assert!(report.is_valid(), "findings: {:?}", report.findings);

    let by_id: std::collections::HashMap<&str, &audit_core::record::Record> =
        ev.records.iter().map(|r| (r.id.as_str(), &r.record)).collect();

    let mut checked = 0;
    for rec in &ev.records {
        let Payload::ToolCall(tc) = &rec.payload else { continue };
        // call -> agent_session -> actor -> delegation.
        let mut cursor = &rec.record;
        let sub = loop {
            let parent = cursor
                .parent_id
                .as_deref()
                .unwrap_or_else(|| panic!("{} never reaches a delegation", rec.id));
            cursor = by_id[parent];
            if let Payload::Delegation(d) = &cursor.payload {
                break d.principal_sub.clone();
            }
        };
        let expected = match tc.tool.as_str() {
            "search_docs" => "u:alice.durand",
            "ticket_update" => "u:bob.martin",
            other => panic!("unexpected tool in the log: {other}"),
        };
        assert_eq!(
            sub, expected,
            "{} ({}) is attributed to {sub}",
            rec.id, tc.tool
        );
        checked += 1;
    }
    assert_eq!(checked, 2 * N as usize, "every call must have been audited");
}

#[test]
fn a_foreign_origin_is_refused() {
    // DNS rebinding: a hostile page pointing a victim's browser at the
    // gateway arrives with the page's Origin. Nothing configured, nothing
    // allowed.
    let gw = start("origin", false, &[]);
    let r = post(
        &gw,
        &[("Origin", "http://evil.example")],
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(r.status, 403);
}

#[test]
fn batches_are_refused() {
    let gw = start("batch", false, &[]);
    let (sid, _) = initialize(&gw, &[]);
    let r = post(
        &gw,
        &[("Mcp-Session-Id", &sid)],
        json!([{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}]),
    );
    assert_eq!(r.status, 400);
}
