//! End-to-end gateway tests.
//!
//! Runs the real `probant-proxy` binary in front of an MCP server that obeys everything,
//! sends it JSON-RPC traffic, and checks both what the agent receives and what
//! the audit log contains.
//!
//! Two of the bugs these tests lock down were found by a manual demo, not by
//! unit tests: a duplicated effect identifier when two calls are in flight,
//! and auto-numbered — hence unstable — Cedar rule identifiers. Neither breaks
//! the integrity chain; both ruin the log's usefulness.

use audit_core::evidence::{self, Evidence};
use audit_core::record::Payload;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use policy::bundle::{Bundle, FailBehaviour, FailMode, ToolDef, FORMAT};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const ISSUER: &str = "https://sso.acme.fr/realms/corp";
const AUDIENCE: &str = "probant-proxy";

/// PKCS8 v1 prefix of an Ed25519 private key.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Signing key for the identity bundle, distinct from the policy one:
/// compromising one must not yield the other.
const IDENTITY_SEED: [u8; 32] = [0x22; 32];

/// Trusted keyring: the policy key and the identity key.
fn keyring(policy_key: &SigningKey) -> Vec<audit_core::checkpoint::PublicKeyEntry> {
    let ik = SigningKey::from_bytes(&IDENTITY_SEED);
    vec![
        audit_core::checkpoint::PublicKeyEntry {
            key_id: "policy-key".to_string(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(policy_key.verifying_key().to_bytes()),
        },
        audit_core::checkpoint::PublicKeyEntry {
            key_id: "identity-key".to_string(),
            algo: "ed25519".to_string(),
            public_key: hex::encode(ik.verifying_key().to_bytes()),
        },
    ]
}

/// Signed identity bundle; the token claims use the Keycloak shape.
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

/// Mints a token expiring in `exp_offset` seconds (negative = already expired).
fn mint(exp_offset: i64, scopes: &str, act: Option<&str>) -> String {
    mint_full(exp_offset, scopes, act, false)
}

fn mint_full(exp_offset: i64, scopes: &str, act: Option<&str>, service: bool) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&[9u8; 32]);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("k1".to_string());

    // Keycloak shape: roles are not flat.
    let mut claims = json!({
        "sub": "u:marie.dupont", "iss": ISSUER, "aud": AUDIENCE,
        "azp": "probant-proxy",
        "exp": now + exp_offset, "iat": now - 10,
        "scope": scopes,
        "realm_access": { "roles": ["support-n2"] },
        "resource_access": { "probant-proxy": { "roles": ["ticket-writer"] } },
    });
    if let Some(a) = act {
        claims["act"] = json!({ "sub": a });
    }
    if service {
        // client_credentials: `sub` == `client_id`, nobody behind it.
        claims["sub"] = json!("batch-agent");
        claims["azp"] = json!("batch-agent");
        claims["client_id"] = json!("batch-agent");
    }

    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der)).unwrap()
}

/// How the gateway establishes the agent's identity.
#[derive(Clone)]
enum Ident {
    /// Declared on the command line, unverified.
    Declared { scopes: Vec<String> },
    /// Proven by an OIDC token, with its validity window.
    Oidc {
        exp_offset: i64,
        scopes: String,
        /// Actor of the `act` claim (RFC 8693 token exchange).
        act: Option<String>,
        /// `client_credentials` token: `sub` == `client_id`, no human.
        service: bool,
    },
}

fn oidc(scopes: &str) -> Ident {
    Ident::Oidc {
        exp_offset: 1800,
        scopes: scopes.to_string(),
        act: None,
        service: false,
    }
}

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

struct Fixture {
    dir: PathBuf,
    evidence: Evidence,
    stdout: Vec<Value>,
    stderr: String,
    /// False when the gateway refused to start.
    started: bool,
}

fn tool(name: &str, destructive: bool, scope: Option<&str>) -> ToolDef {
    ToolDef {
        name: name.into(),
        server: "mcp://test".into(),
        destructive,
        required_scope: scope.map(String::from),
    }
}

fn run(name: &str, cedar: &str, ident: Ident, traffic: &[&str]) -> Fixture {
    let dir = std::env::temp_dir().join(format!("probant-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[0x11; 32]);
    let bundle = Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".to_string(),
        cedar: cedar.to_string(),
        tools: vec![
            tool("delete_production_db", true, Some("db:admin")),
            tool("ticket_update", false, Some("support:ticket_update")),
            tool("search_docs", false, None),
        ],
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    };
    let signed = bundle.sign("policy-key", &key);
    let keys = keyring(&key);

    let bundle_path = dir.join("bundle.json");
    let keys_path = dir.join("keys.json");
    let evidence_path = dir.join("evidence.json");
    std::fs::write(&bundle_path, serde_json::to_string(&signed).unwrap()).unwrap();
    std::fs::write(&keys_path, serde_json::to_string(&keys).unwrap()).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_probant-proxy"));
    cmd.arg("--policy")
        .arg(&bundle_path)
        .arg("--trusted-keys")
        .arg(&keys_path)
        .arg("--wal")
        .arg(dir.join("wal"))
        .arg("--chain-id")
        .arg("test")
        .arg("--env")
        .arg("prod")
        .arg("--evidence-out")
        .arg(&evidence_path);

    match &ident {
        Ident::Declared { scopes } => {
            cmd.arg("--insecure-declared-identity")
                .arg("--principal")
                .arg("marie.dupont");
            for s in scopes {
                cmd.arg("--scope").arg(s);
            }
        }
        Ident::Oidc {
            exp_offset,
            scopes,
            act,
            service,
        } => {
            let ib_path = dir.join("identity-bundle.json");
            let token_path = dir.join("token.jwt");
            std::fs::write(&ib_path, identity_bundle_json()).unwrap();
            std::fs::write(
                &token_path,
                mint_full(*exp_offset, scopes, act.as_deref(), *service),
            )
            .unwrap();
            cmd.arg("--identity-bundle")
                .arg(&ib_path)
                .arg("--token-file")
                .arg(&token_path);
        }
    }

    cmd.arg("--")
        .arg(env!("CARGO_BIN_EXE_mock-mcp-server"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawning probant-proxy");
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in traffic {
            let _ = writeln!(stdin, "{line}");
        }
    }
    let out = child.wait_with_output().expect("waiting for probant-proxy");

    let stdout = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("valid JSON response"))
        .collect();

    // A refused startup (invalid identity) produces no pack.
    let started = evidence_path.exists();
    let evidence: Evidence = if started {
        serde_json::from_str(&std::fs::read_to_string(&evidence_path).unwrap()).unwrap()
    } else {
        Evidence {
            format: audit_core::evidence::FORMAT.to_string(),
            chain_id: String::new(),
            records: Vec::new(),
            checkpoints: Vec::new(),
            keys: Vec::new(),
        }
    };

    Fixture {
        dir,
        evidence,
        stdout,
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        started,
    }
}

fn declared() -> Ident {
    Ident::Declared {
        scopes: vec!["support:ticket_update".to_string()],
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn reply(&self, id: u64) -> &Value {
        self.stdout
            .iter()
            .find(|v| v.get("id").and_then(Value::as_u64) == Some(id))
            .unwrap_or_else(|| panic!("no response for id={id}"))
    }

    fn decisions(&self) -> Vec<(String, Option<String>)> {
        self.evidence
            .records
            .iter()
            .filter_map(|r| match &r.payload {
                Payload::Decision(d) => {
                    Some((d.outcome.as_str().to_string(), d.policy_id.clone()))
                }
                _ => None,
            })
            .collect()
    }
}

const TRAFFIC: &[&str] = &[
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_production_db","arguments":{"database":"customers"}}}"#,
    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ticket_update","arguments":{"ticket":"T-8821"}}}"#,
    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"exfiltrate_secrets","arguments":{}}}"#,
];

#[test]
fn destructive_tool_in_prod_is_blocked_before_the_server() {
    let f = run("deny", CEDAR, declared(), TRAFFIC);

    // The agent receives an errored tool result, not a JSON-RPC error: it can
    // fall back to something else instead of treating the session as
    // broken.
    let r = f.reply(3);
    assert_eq!(r.pointer("/result/isError"), Some(&Value::Bool(true)));

    // And crucially: the server never executed the call. This is the only
    // assertion that really counts — blocking after the fact is useless.
    assert!(
        !f.stderr.contains("[server] EXECUTING delete_production_db"),
        "the call reached the MCP server:\n{}",
        f.stderr
    );
    assert!(
        f.stderr.contains("[server] EXECUTING ticket_update"),
        "the allowed call should have been executed"
    );
}

#[test]
fn tool_outside_the_catalogue_is_refused() {
    // A compromised or updated MCP server can advertise new tools. What the
    // signed catalogue does not describe does not get through.
    let f = run("catalog", CEDAR, declared(), TRAFFIC);
    assert_eq!(f.reply(5).pointer("/result/isError"), Some(&Value::Bool(true)));
    assert!(f.stderr.contains("absent from signed catalogue"));
    assert!(!f.stderr.contains("[server] EXECUTING exfiltrate_secrets"));
}

#[test]
fn tools_list_is_filtered() {
    let f = run("list", CEDAR, declared(), TRAFFIC);
    let tools: Vec<&str> = f
        .reply(2)
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap())
        .collect();

    assert!(tools.contains(&"ticket_update"));
    assert!(tools.contains(&"search_docs"));
    assert!(
        !tools.contains(&"delete_production_db"),
        "a forbidden tool is still visible: the agent will attempt it"
    );
    assert!(!tools.contains(&"exfiltrate_secrets"));
}

#[test]
fn rule_identifiers_are_stable_in_the_log() {
    // Regression: Cedar numbers rules `policy0`, `policy1`... by file order.
    // A log referencing `policy0` becomes wrong as soon as a rule is inserted
    // at the top.
    let f = run("ids", CEDAR, declared(), TRAFFIC);
    let d = f.decisions();

    assert_eq!(
        d[0],
        ("deny".into(), Some("forbid_destructive_prod".into())),
        "unstable or missing rule identifier"
    );
    assert_eq!(d[1], ("allow".into(), Some("allow_scoped".into())));
    // Out-of-catalogue refusal: no rule decided, hence no identifier.
    assert_eq!(d[2], ("deny".into(), None));
}

#[test]
fn record_identifiers_stay_unique_despite_asynchrony() {
    // Regression: the effect identifier was derived from a counter read when
    // the response arrived. Since MCP responses come back out of order, two
    // effects got the same identifier and the attribution graph became
    // ambiguous.
    let f = run("unique", CEDAR, declared(), TRAFFIC);

    let ids: Vec<&str> = f.evidence.records.iter().map(|r| r.id.as_str()).collect();
    let uniques: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        ids.len(),
        uniques.len(),
        "duplicate identifiers in the attribution chain: {ids:?}"
    );

    // Every referenced parent must exist.
    for r in &f.evidence.records {
        if let Some(p) = &r.parent_id {
            assert!(
                ids.contains(&p.as_str()),
                "record {} references a non-existent parent {p}",
                r.id
            );
        }
    }
}

#[test]
fn the_produced_evidence_pack_is_verifiable() {
    let f = run("verify", CEDAR, declared(), TRAFFIC);
    let keys = f.evidence.keys.clone();
    let report = evidence::verify(&f.evidence, &keys);

    assert!(report.is_valid(), "findings: {:?}", report.findings);
    assert_eq!(
        report.records_sealed, report.records_total,
        "everything logged must be sealed on shutdown"
    );
}

#[test]
fn the_log_resumes_after_restart() {
    // Two successive runs against the same WAL: the chain must continue, not
    // restart from zero.
    let dir = std::env::temp_dir().join(format!("probant-e2e-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[0x11; 32]);
    let bundle = Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".to_string(),
        cedar: CEDAR.to_string(),
        tools: vec![tool("search_docs", false, None)],
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    };
    let signed = bundle.sign("policy-key", &key);
    let keys = keyring(&key);
    std::fs::write(dir.join("bundle.json"), serde_json::to_string(&signed).unwrap()).unwrap();
    std::fs::write(dir.join("keys.json"), serde_json::to_string(&keys).unwrap()).unwrap();

    let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{}}}"#;

    let mut seqs = Vec::new();
    for run_idx in 0..2 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_probant-proxy"))
            .args(["--policy", dir.join("bundle.json").to_str().unwrap()])
            .args(["--trusted-keys", dir.join("keys.json").to_str().unwrap()])
            .args(["--wal", dir.join("wal").to_str().unwrap()])
            .args(["--chain-id", "resume", "--env", "prod"])
            .args(["--insecure-declared-identity", "--principal", "m"])
            .args([
                "--evidence-out",
                dir.join(format!("ev{run_idx}.json")).to_str().unwrap(),
            ])
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_mock-mcp-server"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{call}").unwrap();
        child.wait_with_output().unwrap();

        let ev: Evidence = serde_json::from_str(
            &std::fs::read_to_string(dir.join(format!("ev{run_idx}.json"))).unwrap(),
        )
        .unwrap();
        seqs.push(ev.records.last().unwrap().seq);
    }

    assert!(
        seqs[1] > seqs[0],
        "the chain restarted from zero: {seqs:?}"
    );

    // The second run's pack holds the full history and stays verifiable end
    // to end.
    let ev: Evidence =
        serde_json::from_str(&std::fs::read_to_string(dir.join("ev1.json")).unwrap()).unwrap();
    let keys = ev.keys.clone();
    let report = evidence::verify(&ev, &keys);
    assert!(report.is_valid(), "findings: {:?}", report.findings);

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// Identite : declaree contre prouvee
// =====================================================================

/// Runs `probant-proxy` with raw arguments and no traffic. Used to check startup
/// refusals.
fn start_only(name: &str, extra: &[&str]) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("probant-start-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[0x11; 32]);
    let bundle = Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".to_string(),
        cedar: CEDAR.to_string(),
        tools: vec![tool("search_docs", false, None)],
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    };
    let signed = bundle.sign("policy-key", &key);
    let keys = keyring(&key);
    std::fs::write(dir.join("bundle.json"), serde_json::to_string(&signed).unwrap()).unwrap();
    std::fs::write(dir.join("keys.json"), serde_json::to_string(&keys).unwrap()).unwrap();
    std::fs::write(dir.join("identity-bundle.json"), identity_bundle_json()).unwrap();
    std::fs::write(dir.join("token.jwt"), mint(1800, "support:read", None)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_probant-proxy"))
        .args(["--policy", dir.join("bundle.json").to_str().unwrap()])
        .args(["--trusted-keys", dir.join("keys.json").to_str().unwrap()])
        .args(["--wal", dir.join("wal").to_str().unwrap()])
        .args(["--chain-id", "start"])
        .args(
            extra
                .iter()
                .map(|a| a.replace("{dir}", dir.to_str().unwrap()))
                .collect::<Vec<_>>(),
        )
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_mock-mcp-server"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawning probant-proxy");

    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn proven_identity_is_recorded_with_its_real_issuer() {
    let f = run(
        "oidc-ok",
        CEDAR,
        oidc("support:ticket_update"),
        TRAFFIC,
    );
    assert!(f.started, "the gateway should have started:\n{}", f.stderr);

    let deleg = f
        .evidence
        .records
        .iter()
        .find_map(|r| match &r.payload {
            Payload::Delegation(d) => Some(d.clone()),
            _ => None,
        })
        .expect("a delegation record");

    // This is the field that attests in the log that the identity was
    // verified, not merely asserted.
    assert_eq!(deleg.principal_issuer, ISSUER);
    assert_eq!(deleg.principal_sub, "u:marie.dupont");
    assert!(
        deleg.expires_at_ms > 0 && deleg.expires_at_ms != i64::MAX,
        "expiry must come from the token"
    );
    assert!(f.stderr.contains("identity PROVEN"));

    // Scopes come from the token, not the command line: the covered call is
    // allowed, the destructive one stays refused.
    assert!(f.stderr.contains("[server] EXECUTING ticket_update"));
    assert!(!f.stderr.contains("[server] EXECUTING delete_production_db"));
}

#[test]
fn declared_identity_is_marked_as_unproven() {
    let f = run("declared-mark", CEDAR, declared(), TRAFFIC);

    let deleg = f
        .evidence
        .records
        .iter()
        .find_map(|r| match &r.payload {
            Payload::Delegation(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    // An auditor reading `cli://declared` immediately knows nothing was
    // verified. That is the point: never let anyone believe otherwise.
    assert_eq!(deleg.principal_issuer, "cli://declared");
    assert!(f.stderr.contains("identity DECLARED, unverified"));
}

#[test]
fn an_expired_token_prevents_startup() {
    let f = run(
        "oidc-expired",
        CEDAR,
        Ident::Oidc {
            exp_offset: -3600,
            scopes: "support:ticket_update".to_string(),
            act: None,
            service: false,
        },
        TRAFFIC,
    );

    assert!(
        !f.started,
        "the gateway started with an expired token:\n{}",
        f.stderr
    );
    // And nothing was relayed: no call reached the server.
    assert!(!f.stderr.contains("[server] EXECUTING"));
}

#[test]
fn an_ambiguous_identity_configuration_is_refused() {
    // Mixing OIDC and declared identity would leave doubt about what is
    // authoritative. We refuse rather than choose on the operator's behalf.
    let out = start_only(
        "ambigu",
        &[
            "--insecure-declared-identity",
            "--principal",
            "marie",
            "--identity-bundle",
            "{dir}/identity-bundle.json",
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("incompatible"), "unclear message: {err}");
}

#[test]
fn an_unconfigured_identity_is_refused() {
    // No permissive default: with no identity configuration the gateway does
    // not start. The worst outcome would be silently falling back to anonymous
    // mode.
    let out = start_only("aucune", &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("identity not configured"),
        "unclear message: {err}"
    );
}

// =====================================================================
// Delegation chain: token exchange and service accounts
// =====================================================================

/// Policy adding the rule "nothing destructive without a human at the root".
const CEDAR_HUMAIN: &str = r#"
@id("destructif_exige_humain")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };

@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope != "" && context.scopes.contains(resource.required_scope) };

@id("allow_unscoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope == "" };
"#;

fn actors(f: &Fixture) -> Option<(Vec<String>, String)> {
    f.evidence.records.iter().find_map(|r| match &r.payload {
        Payload::Actor(a) => Some((a.chain.clone(), a.principal_kind.as_str().to_string())),
        _ => None,
    })
}

#[test]
fn nested_keycloak_roles_are_read() {
    // The test token uses the Keycloak shape: nothing flat, everything under
    // `realm_access.roles` and `resource_access.<client>.roles`. A naive
    // mapping would return empty groups and no group-based rule would ever
    // match.
    let f = run("keycloak", CEDAR, oidc("support:ticket_update"), TRAFFIC);
    assert!(f.started, "{}", f.stderr);

    let deleg = f
        .evidence
        .records
        .iter()
        .find_map(|r| match &r.payload {
            Payload::Delegation(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    // Scopes were extracted, otherwise startup would have failed on
    // `NoScopes`.
    assert!(deleg.scopes.contains(&"support:ticket_update".to_string()));
}

#[test]
fn token_exchange_records_the_actor_chain() {
    let f = run(
        "exchange",
        CEDAR,
        Ident::Oidc {
            exp_offset: 1800,
            scopes: "support:ticket_update".to_string(),
            act: Some("support-copilot".to_string()),
            service: false,
        },
        TRAFFIC,
    );
    assert!(f.started, "{}", f.stderr);

    let (chain, kind) = actors(&f).expect("an actor record");
    // From outermost (the acting agent) to innermost (the human).
    assert_eq!(chain, vec!["support-copilot", "u:marie.dupont"]);
    assert_eq!(kind, "delegated_human");
}

#[test]
fn a_plain_user_token_yields_a_single_element_chain() {
    let f = run("simple", CEDAR, oidc("support:ticket_update"), TRAFFIC);
    let (chain, kind) = actors(&f).expect("an actor record");
    assert_eq!(chain, vec!["u:marie.dupont"]);
    assert_eq!(kind, "human");
}

#[test]
fn a_service_account_is_marked_machine() {
    let f = run(
        "service-mark",
        CEDAR,
        Ident::Oidc {
            exp_offset: 1800,
            scopes: "support:ticket_update".to_string(),
            act: None,
            service: true,
        },
        TRAFFIC,
    );
    assert!(f.started, "{}", f.stderr);

    let (chain, kind) = actors(&f).expect("an actor record");
    assert_eq!(chain, vec!["batch-agent"]);
    assert_eq!(
        kind, "machine",
        "a client_credentials token has no human behind it"
    );
}

#[test]
fn a_service_account_is_blocked_on_a_destructive_tool() {
    // The product rule: "no agent destroys anything without an identifiable
    // human at the end of the chain". Here the tool is not even in
    // production — it really is the missing human that blocks.
    let f = run(
        "service-deny",
        CEDAR_HUMAIN,
        Ident::Oidc {
            exp_offset: 1800,
            scopes: "db:admin".to_string(),
            act: None,
            service: true,
        },
        TRAFFIC,
    );
    assert!(f.started, "{}", f.stderr);

    assert_eq!(f.reply(3).pointer("/result/isError"), Some(&Value::Bool(true)));
    assert!(
        !f.stderr.contains("[server] EXECUTING delete_production_db"),
        "the destructive call reached the server:\n{}",
        f.stderr
    );

    let decision = f
        .evidence
        .records
        .iter()
        .find_map(|r| match &r.payload {
            Payload::Decision(d) if d.policy_id.is_some() => d.policy_id.clone(),
            _ => None,
        })
        .unwrap();
    assert_eq!(decision, "destructif_exige_humain");
}

#[test]
fn a_delegated_human_keeps_destructive_access() {
    // Counter-check: same policy, same tool, but an attested human at the
    // root. Without it, a passing test would only prove "everything is
    // blocked".
    let f = run(
        "human-allow",
        CEDAR_HUMAIN,
        Ident::Oidc {
            exp_offset: 1800,
            scopes: "db:admin".to_string(),
            act: Some("support-copilot".to_string()),
            service: false,
        },
        TRAFFIC,
    );
    assert!(f.started, "{}", f.stderr);
    assert!(
        f.stderr.contains("[server] EXECUTING delete_production_db"),
        "the delegated human should have been allowed:\n{}",
        f.stderr
    );
}
