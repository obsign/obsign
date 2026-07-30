//! MCP gateway: a transparent proxy that enforces a signed policy and
//! engraves every act into an audit log.
//!
//! It sits between the agent and the MCP server. The wrapped server is always
//! spawned as a child over stdio; on the agent side the gateway speaks either
//! stdio (the default — you swap the MCP server command in the agent's
//! configuration, that is all) or Streamable HTTP (`--http`, one session per
//! agent, see `http.rs`).
//!
//! Three interceptions, identical on both transports:
//!
//! * `tools/list`: the response is filtered, the agent only sees the tools the
//!   policy allows it. What you cannot see, you do not attempt.
//! * `tools/call`: identity verified, policy evaluated, act logged, then
//!   forwarded or refused.
//! * everything else: relayed as-is.
//!
//! **All logging goes to stderr.** stdout is the MCP channel in stdio mode:
//! one stray `println!` and the protocol is broken.

mod auth;
mod gateway;
mod http;
mod origin;
#[cfg(test)]
mod testutil;
mod session;

use anyhow::{bail, Context as _, Result};
use auth::Auth;
use clap::Parser;
use gateway::{handle_from_agent, handle_from_server, spawn_server, Ctx, Forward};
use identity::BundleSource;
use origin::OriginSigner as _;
use policy::{Engine, SignedBundle};
use serde_json::Value;
use session::now_ms;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use wal::Wal;

#[derive(Parser)]
#[command(
    name = "probant-proxy",
    about = "MCP proxy enforcing a signed policy and logging every act",
    long_about = "Sits between an agent and an MCP server (stdio or Streamable\n\
                  HTTP transport). Filters tools/list, arbitrates tools/call,\n\
                  and engraves everything into an offline-verifiable audit log."
)]
struct Cli {
    /// Signed policy bundle (JSON)
    #[arg(long)]
    policy: PathBuf,

    /// Trusted public keys, used to verify both bundles (JSON)
    #[arg(long)]
    trusted_keys: PathBuf,

    // --- Transport ------------------------------------------------------
    /// Serve MCP over Streamable HTTP on this address (e.g. 127.0.0.1:8080)
    /// instead of stdio. Each session gets its own audit chain and its own
    /// instance of the wrapped server; identity arrives per request in the
    /// Authorization header.
    #[arg(long)]
    http: Option<String>,

    /// Origin allowed on the HTTP endpoint (repeatable). Requests carrying
    /// any other Origin are refused — the DNS-rebinding defence. Non-browser
    /// clients send no Origin and are unaffected.
    #[arg(long = "allowed-origin")]
    allowed_origins: Vec<String>,

    // --- Identity: OIDC (normal) --------------------------------------
    /// Signed identity bundle: issuer, audience, JWKS, claim mapping.
    ///
    /// Signed because the JWKS decides who can mint valid tokens, and the
    /// claim mapping decides which groups get assigned. Whoever can write this
    /// file can mint an identity for themselves.
    #[arg(long)]
    identity_bundle: Option<PathBuf>,

    /// File holding the access token, stdio transport only. Re-read
    /// automatically on expiry. Over HTTP the token arrives per request.
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

    /// Origin key seed (32 bytes, hex): the gateway signs every record it
    /// writes directly with this key (v0/v1). Without it — and without
    /// --identity-key — the log is chained but unsigned.
    #[arg(long, conflicts_with = "identity_key")]
    origin_key: Option<PathBuf>,

    /// Identity key seed (32 bytes, hex): the two-tier scheme (v2). This
    /// long-lived key certifies a fresh session key per chain; the session
    /// key — generated in memory, never on disk — signs the records. The
    /// seed file is dev-grade; production uses --identity-hsm-module.
    #[arg(long, conflicts_with = "identity_hsm_module")]
    identity_key: Option<PathBuf>,

    /// PKCS#11 module (.so) holding the identity key in hardware (v2, prod).
    /// The key certifies session keys and never enters this process.
    #[arg(long, conflicts_with = "origin_key")]
    identity_hsm_module: Option<PathBuf>,

    /// Label of the Ed25519 identity key pair on the token
    #[arg(long, requires = "identity_hsm_module")]
    identity_hsm_key_label: Option<String>,

    /// Token to use, by label, when the module exposes several
    #[arg(long, requires = "identity_hsm_module", conflicts_with = "identity_hsm_slot")]
    identity_hsm_token_label: Option<String>,

    /// Token to use, by slot id, when labels are not unique
    #[arg(long, requires = "identity_hsm_module")]
    identity_hsm_slot: Option<u64>,

    /// File holding the user PIN. Without it, the PROBANT_HSM_PIN environment
    /// variable. Never an argument: arguments end up in `ps` and shell history.
    #[arg(long, requires = "identity_hsm_module")]
    identity_hsm_pin_file: Option<PathBuf>,

    /// Session-certificate lifetime in seconds (v2). A leaked session key
    /// forges records only until it expires; keep it to the session's scale.
    #[arg(long, default_value_t = 3600)]
    session_lifetime_secs: i64,

    /// Ops-signed deployment bundle (v1/v2): the active gateway origin or
    /// identity keys. Verified under the ops key in --trusted-keys. On resume
    /// the gateway accepts a tail certified by any key it enrolls (rotation
    /// window), and the bundle in force is recorded at the top of every chain.
    #[arg(long)]
    deployment_bundle: Option<PathBuf>,

    /// Audit chain identifier. Over HTTP, each session chains under
    /// `<chain-id>-<session>`.
    #[arg(long, default_value = "default")]
    chain_id: String,

    /// Declared environment, exposed to policies
    #[arg(long, default_value = "prod")]
    env: String,

    /// Agent identifier
    #[arg(long, default_value = "unknown-agent")]
    agent_id: String,

    /// Session identifier (end-to-end correlation), stdio transport only:
    /// over HTTP the gateway assigns one per session (Mcp-Session-Id).
    #[arg(long)]
    session_id: Option<String>,

    /// MCP server command to wrap, after `--`
    #[arg(last = true, required = true)]
    server_cmd: Vec<String>,
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

    eprintln!(
        "[probant] policy {} — {} tool(s) in catalogue — env {}",
        bundle_version,
        engine.known_tools().count(),
        cli.env
    );

    // --- Signing keys -------------------------------------------------
    // Resolved once, at startup, in front of the operator: a gateway that
    // discovers its key is unreadable at the first tool call has already
    // accepted a session it cannot sign for.
    let two_tier = |identity: Arc<dyn origin::IdentitySigner>| {
        eprintln!(
            "[probant] identity key {} — certifies a session key per chain — public entry: {}",
            identity.key_id(),
            serde_json::to_string(&identity.public_key()).expect("serializing a key entry")
        );
        origin::Signing::TwoTier {
            identity,
            lifetime_ms: cli.session_lifetime_secs.saturating_mul(1000),
        }
    };

    let signing = match (&cli.origin_key, &cli.identity_key, &cli.identity_hsm_module) {
        (None, None, None) => {
            eprintln!(
                "[probant] WARNING: no signing key. Records are chained but \
                 unsigned: nothing proves this gateway wrote them."
            );
            origin::Signing::None
        }
        (Some(path), None, None) => {
            let s = Arc::new(origin::FileOriginSigner::from_seed_file(path)?);
            eprintln!(
                "[probant] origin key {} — every record signed directly — public entry: {}",
                s.key_id(),
                serde_json::to_string(&s.public_key()).expect("serializing a key entry")
            );
            origin::Signing::Direct(s)
        }
        (None, Some(path), None) => {
            let id = Arc::new(origin::FileIdentitySigner::from_seed_file(path)?);
            two_tier(id as Arc<dyn origin::IdentitySigner>)
        }
        (None, None, Some(module)) => {
            let id = Arc::new(build_hsm_identity(&cli, module)?);
            two_tier(id as Arc<dyn origin::IdentitySigner>)
        }
        _ => unreachable!("clap: conflicts_with"),
    };

    // --- Deployment bundle (v1/v2) -----------------------------------
    // The active key set: what the gateway accepts on resume, and the
    // in-chain record of who it trusted. Verified under the ops key it names.
    let deployment = match &cli.deployment_bundle {
        None => None,
        Some(path) => {
            let trust = origin::DeploymentTrust::load(path, &trusted)?;
            eprintln!(
                "[probant] deployment bundle {} — {} gateway key(s) trusted on resume",
                trust.version,
                trust.active.len()
            );
            Some(trust)
        }
    };

    let keys = Arc::new(origin::GatewayKeys {
        signing,
        deployment,
        gateway_id: cli.agent_id.clone(),
    });
    // A gateway not enrolled in its own deployment writes records the ledger
    // will refuse: fail at startup, in front of the operator.
    keys.verify_enrolled()?;

    match &cli.http {
        Some(addr) => run_http(&cli, addr, engine, bundle_version, trusted, keys),
        None => run_stdio(&cli, engine, bundle_version, trusted, keys),
    }
}

// ---------------------------------------------------------------------------
// Streamable HTTP transport
// ---------------------------------------------------------------------------

fn run_http(
    cli: &Cli,
    addr: &str,
    engine: Arc<Engine>,
    bundle_version: String,
    trusted: Vec<audit_core::checkpoint::PublicKeyEntry>,
    keys: Arc<origin::GatewayKeys>,
) -> Result<()> {
    // Options that only mean something on stdio are refused, not ignored: an
    // operator who set them expects them to act.
    if cli.token_file.is_some() {
        bail!(
            "--token-file is a stdio option: over HTTP the token arrives in the \
             Authorization header of each request"
        );
    }
    if cli.session_id.is_some() {
        bail!("--session-id is assigned by the gateway over HTTP (Mcp-Session-Id)");
    }

    let identity = if cli.insecure_declared_identity {
        if cli.identity_bundle.is_some() {
            bail!(
                "--insecure-declared-identity is incompatible with the OIDC options: \
                 pick a single identity source"
            );
        }
        let principal = cli
            .principal
            .clone()
            .context("--principal is required with --insecure-declared-identity")?;
        eprintln!(
            "[probant] WARNING: identity DECLARED, unverified — \"{principal}\". \
             The log will carry the issuer cli://declared. \
             Never use in production."
        );
        http::Identity::Declared {
            principal,
            scopes: cli.scopes.clone(),
            groups: cli.groups.clone(),
        }
    } else {
        let Some(bundle_path) = &cli.identity_bundle else {
            bail!(
                "identity not configured: supply --identity-bundle (the token then \
                 arrives per request in the Authorization header), or \
                 --insecure-declared-identity for development"
            );
        };
        // Verified now so a bad configuration fails at startup, in front of
        // the operator, not at the first agent's initialize.
        BundleSource::load(bundle_path, &trusted)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", bundle_path.display()))?;
        http::Identity::Oidc {
            bundle_path: bundle_path.clone(),
        }
    };

    http::serve(
        http::Gateway {
            engine,
            trusted,
            bundle_version,
            identity,
            env: cli.env.clone(),
            agent_id: cli.agent_id.clone(),
            wal_dir: cli.wal.clone(),
            chain_id: cli.chain_id.clone(),
            server_cmd: cli.server_cmd.clone(),
            allowed_origins: cli.allowed_origins.clone(),
            keys,
        },
        addr,
    )
}

/// Opens the identity key on a PKCS#11 token, from the --identity-hsm-* flags.
/// The credentials are presented once, here, at startup — never in a loop
/// that could walk the token toward lock-out (the ledger's PIN discipline).
fn build_hsm_identity(cli: &Cli, module: &std::path::Path) -> Result<origin::Pkcs11IdentitySigner> {
    let label = cli
        .identity_hsm_key_label
        .as_deref()
        .context("--identity-hsm-module needs --identity-hsm-key-label")?;
    let token = match (cli.identity_hsm_slot, &cli.identity_hsm_token_label) {
        (Some(slot), None) => pkcs11::TokenSelector::Slot(slot),
        (None, Some(label)) => pkcs11::TokenSelector::Label(label.clone()),
        (None, None) => pkcs11::TokenSelector::Only,
        (Some(_), Some(_)) => unreachable!("clap: conflicts_with"),
    };
    let pin = match &cli.identity_hsm_pin_file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading the PIN file {}", path.display()))?
            .trim()
            .to_string(),
        None => std::env::var("PROBANT_HSM_PIN").map_err(|_| {
            anyhow::anyhow!("no PIN: give --identity-hsm-pin-file or set PROBANT_HSM_PIN")
        })?,
    };
    origin::Pkcs11IdentitySigner::open(module, &token, &pin, label)
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

fn run_stdio(
    cli: &Cli,
    engine: Arc<Engine>,
    bundle_version: String,
    trusted: Vec<audit_core::checkpoint::PublicKeyEntry>,
    keys: Arc<origin::GatewayKeys>,
) -> Result<()> {
    // --- Identity -------------------------------------------------------
    let auth = build_auth(cli, &trusted)?;
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

    // --- Log -------------------------------------------------------------
    // Resuming refuses a tail no trusted origin key signed: adopting it would
    // chain authentic records on top of a forgery. Under the two-tier scheme
    // the trusted set is rebuilt from the certificates already in the chain,
    // so a tail signed by a *previous* session key — which this process no
    // longer holds — is adopted iff the identity key vouched for it.
    let existing = wal::read(&cli.wal, &cli.chain_id).context("reading the log")?;
    let setup = keys.open_session(&cli.chain_id, &existing, now_ms())?;
    let (wal, chain) = match &setup.resume_trust {
        Some(map) => Wal::open_authenticated(&cli.wal, &cli.chain_id, map)
            .context("opening the log (origin-authenticated)")?,
        None => Wal::open(&cli.wal, &cli.chain_id).context("opening the log")?,
    };
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

    let mut sess = session::open(chain, wal, session_id.clone(), setup.origin);
    {
        let mut a = auth.lock().unwrap();
        // A rotation recovered while verifying the startup token happened
        // before this session existed; its record still comes first.
        session::record_config_reloads(&mut sess, a.take_reloads())?;
        // The session certificate establishes who signs, before anyone signs;
        // the deployment bundle in force says who could have. Both precede the
        // delegation.
        if let Some(cert) = setup.cert {
            session::record_session_cert(&mut sess, cert)?;
        }
        if let Some(trust) = &keys.deployment {
            session::record_deployment_bundle(&mut sess, trust)?;
        }
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
        engine,
        auth,
        env: cli.env.clone(),
        agent_id: cli.agent_id.clone(),
        bundle_version,
    });

    // --- Wrapped MCP server ----------------------------------------------
    let mut child = spawn_server(&cli.server_cmd)?;
    let mut child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

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
                    Ok(msg) => {
                        handle_from_server(msg, &state, &ctx, &session_id).to_string()
                    }
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
            Ok(msg) => handle_from_agent(msg, &state, &ctx, None)?,
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
    // Nothing to seal, nothing to export: the WAL already holds every record,
    // fsynced before the act it describes was forwarded. Sealing is the
    // ledger's job, with a key this process never held.
    drop(child_stdin);
    let _ = downstream.join();
    let _ = child.wait();

    eprintln!("[probant] {}", state.lock().unwrap().closing_report());
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
