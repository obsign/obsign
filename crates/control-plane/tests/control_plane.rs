//! Control plane integration tests.
//!
//! Same philosophy as the other crates: each control has its paired
//! legitimate-path test, and what matters is not that the code runs but that
//! the refusals refuse — a version that could be silently rewritten, a key id
//! that could be rebound or a dossier that hid an invalid pack would each
//! defeat the product.

use audit_core::hash::sha256;
use audit_core::record::{Effect, EffectStatus, Payload};
use base64::Engine as _;
use control_plane::export::SignedExportManifest;
use control_plane::release::SignedManifest;
use control_plane::source::{git_head, short_ref};
use control_plane::{compile, export_all, publish, Console, Error, OpsKey, SourceTree};
use ledger::{seal_pass, FileSealer, Store};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use wal::Wal;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ctl-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const CEDAR_OK: &str = r#"
@id("forbid_destructive_prod")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && context.env == "prod" };

@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope != "" && context.scopes.contains(resource.required_scope) };
"#;

/// Writes a complete, valid source tree.
fn write_source_tree(root: &Path) {
    std::fs::create_dir_all(root.join("policies")).unwrap();
    std::fs::create_dir_all(root.join("identity")).unwrap();

    std::fs::write(root.join("policies/00-base.cedar"), CEDAR_OK).unwrap();
    std::fs::write(
        root.join("tools.json"),
        serde_json::json!([
            {"name": "delete_production_db", "server": "mcp://db", "destructive": true,
             "required_scope": "db:admin"},
            {"name": "ticket_update", "server": "mcp://crm",
             "required_scope": "support:ticket_update"}
        ])
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        root.join("fail-mode.json"),
        serde_json::json!({"default": "closed", "tools": {"ticket_update": "open"}})
            .to_string(),
    )
    .unwrap();

    let vk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes());
    std::fs::write(
        root.join("identity/provider.json"),
        serde_json::json!({
            "issuer": "https://sso.acme.fr/realms/corp",
            "audience": "probant-proxy"
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        root.join("identity/jwks.json"),
        serde_json::json!({"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": x}]})
            .to_string(),
    )
    .unwrap();
}

fn ops() -> OpsKey {
    OpsKey::from_seed([0x21u8; 32], "ops-key")
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

#[test]
fn compilation_is_deterministic_and_verifiable() {
    let dir = tmp("compile");
    write_source_tree(&dir);

    let tree = SourceTree::load(&dir).unwrap();
    let a = compile(&tree, "aaaa11112222", &ops()).unwrap();
    let b = compile(&SourceTree::load(&dir).unwrap(), "aaaa11112222", &ops()).unwrap();

    // Byte-identical artifacts: same tree, same ref, same key. This is what
    // makes publish idempotent and releases comparable by hash.
    assert_eq!(
        serde_json::to_vec(&a.policy).unwrap(),
        serde_json::to_vec(&b.policy).unwrap()
    );
    assert_eq!(a.policy.bundle.version, "policies@aaaa11112222");

    // Signatures verify against the ops public key — and against nothing else.
    let vk = ops().signing_key().verifying_key();
    a.policy.verify(&vk).expect("policy bundle must verify");
    let idb = a.identity.expect("identity bundle expected");
    assert_eq!(idb.bundle.version, "identity@aaaa11112222");
    idb.verify(&vk).expect("identity bundle must verify");

    let other = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]).verifying_key();
    assert!(a.policy.verify(&other).is_err(), "a foreign key must not verify");
}

#[test]
fn a_rule_without_id_is_rejected_at_compile_time() {
    let dir = tmp("no-id");
    write_source_tree(&dir);
    std::fs::write(
        dir.join("policies/10-extra.cedar"),
        "permit (principal, action, resource);",
    )
    .unwrap();

    let tree = SourceTree::load(&dir).unwrap();
    let err = compile(&tree, "v1", &ops()).unwrap_err();
    match err {
        Error::Source(msg) => assert!(msg.contains("@id"), "message must name @id: {msg}"),
        other => panic!("expected Source, got {other}"),
    }
}

#[test]
fn source_tree_mistakes_are_compile_errors() {
    // Duplicate tool: the engine would silently shadow one definition.
    let dir = tmp("dup-tool");
    write_source_tree(&dir);
    std::fs::write(
        dir.join("tools.json"),
        serde_json::json!([
            {"name": "t", "server": "mcp://a"},
            {"name": "t", "server": "mcp://b"}
        ])
        .to_string(),
    )
    .unwrap();
    assert!(matches!(SourceTree::load(&dir), Err(Error::Source(m)) if m.contains("twice")));

    // Fail-mode override for a tool outside the catalogue: a typo here
    // silently applies the default to the tool the author meant.
    let dir = tmp("fm-typo");
    write_source_tree(&dir);
    std::fs::write(
        dir.join("fail-mode.json"),
        serde_json::json!({"default": "closed", "tools": {"tikcet_update": "open"}})
            .to_string(),
    )
    .unwrap();
    assert!(matches!(SourceTree::load(&dir), Err(Error::Source(m)) if m.contains("tikcet_update")));

    // A JWKS the gateway would refuse (symmetric key) must not compile.
    let dir = tmp("bad-jwks");
    write_source_tree(&dir);
    std::fs::write(
        dir.join("identity/jwks.json"),
        serde_json::json!({"keys": [{"kty": "oct", "kid": "h1"}]}).to_string(),
    )
    .unwrap();
    assert!(matches!(SourceTree::load(&dir), Err(Error::Source(_))));

    // No policies at all: an empty policy set denies everything, which
    // deserves an explicit file saying so.
    let dir = tmp("no-cedar");
    write_source_tree(&dir);
    std::fs::remove_file(dir.join("policies/00-base.cedar")).unwrap();
    assert!(matches!(SourceTree::load(&dir), Err(Error::Source(_))));
}

// ---------------------------------------------------------------------------
// Git resolution
// ---------------------------------------------------------------------------

#[test]
fn git_head_is_resolved_without_a_git_binary() {
    let sha = "0123456789abcdef0123456789abcdef01234567";

    // Loose ref.
    let dir = tmp("git-loose");
    std::fs::create_dir_all(dir.join(".git/refs/heads")).unwrap();
    std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(dir.join(".git/refs/heads/main"), format!("{sha}\n")).unwrap();
    assert_eq!(git_head(&dir).unwrap(), sha);
    // And from a subdirectory of the checkout.
    std::fs::create_dir_all(dir.join("policies")).unwrap();
    assert_eq!(git_head(&dir.join("policies")).unwrap(), sha);

    // Packed ref (git gc ran).
    let dir = tmp("git-packed");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        dir.join(".git/packed-refs"),
        format!("# pack-refs with: peeled fully-peeled sorted\n{sha} refs/heads/main\n"),
    )
    .unwrap();
    assert_eq!(git_head(&dir).unwrap(), sha);

    // Detached HEAD.
    let dir = tmp("git-detached");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git/HEAD"), format!("{sha}\n")).unwrap();
    assert_eq!(git_head(&dir).unwrap(), sha);

    assert_eq!(short_ref(sha), "0123456789ab");

    // Outside any repository: a clear refusal pointing at --label.
    let dir = tmp("git-none");
    assert!(matches!(git_head(&dir), Err(Error::NoVersion(_))));
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

#[test]
fn a_published_version_is_immutable() {
    let src = tmp("pub-src");
    let dist = tmp("pub-dist");
    write_source_tree(&src);

    let tree = SourceTree::load(&src).unwrap();
    let v1 = compile(&tree, "v1", &ops()).unwrap();
    let p = publish(&dist, &v1, &ops(), 1_000).unwrap();
    assert!(!p.reused);

    // The current files are the release files, hash for hash.
    let current = std::fs::read(dist.join("policy-bundle.json")).unwrap();
    let in_release = std::fs::read(dist.join("releases/v1/policy-bundle.json")).unwrap();
    assert_eq!(current, in_release);

    // The manifest verifies and names exactly these bytes — checkable with
    // nothing but sha256sum.
    let signed: SignedManifest =
        serde_json::from_str(&std::fs::read_to_string(dist.join("manifest.json")).unwrap())
            .unwrap();
    let m = signed
        .verify(&ops().signing_key().verifying_key())
        .expect("manifest must verify");
    assert_eq!(m.version, "v1");
    let entry = m
        .artifacts
        .iter()
        .find(|a| a.name == "policy-bundle.json")
        .unwrap();
    assert_eq!(entry.sha256, sha256(&current));

    // Republishing the same content under the same version is idempotent.
    let again = publish(&dist, &v1, &ops(), 2_000).unwrap();
    assert!(again.reused, "identical content must be accepted silently");

    // Different content under the same version: refused. Decisions in the
    // log cite policies@v1; the sha must keep designating the same rules.
    std::fs::write(
        src.join("policies/00-base.cedar"),
        CEDAR_OK.replace("prod", "staging"),
    )
    .unwrap();
    let modified = compile(&SourceTree::load(&src).unwrap(), "v1", &ops()).unwrap();
    assert!(matches!(
        publish(&dist, &modified, &ops(), 3_000),
        Err(Error::VersionConflict { .. })
    ));
    // And the paired legitimate path: the same change under a new version.
    let v2 = compile(&SourceTree::load(&src).unwrap(), "v2", &ops()).unwrap();
    publish(&dist, &v2, &ops(), 4_000).expect("a new version must publish");
}

#[test]
fn republishing_an_old_version_is_a_rollback() {
    let src = tmp("rb-src");
    let dist = tmp("rb-dist");
    write_source_tree(&src);

    let v1 = compile(&SourceTree::load(&src).unwrap(), "v1", &ops()).unwrap();
    publish(&dist, &v1, &ops(), 1_000).unwrap();

    std::fs::write(
        src.join("policies/00-base.cedar"),
        CEDAR_OK.replace("prod", "staging"),
    )
    .unwrap();
    let v2 = compile(&SourceTree::load(&src).unwrap(), "v2", &ops()).unwrap();
    publish(&dist, &v2, &ops(), 2_000).unwrap();

    // Roll back: point current at v1 again. No dedicated tooling, publish is
    // the rollback path.
    let p = publish(&dist, &v1, &ops(), 3_000).unwrap();
    assert!(p.reused);
    let current = std::fs::read(dist.join("policy-bundle.json")).unwrap();
    assert_eq!(
        current,
        std::fs::read(dist.join("releases/v1/policy-bundle.json")).unwrap()
    );
    let signed: SignedManifest =
        serde_json::from_str(&std::fs::read_to_string(dist.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(signed.manifest.version, "v1");
    // The release's original timestamp is kept: the manifest describes the
    // release, not the act of pointing the fleet at it.
    assert_eq!(signed.manifest.ts_ms, 1_000);
    // v2's immutable history is untouched.
    assert!(dist.join("releases/v2/policy-bundle.json").exists());
}

#[test]
fn a_key_id_cannot_be_rebound() {
    let src = tmp("key-src");
    let dist = tmp("key-dist");
    write_source_tree(&src);
    let tree = SourceTree::load(&src).unwrap();

    let v1 = compile(&tree, "v1", &ops()).unwrap();
    publish(&dist, &v1, &ops(), 1_000).unwrap();

    // Same key id, different key material: whoever can do that can sign
    // rules the fleet will trust under an already-trusted name.
    let imposter = OpsKey::from_seed([0x99u8; 32], "ops-key");
    let v2 = compile(&tree, "v2", &imposter).unwrap();
    assert!(matches!(
        publish(&dist, &v2, &imposter, 2_000),
        Err(Error::KeyConflict(_))
    ));

    // A new id is the legitimate path, and both keys end up trusted.
    let rotated = OpsKey::from_seed([0x99u8; 32], "ops-key-2");
    let v2 = compile(&tree, "v2", &rotated).unwrap();
    publish(&dist, &v2, &rotated, 3_000).unwrap();
    let keys: Vec<audit_core::checkpoint::PublicKeyEntry> =
        serde_json::from_str(&std::fs::read_to_string(dist.join("trusted-keys.json")).unwrap())
            .unwrap();
    assert_eq!(keys.len(), 2);
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn payload(n: u64) -> Payload {
    Payload::Effect(Effect {
        status: EffectStatus::Ok,
        result_hash: None,
        latency_ms: n,
    })
}

/// Writes `n` records to a chain and returns nothing: the WAL is the output.
fn fill_chain(wal_dir: &Path, chain: &str, n: u64, salt: u64) {
    let (mut wal, mut writer) = Wal::open(wal_dir, chain).unwrap();
    for i in 0..n {
        let rec = writer.append(i as i64, format!("r{i}"), None, "s", payload(salt + i));
        wal.append(&rec).unwrap();
    }
}

fn seal_chain(wal_dir: &Path, store_dir: &Path, chain: &str) {
    let records = wal::read(wal_dir, chain).unwrap();
    let mut store = Store::open(store_dir, chain).unwrap();
    let sealer = FileSealer::from_seed([0x55u8; 32], "seal-1");
    seal_pass(&records, &mut store, &sealer, 42, 1)
        .unwrap()
        .expect("something to seal");
}

#[test]
fn export_produces_verifiable_packs_and_a_signed_manifest() {
    let wal_dir = tmp("exp-wal");
    let store_dir = tmp("exp-store");
    let out = tmp("exp-out");

    for (chain, salt) in [("alpha", 0u64), ("beta", 100)] {
        fill_chain(&wal_dir, chain, 4, salt);
        seal_chain(&wal_dir, &store_dir, chain);
    }

    let (exports, all_valid) = export_all(&wal_dir, &store_dir, &out, &ops(), 9_000).unwrap();
    assert!(all_valid);
    assert_eq!(exports.len(), 2, "one pack per chain");

    let signed: SignedExportManifest = serde_json::from_str(
        &std::fs::read_to_string(out.join("export-manifest.json")).unwrap(),
    )
    .unwrap();
    let manifest = signed
        .verify(&ops().signing_key().verifying_key())
        .expect("export manifest must verify");

    for entry in &manifest.packs {
        assert!(entry.valid);
        assert_eq!(entry.records, 4);
        assert_eq!(entry.records_sealed, 4);

        // The manifest hash is the hash of the file as written: the recipient
        // checks it with sha256sum before anything else.
        let bytes = std::fs::read(out.join(&entry.file)).unwrap();
        assert_eq!(entry.sha256, sha256(&bytes));

        // And each pack verifies on its own, exactly as the auditor will.
        let ev: audit_core::evidence::Evidence = serde_json::from_slice(&bytes).unwrap();
        let trusted: Vec<audit_core::checkpoint::PublicKeyEntry> =
            serde_json::from_str(&std::fs::read_to_string(store_dir.join("keys.json")).unwrap())
                .unwrap();
        assert!(audit_core::evidence::verify(&ev, &trusted).is_valid());
    }
}

#[test]
fn a_rewritten_wal_is_exported_but_flagged_invalid() {
    let wal_dir = tmp("rw-wal");
    let store_dir = tmp("rw-store");
    let out = tmp("rw-out");

    fill_chain(&wal_dir, "alpha", 4, 0);
    seal_chain(&wal_dir, &store_dir, "alpha");

    // The rewritten-WAL attack: a fresh, internally consistent chain that is
    // not the history the checkpoints certify.
    std::fs::remove_file(wal_dir.join("alpha.jsonl")).unwrap();
    fill_chain(&wal_dir, "alpha", 4, 999);

    let (exports, all_valid) = export_all(&wal_dir, &store_dir, &out, &ops(), 9_000).unwrap();
    // Written anyway — the failing pack is the one you want on disk — but
    // never passed off as fine.
    assert!(!all_valid);
    assert!(!exports[0].report.is_valid());
    let signed: SignedExportManifest = serde_json::from_str(
        &std::fs::read_to_string(out.join("export-manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(!signed.manifest.packs[0].valid);
    assert!(out.join("alpha.evidence.json").exists());
}

#[test]
fn an_empty_or_mistyped_export_is_refused() {
    let wal_dir = tmp("empty-wal");
    let store_dir = tmp("empty-store");
    let out = tmp("empty-out");

    // No chain: an empty audit dossier is a mistyped path, not a result.
    assert!(export_all(&wal_dir, &store_dir, &out, &ops(), 0).is_err());

    // Missing store directory: would export every chain as "0 sealed".
    fill_chain(&wal_dir, "alpha", 2, 0);
    let missing = store_dir.join("nope");
    assert!(export_all(&wal_dir, &missing, &out, &ops(), 0).is_err());
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

fn http_get(addr: SocketAddr, request: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn console_is_read_only_and_shows_the_log() {
    let wal_dir = tmp("con-wal");
    let store_dir = tmp("con-store");
    let dist = tmp("con-dist");
    let src = tmp("con-src");

    write_source_tree(&src);
    let compiled = compile(&SourceTree::load(&src).unwrap(), "v1", &ops()).unwrap();
    publish(&dist, &compiled, &ops(), 1_000).unwrap();
    fill_chain(&wal_dir, "alpha", 3, 0);
    seal_chain(&wal_dir, &store_dir, "alpha");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let console = Console {
        wal_dir: wal_dir.clone(),
        store_dir: Some(store_dir.clone()),
        dist_dir: Some(dist.clone()),
    };
    std::thread::spawn(move || console.serve_on(listener));

    let overview = http_get(addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(overview.starts_with("HTTP/1.1 200"));
    assert!(overview.contains("alpha"), "chains must be listed");
    assert!(overview.contains("intact"), "sealing state must be shown");
    assert!(overview.contains("version <code>v1</code>"), "release version must be shown");
    assert!(overview.contains("signature valid"), "manifest verdict must be shown");

    let chain = http_get(addr, "GET /chain/alpha HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(chain.starts_with("HTTP/1.1 200"));
    assert!(chain.contains("effect"), "records must be rendered");

    let release = http_get(addr, "GET /release HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(release.starts_with("HTTP/1.1 200"));
    assert!(release.contains("delete_production_db"), "catalogue must be shown");
    assert!(release.contains("forbid_destructive_prod"), "rules must be shown");

    // Read-only by construction: no method but GET exists.
    let post = http_get(addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(post.starts_with("HTTP/1.1 405"), "got: {}", &post[..40.min(post.len())]);

    // A chain id is a file name: traversal shapes are 404, not a disk read.
    let esc = http_get(addr, "GET /chain/../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(esc.starts_with("HTTP/1.1 404"));
    let unknown = http_get(addr, "GET /chain/nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(unknown.starts_with("HTTP/1.1 404"));
}
