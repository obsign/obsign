//! Integration with a real PKCS#11 module (SoftHSM in CI/dev, but nothing
//! here is SoftHSM-specific: the point of the standard is that a Trustway or
//! a Luna answers the same calls).
//!
//! Gated on the environment because it needs a provisioned token:
//!
//! ```sh
//! source scripts/pkcs11-test-env.sh   # throwaway SoftHSM token + env vars
//! cargo test -p ledger --test pkcs11_softhsm
//! ```
//!
//! Without `PROBANT_TEST_PKCS11_MODULE` the test passes vacuously and says
//! so — an unprovisioned machine must not fail the suite, but the skip has
//! to be visible, not silent.
//!
//! One #[test], sequential: PKCS#11 login state is per-token per-process, so
//! concurrent test functions would see each other's sessions
//! (CKR_USER_ALREADY_LOGGED_IN) and the wrong-PIN check would depend on
//! ordering. Failure paths run first — a wrong PIN presented after the right
//! one proves less.

#![cfg(unix)]

use audit_core::evidence;
use audit_core::record::{Effect, EffectStatus, Payload};
use ledger::{export, seal_pass, Pkcs11Sealer, Sealer, TokenSelector};
use std::path::{Path, PathBuf};
use wal::Wal;

struct Env {
    module: PathBuf,
    pin: String,
    key_label: String,
}

fn test_env() -> Option<Env> {
    let module = std::env::var("PROBANT_TEST_PKCS11_MODULE").ok()?;
    Some(Env {
        module: PathBuf::from(module),
        pin: std::env::var("PROBANT_TEST_PKCS11_PIN").ok()?,
        key_label: std::env::var("PROBANT_TEST_PKCS11_KEY_LABEL").ok()?,
    })
}

fn grow_wal(dir: &Path, n: u64) {
    let (mut wal, mut chain) = Wal::open(dir, "c1").unwrap();
    let start = chain.next_seq();
    for i in start..start + n {
        let r = chain.append(
            i as i64,
            format!("r{i}"),
            None,
            "s",
            Payload::Effect(Effect {
                status: EffectStatus::Ok,
                result_hash: None,
                latency_ms: i,
            }),
        );
        wal.append(&r).unwrap();
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ledger-hsm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn seals_through_a_real_token() {
    let Some(env) = test_env() else {
        eprintln!("skipped: PROBANT_TEST_PKCS11_MODULE not set (see scripts/pkcs11-test-env.sh)");
        return;
    };

    // A wrong PIN must fail at construction, with the vendor code an
    // operator can look up — and must be presented exactly once (a retried
    // wrong PIN is how tokens get locked).
    let e = Pkcs11Sealer::open(
        &env.module,
        &TokenSelector::Only,
        "0000-wrong",
        &env.key_label,
        "seal-hsm",
    )
    .unwrap_err();
    assert!(e.to_string().contains("PIN"), "unhelpful wrong-PIN error: {e}");

    // A key that is not on the token: named refusal, not a fallback.
    let e = Pkcs11Sealer::open(
        &env.module,
        &TokenSelector::Only,
        &env.pin,
        "no-such-key",
        "seal-hsm",
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("no-such-key"),
        "the error does not name the missing key: {e}"
    );

    // A key of the wrong type under a correct label must be refused by type,
    // not by a later signature mismatch. Provisioned by the env script.
    if let Ok(p256) = std::env::var("PROBANT_TEST_PKCS11_P256_LABEL") {
        let e = Pkcs11Sealer::open(
            &env.module,
            &TokenSelector::Only,
            &env.pin,
            &p256,
            "seal-hsm",
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("not an Ed25519 key"),
            "wrong-type key not refused by type: {e}"
        );
    }

    // Selecting a token that does not exist lists what does.
    let e = Pkcs11Sealer::open(
        &env.module,
        &TokenSelector::Label("no-such-token".to_string()),
        &env.pin,
        &env.key_label,
        "seal-hsm",
    )
    .unwrap_err();
    assert!(e.to_string().contains("no token labelled"), "{e}");

    // Happy path: same pipeline as the FileSealer tests, evidence verified
    // offline down to the signatures the token produced.
    let sealer = Pkcs11Sealer::open(
        &env.module,
        &TokenSelector::Only,
        &env.pin,
        &env.key_label,
        "seal-hsm",
    )
    .unwrap();

    let wal_dir = tmpdir("wal");
    grow_wal(&wal_dir, 3);
    let records = wal::read(&wal_dir, "c1").unwrap();
    let mut store = ledger::Store::open(&tmpdir("store"), "c1").unwrap();

    let sc = seal_pass(&records, &mut store, &sealer, 1_000, 1)
        .unwrap()
        .expect("three records to seal");
    assert_eq!(sc.checkpoint.key_id, "seal-hsm");

    let ev = export(records, &store);
    let report = evidence::verify(&ev, store.keys());
    assert!(report.is_valid(), "{:?}", report.errors().collect::<Vec<_>>());
    assert_eq!(report.records_sealed, 3);

    // The signature came from the token, and verifies against the public
    // half read off the token — not against anything this process invented.
    let vk = sealer.public_key().to_verifying_key().unwrap();
    sc.verify(&vk).unwrap();

    // A second sealer while the first is alive: the module is already
    // initialized and the token already logged in, both of which the
    // constructor must treat as normal (`run` restarts, sidecar tools).
    let again = Pkcs11Sealer::open(
        &env.module,
        &TokenSelector::Only,
        &env.pin,
        &env.key_label,
        "seal-hsm",
    )
    .unwrap();
    assert_eq!(again.public_key().public_key, sealer.public_key().public_key);
}

/// The same path through the shipped binary: flags, PIN file, exit code.
#[test]
fn cli_seals_with_hsm_flags() {
    let Some(env) = test_env() else {
        eprintln!("skipped: PROBANT_TEST_PKCS11_MODULE not set (see scripts/pkcs11-test-env.sh)");
        return;
    };

    let wal_dir = tmpdir("cli-wal");
    grow_wal(&wal_dir, 2);
    let store_dir = tmpdir("cli-store");
    let pin_file = tmpdir("cli-pin").with_extension("txt");
    std::fs::write(&pin_file, format!("{}\n", env.pin)).unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_probant-ledger"))
        .args(["seal", "--chain-id", "c1"])
        .arg("--wal")
        .arg(&wal_dir)
        .arg("--store")
        .arg(&store_dir)
        .arg("--hsm-module")
        .arg(&env.module)
        .args(["--hsm-key-label", &env.key_label])
        .arg("--hsm-pin-file")
        .arg(&pin_file)
        .args(["--key-id", "seal-hsm"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("sealed [0..1]"));
}
