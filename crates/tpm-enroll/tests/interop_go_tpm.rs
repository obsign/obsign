//! Cross-implementation interop: the hand-rolled TCG marshalling against
//! go-tpm, Google's independent implementation of the same wire formats,
//! exercised in production against real TPM hardware fleets.
//!
//! swtpm proves our bytes satisfy *one* TPM; it cannot prove our reading of
//! the TCG format is the consensus reading — parser and encoder were written
//! by the same hands and could agree on a shared mistake. This test closes
//! that gap in both directions:
//!
//! * **our encoder, their decoder** — everything we marshal (templates, the
//!   enrolled `TPMT_PUBLIC`, certify and quote `TPMS_ATTEST`) must decode
//!   under go-tpm, re-encode byte-identically, and yield the same Name.
//! * **their encoder, our decoder** — a full enrollment ceremony performed
//!   by go-tpm's own marshalling must assemble into a `KeyAttestation` that
//!   `audit_core::verify_attestation` accepts.
//!
//! What this still does not prove: behavior of real silicon (provisioned
//! hierarchy auths, EK certificates, vendor quirks). That pass needs a
//! machine with `/dev/tpmrm0` — see `docs/real-tpm-interop.md`.
//!
//! Gated on `swtpm` and `go` on PATH, the SoftHSM pattern: skip loudly,
//! never fail an unprovisioned machine. The first run downloads go-tpm into
//! the Go module cache (pinned by tests/interop/go/go.sum); a machine
//! without network and without a warm cache skips at the build step.

mod common;

use audit_core::attestation::{verify_attestation, KeyAttestation, PcrExpectation};
use audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use common::{go_on_path, start_swtpm, swtpm_on_path};
use std::io::Write;
use std::process::{Command, Stdio};
use tpm_enroll::{enroll, tpm, EnrollmentRequest, Tpm};

/// Builds the Go harness, or explains why it cannot run here. Build errors
/// are a skip, not a failure: the common cause is a cold module cache with
/// no network, which must not fail an unprovisioned machine.
fn build_go_harness(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let bin = std::env::temp_dir().join(format!("probant-tpm-interop-{}", std::process::id()));
    // Two attempts: a default build, then external linking — Go toolchains
    // before 1.20 emit Mach-O without LC_UUID, which recent macOS dyld
    // refuses to load; the system linker adds it.
    for flags in [&[][..], &["-ldflags", "-linkmode=external"][..]] {
        let out = Command::new("go")
            .args(["build"])
            .args(flags)
            .args(["-o"])
            .arg(&bin)
            .arg(".")
            .current_dir(dir)
            .output()
            .expect("run go build");
        if !out.status.success() {
            eprintln!(
                "skipped: building the go-tpm harness failed (cold module \
                 cache without network?):\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        // Smoke-test: the binary must actually execute on this host.
        let probe = Command::new(&bin)
            .arg("decode")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut c| {
                c.stdin
                    .take()
                    .expect("piped stdin")
                    .write_all(b"{\"publics\":[],\"attests\":[]}")?;
                c.wait()
            });
        if matches!(&probe, Ok(status) if status.success()) {
            return Some(bin);
        }
    }
    eprintln!("skipped: the go-tpm harness binary does not execute on this host");
    None
}

fn run_json(bin: &std::path::Path, args: &[&str], stdin: Option<&str>) -> serde_json::Value {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn interop harness");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .expect("write harness stdin");
    }
    let out = child.wait_with_output().expect("harness output");
    assert!(out.status.success(), "interop harness failed");
    serde_json::from_slice(&out.stdout).expect("harness output is JSON")
}

/// Splits an `attest || 64-byte signature` hex field into the attest hex.
fn attest_of(signed_hex: &str) -> &str {
    assert!(signed_hex.len() > 128, "signed attest too short");
    &signed_hex[..signed_hex.len() - 128]
}

#[test]
fn the_wire_format_agrees_with_go_tpm_in_both_directions() {
    if !swtpm_on_path() {
        eprintln!("skipped: swtpm not on PATH (brew install swtpm)");
        return;
    }
    if !go_on_path() {
        eprintln!("skipped: go not on PATH (needed to build the go-tpm harness)");
        return;
    }
    let go_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/go");
    let Some(harness) = build_go_harness(&go_dir) else {
        return;
    };

    let swtpm = start_swtpm("interop");
    swtpm
        .ctrl
        .init()
        .expect("CMD_INIT over the control channel");

    let mut conn = Tpm::connect(&swtpm.tpm_addr).expect("connect to the TPM socket");
    conn.startup_clear().expect("TPM2_Startup");

    let binary_hash: [u8; 32] = *audit_core::hash::sha256(b"gateway-binary").as_bytes();
    let enrollment = enroll(
        &mut conn,
        &EnrollmentRequest {
            key_id: "gw-interop".into(),
            binary_hash,
            pcr: 16,
            ek_cert: Vec::new(),
        },
    )
    .expect("enrollment ceremony");
    let att = &enrollment.attestation;

    // -- Direction one: our encoder, go-tpm's decoder. -------------------

    let identity_pub = att.identity_pub.as_ref().expect("identity_pub").clone();
    let input = serde_json::json!({
        "publics": [
            identity_pub,
            // The templates we send in CreatePrimary, empty unique included.
            hex::encode(tpm::ak_template(tpm::KeyAlg::EcdsaP256)),
            hex::encode(tpm::identity_template(tpm::KeyAlg::EcdsaP256)),
        ],
        "attests": [
            attest_of(&att.certify),
            attest_of(&att.quote),
        ],
    });
    let decoded = run_json(&harness, &["decode"], Some(&input.to_string()));

    // Every TPMT_PUBLIC we produced re-encodes byte-identically under
    // go-tpm: the two implementations parse the structure the same way.
    let publics = decoded["publics"].as_array().expect("publics");
    assert_eq!(publics[0]["reencoded"], serde_json::json!(identity_pub));
    assert_eq!(
        publics[1]["reencoded"].as_str().unwrap(),
        hex::encode(tpm::ak_template(tpm::KeyAlg::EcdsaP256)),
        "AK template must round-trip through go-tpm"
    );
    assert_eq!(
        publics[2]["reencoded"].as_str().unwrap(),
        hex::encode(tpm::identity_template(tpm::KeyAlg::EcdsaP256)),
        "identity template must round-trip through go-tpm"
    );
    assert_eq!(publics[0]["type"], "0x0023", "TPM_ALG_ECC");
    assert_eq!(publics[0]["scheme"], 0x0018, "TPM_ALG_ECDSA");
    assert_eq!(publics[0]["curve"], 0x0003, "TPM_ECC_NIST_P256");

    // Both TPMS_ATTEST structures re-encode byte-identically, carry the
    // right magic and type, and go-tpm's reading of their contents matches
    // what our verifier checks: the certify Name is the Name go-tpm itself
    // computes over our TPMT_PUBLIC, and the quote names our PCR selection
    // with the digest of the value we read back.
    let attests = decoded["attests"].as_array().expect("attests");
    assert_eq!(
        attests[0]["reencoded"].as_str().unwrap(),
        attest_of(&att.certify)
    );
    assert_eq!(
        attests[1]["reencoded"].as_str().unwrap(),
        attest_of(&att.quote)
    );
    assert_eq!(attests[0]["magic"], "0xFF544347");
    assert_eq!(attests[0]["type"], "0x8017", "TPM_ST_ATTEST_CERTIFY");
    assert_eq!(attests[1]["type"], "0x8018", "TPM_ST_ATTEST_QUOTE");
    assert_eq!(
        attests[0]["certify_name"], publics[0]["name"],
        "the Name go-tpm computes over our TPMT_PUBLIC must be the Name \
         inside our certify attest"
    );
    assert_eq!(attests[1]["quote_bank"], 0x000B, "SHA-256 bank");
    assert_eq!(attests[1]["quote_pcrs"], serde_json::json!([16]));
    let pcr_value = hex::decode(&att.expected_pcrs[0].digest).expect("pcr digest hex");
    assert_eq!(
        attests[1]["pcr_digest"].as_str().unwrap(),
        hex::encode(audit_core::hash::sha256(&pcr_value).as_bytes()),
        "quote pcrDigest must be the hash of the PCR value we read back"
    );

    eprintln!("direction one: go-tpm agrees with every structure we marshalled");

    // -- Direction two: go-tpm's encoder, our decoder. --------------------

    // swtpm serves one data client at a time: hand the socket to Go.
    drop(conn);

    let enrolled = run_json(
        &harness,
        &[
            "enroll",
            "-tpm",
            &swtpm.tpm_addr,
            "-pcr",
            "16",
            "-hash",
            &hex::encode(binary_hash),
        ],
        None,
    );

    let field = |k: &str| {
        enrolled[k]
            .as_str()
            .unwrap_or_else(|| panic!("harness output missing {k}"))
            .to_string()
    };
    let foreign = KeyAttestation {
        key_id: "gw-go-tpm".into(),
        ak_pub: field("ak_point"),
        ek_cert: String::new(),
        certify: field("certify"),
        quote: field("quote"),
        expected_pcrs: vec![PcrExpectation {
            index: 16,
            digest: field("pcr_value"),
        }],
        identity_pub: Some(field("identity_pub")),
    };
    let entry = PublicKeyEntry {
        key_id: "gw-go-tpm".into(),
        algo: audit_core::attestation::ALGO_ECDSA_P256.into(),
        public_key: field("identity_point"),
        role: KeyRole::Origin,
    };

    verify_attestation(&entry, &foreign)
        .expect("audit-core must accept an attestation marshalled entirely by go-tpm");

    // The acceptance is not vacuous: a flipped signature bit still fails.
    let mut tampered = foreign.clone();
    let mut raw = hex::decode(&tampered.quote).unwrap();
    let n = raw.len();
    raw[n - 1] ^= 0x01;
    tampered.quote = hex::encode(raw);
    assert!(
        verify_attestation(&entry, &tampered).is_err(),
        "tampered go-tpm quote accepted"
    );

    eprintln!("direction two: audit-core verified a go-tpm-marshalled enrollment");
}
