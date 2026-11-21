//! Cross-implementation interop: the hand-rolled TCG marshalling against
//! go-tpm, Google's independent implementation of the same wire formats,
//! exercised in production against real TPM hardware fleets.
//!
//! swtpm proves our bytes satisfy *one* TPM; it cannot prove our reading of
//! the TCG format is the consensus reading. Parser and encoder were written
//! by the same hands and could agree on a shared mistake. This test closes
//! that gap in both directions:
//!
//! * **our encoder, their decoder**, everything we marshal (templates, the
//!   EK, AK and identity `TPMT_PUBLIC`s of a v4 exchange, certify and quote
//!   `TPMS_ATTEST`) must decode under go-tpm, re-encode byte-identically,
//!   and yield the same Name and the same qualifying data.
//! * **their encoder, our decoder**, a full enrollment ceremony performed
//!   by go-tpm's own marshalling must assemble into a `KeyAttestation` that
//!   `obsign_audit_core::verify_attestation` accepts (in the pre-v4 form:
//!   that ceremony has no activation, and the verifier reports it so).
//! * **their credential, our activation**: a `TPM2_MakeCredential` computed
//!   by go-tpm's `credactivation` for our EK and AK must activate through
//!   our TPM path to the same credential, the cross-check of the software
//!   MakeCredential in `obsign_tpm_enroll::credential` (whose own output the
//!   swtpm test activates).
//!
//! What this still does not prove: behavior of real silicon (provisioned
//! hierarchy auths, EK certificates, vendor quirks). That pass needs a
//! machine with `/dev/tpmrm0` (see `docs/real-tpm-interop.md`).
//!
//! Gated on `swtpm` and `go` on PATH, the SoftHSM pattern: skip loudly,
//! never fail an unprovisioned machine. The first run downloads go-tpm into
//! the Go module cache (pinned by tests/interop/go/go.sum); a machine
//! without network and without a warm cache skips at the build step.

mod common;

use obsign_audit_core::attestation::{verify_attestation, KeyAttestation, PcrExpectation};
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use common::{go_on_path, start_swtpm, swtpm_on_path};
use std::io::Write;
use std::process::{Command, Stdio};
use obsign_tpm_enroll::enroll::{activate, measure};
use obsign_tpm_enroll::{challenge, finish, request, respond, tpm, Challenge, EnrollmentRequest, Tpm};

/// Builds the Go harness, or explains why it cannot run here. Build errors
/// are a skip, not a failure: the common cause is a cold module cache with
/// no network, which must not fail an unprovisioned machine.
fn build_go_harness(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let bin = std::env::temp_dir().join(format!("obsign-tpm-interop-{}", std::process::id()));
    // Two attempts: a default build, then external linking, Go toolchains
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

    let swtpm = start_swtpm("interop"); // already initialized (CMD_INIT)

    let mut conn = Tpm::connect(&swtpm.tpm_addr).expect("connect to the TPM socket");
    conn.startup_clear().expect("TPM2_Startup");

    let binary_hash: [u8; 32] = *obsign_audit_core::hash::sha256(b"gateway-binary").as_bytes();
    measure(&mut conn, 16, &binary_hash).expect("measure");
    let req = request(&mut conn, &[]).expect("request");
    let (ch, state) = challenge(&req).expect("challenge");
    let enrollment = respond(
        &mut conn,
        &ch,
        &EnrollmentRequest {
            key_id: "gw-interop".into(),
            pcr: 16,
            measure: None,
        },
    )
    .expect("respond");
    let finished = finish(&state, &enrollment, Some(&binary_hash)).expect("finish");
    let att = &finished;
    let act = att.activation.as_ref().expect("activation form");

    // -- Direction one: our encoder, go-tpm's decoder. -------------------

    // enroll() picked its algorithm off the TPM's capabilities (Ed25519
    // where libtpms implements it, ECDSA-P256 otherwise); the assertions on
    // the enrolled key must follow that choice, not assume P-256. The
    // template round-trips cover both algorithms either way.
    let (want_scheme, want_curve) = match enrollment.algorithm.as_str() {
        "ed25519" => (tpm::ALG_EDDSA, tpm::ECC_CURVE_25519),
        _ => (tpm::ALG_ECDSA, tpm::ECC_NIST_P256),
    };
    let policy = obsign_audit_core::attestation::pcr_policy_digest(&att.expected_pcrs).unwrap();
    let templates = [
        tpm::ak_template(tpm::KeyAlg::EcdsaP256),
        tpm::identity_template(tpm::KeyAlg::EcdsaP256, &policy),
        tpm::ak_template(tpm::KeyAlg::Ed25519),
        tpm::identity_template(tpm::KeyAlg::Ed25519, &policy),
        tpm::ek_template(),
    ];
    let identity_pub = att.identity_pub.as_ref().expect("identity_pub").clone();
    // The three public areas the activation form records, then the
    // templates we send in CreatePrimary (empty or zero unique included).
    let mut publics_in = vec![identity_pub.clone(), act.ek_pub.clone(), act.ak_public.clone()];
    publics_in.extend(templates.iter().map(hex::encode));
    let input = serde_json::json!({
        "publics": publics_in,
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
    assert_eq!(publics[1]["reencoded"], serde_json::json!(act.ek_pub));
    assert_eq!(publics[1]["type"], "0x0001", "TPM_ALG_RSA");
    assert_eq!(publics[2]["reencoded"], serde_json::json!(act.ak_public));
    assert_eq!(
        publics[2]["name"].as_str().unwrap(),
        ch.ak_name,
        "the Name go-tpm computes for the AK is the one the credential was made for"
    );
    for (i, template) in templates.iter().enumerate() {
        assert_eq!(
            publics[i + 3]["reencoded"].as_str().unwrap(),
            hex::encode(template),
            "template {i} must round-trip through go-tpm"
        );
    }
    assert_eq!(publics[0]["type"], "0x0023", "TPM_ALG_ECC");
    assert_eq!(
        publics[0]["scheme"],
        serde_json::json!(want_scheme),
        "scheme of the enrolled algorithm {:?}",
        enrollment.algorithm
    );
    assert_eq!(
        publics[0]["curve"],
        serde_json::json!(want_curve),
        "curve of the enrolled algorithm {:?}",
        enrollment.algorithm
    );

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
    let qualifier = hex::encode(obsign_audit_core::attestation::activation_qualifier(
        &hex::decode(&act.nonce).unwrap(),
        &hex::decode(&act.secret).unwrap(),
    ));
    assert_eq!(attests[0]["extra_data"].as_str().unwrap(), qualifier);
    assert_eq!(attests[1]["extra_data"].as_str().unwrap(), qualifier);
    assert_eq!(attests[1]["quote_bank"], 0x000B, "SHA-256 bank");
    assert_eq!(attests[1]["quote_pcrs"], serde_json::json!([16]));
    let pcr_value = hex::decode(&att.expected_pcrs[0].digest).expect("pcr digest hex");
    assert_eq!(
        attests[1]["pcr_digest"].as_str().unwrap(),
        hex::encode(obsign_audit_core::hash::sha256(&pcr_value).as_bytes()),
        "quote pcrDigest must be the hash of the PCR value we read back"
    );

    eprintln!("direction one: go-tpm agrees with every structure we marshalled");

    // -- Their credential, our activation. --------------------------------

    let secret = [0x5Cu8; 32];
    let made = run_json(
        &harness,
        &[
            "makecred",
            "-ek",
            &act.ek_pub,
            "-name",
            &ch.ak_name,
            "-secret",
            &hex::encode(secret),
        ],
        None,
    );
    let go_challenge = Challenge {
        credential_blob: made["credential_blob"].as_str().unwrap().into(),
        encrypted_secret: made["encrypted_secret"].as_str().unwrap().into(),
        ..ch.clone()
    };
    let alg = tpm::public_key_bytes(&hex::decode(&act.ak_public).unwrap()).unwrap().0;
    let ek = conn.create_primary(tpm::TPM_RH_ENDORSEMENT, &tpm::ek_template()).unwrap();
    let ak = conn.create_primary(tpm::TPM_RH_ENDORSEMENT, &tpm::ak_template(alg)).unwrap();
    let recovered = activate(&mut conn, ak.handle, ek.handle, &go_challenge)
        .expect("a go-tpm credential activates through our TPM path");
    assert_eq!(recovered, secret);
    conn.flush(ek.handle).unwrap();
    conn.flush(ak.handle).unwrap();
    eprintln!("credential: go-tpm's MakeCredential activates through our ActivateCredential");

    // -- Direction two: go-tpm's encoder, our decoder. --------------------

    // This direction is P-256 by necessity, not omission: go-tpm v0.3.3's
    // signature marshalling covers RSA and ECDSA only, so an EdDSA ceremony
    // cannot be driven from its side. Ed25519 encoding is covered by the
    // template round-trips above and by the swtpm test where libtpms
    // implements it.

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
        // go-tpm's ceremony here has no activation: the pre-v4 form, which
        // still verifies and which the report names attestation_unbound.
        activation: None,
    };
    let entry = PublicKeyEntry {
        key_id: "gw-go-tpm".into(),
        algo: obsign_audit_core::attestation::ALGO_ECDSA_P256.into(),
        public_key: field("identity_point"),
        role: KeyRole::Origin,
    };

    verify_attestation(&entry, &foreign)
        .expect("obsign-audit-core must accept an attestation marshalled entirely by go-tpm");

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

    eprintln!("direction two: obsign-audit-core verified a go-tpm-marshalled enrollment");
}
