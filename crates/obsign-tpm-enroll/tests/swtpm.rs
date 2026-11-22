//! Integration with a real (software) TPM: the whole attestation-v4
//! exchange (request, credential challenge, `TPM2_ActivateCredential`,
//! PCR-policy identity key, qualified certify and quote, ops-side finish)
//! against an actual TPM 2.0 implementation, and
//! `obsign_audit_core::verify_attestation` accepting the output, byte for
//! byte. Then the negatives the protocol exists for, each against real TPM
//! behavior rather than a synthesizer: an AK from another TPM cannot
//! activate, unqualified or replayed statements are refused, an identity key
//! without the PCR policy is refused, and a PCR that moved stops the
//! identity key from signing.
//!
//! Gated on `swtpm` being on PATH (brew install swtpm / apt install swtpm),
//! following the SoftHSM pattern: an unprovisioned machine must not fail the
//! suite, but the skip has to be visible, not silent. Each test provisions
//! its own instance: temp state dir, ephemeral ports, shut down and removed
//! after.
//!
//! Set `OBSIGN_TPM_FIXTURE_DIR` to have the exchange test write its
//! attestation and identity entry there: that is how the swtpm fixtures in
//! obsign-audit-core are regenerated.

mod common;

use common::{start_swtpm, swtpm_on_path, Swtpm};
use obsign_audit_core::attestation::{verify_attestation, KeyAttestation};
use obsign_audit_core::error::Error as CoreError;
use obsign_tpm_enroll::enroll::{activate, measure};
use obsign_tpm_enroll::tpm::{
    ak_template, ek_template, legacy_identity_template, public_key_bytes, KeyAlg,
    TPM_RH_ENDORSEMENT, TPM_RH_OWNER,
};
use obsign_tpm_enroll::{
    challenge, finish, request, respond, sign, ActivationRequest, EnrollmentRequest, Error, Tpm,
};
use std::process::Command;

const PCR: u32 = 16;

fn binary_hash() -> [u8; 32] {
    *obsign_audit_core::hash::sha256(b"gateway-binary").as_bytes()
}

/// A started swtpm and a connection to it, or None (with the skip said)
/// when swtpm is not installed.
fn tpm(tag: &str) -> Option<(Swtpm, Tpm)> {
    if !swtpm_on_path() {
        eprintln!("skipped: swtpm not on PATH (brew install swtpm)");
        return None;
    }
    let swtpm = start_swtpm(tag); // already initialized (CMD_INIT)
    let mut tpm = Tpm::connect(&swtpm.tpm_addr).expect("connect to the TPM socket");
    tpm.startup_clear().expect("TPM2_Startup");
    Some((swtpm, tpm))
}

/// The steps, in process: measure (the launch wrapper), request,
/// challenge, respond, finish.
fn exchange(tpm: &mut Tpm, key_id: &str) -> (obsign_tpm_enroll::Enrollment, KeyAttestation) {
    measure(tpm, PCR, &binary_hash()).expect("launch-wrapper measurement");
    let req = request(tpm, &[]).expect("request");
    let (ch, state) = challenge(&req).expect("challenge");
    let resp = respond(
        tpm,
        &ch,
        &EnrollmentRequest {
            key_id: key_id.into(),
            pcr: PCR,
            measure: None,
        },
    )
    .expect("respond");
    let att = finish(&state, &resp, Some(&binary_hash())).expect("finish");
    (resp, att)
}

fn alg_of(req: &ActivationRequest) -> KeyAlg {
    public_key_bytes(&hex::decode(&req.ak_public).unwrap()).unwrap().0
}

fn mismatch(r: Result<(), CoreError>, needle: &str) {
    match r {
        Err(CoreError::AttestationMismatch(m)) => assert!(m.contains(needle), "got: {m}"),
        other => panic!("expected a mismatch naming {needle:?}, got {other:?}"),
    }
}

#[test]
fn the_full_exchange_against_a_software_tpm_is_accepted() {
    let Some((_swtpm, mut tpm)) = tpm("exchange") else {
        return;
    };
    let (resp, att) = exchange(&mut tpm, "gw-tpm-1");
    eprintln!(
        "enrolled through swtpm with activation: algorithm={}, certify {} bytes, quote {} bytes",
        resp.algorithm,
        att.certify.len() / 2,
        att.quote.len() / 2,
    );

    // The algorithm must be what the TPM's capabilities dictate.
    let eddsa = tpm.algorithms().expect("capabilities").contains(&0x0060);
    assert_eq!(resp.algorithm == "ed25519", eddsa);

    verify_attestation(&resp.identity_entry, &att).expect("v4 attestation verifies offline");
    assert!(att.activation.is_some(), "the finished attestation is in the activation form");

    // The quote reports the extended PCR: sha256(zeros || binary_hash).
    let mut preimage = [0u8; 64];
    preimage[32..].copy_from_slice(&binary_hash());
    assert_eq!(
        att.expected_pcrs[0].digest,
        hex::encode(obsign_audit_core::hash::sha256(&preimage).as_bytes()),
    );

    // The identity key signs while the PCR holds the enrolled value, and
    // the signature verifies under the enrolled key.
    let digest = *obsign_audit_core::hash::sha256(b"session certificate").as_bytes();
    let sig = sign(&mut tpm, &att, &digest).expect("signing under the PCR policy");
    if resp.algorithm != "ed25519" {
        let point = hex::decode(&resp.identity_entry.public_key).unwrap();
        assert!(obsign_audit_core::p256::verify_ecdsa_p256(&point, &digest, &sig));
    }

    if let Ok(dir) = std::env::var("OBSIGN_TPM_FIXTURE_DIR") {
        let dir = std::path::Path::new(&dir);
        std::fs::write(
            dir.join("swtpm-attestation-v4.json"),
            serde_json::to_string_pretty(&att).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("swtpm-identity-entry-v4.json"),
            serde_json::to_string_pretty(&resp.identity_entry).unwrap(),
        )
        .unwrap();
        eprintln!("fixtures written to {}", dir.display());
    }
}

#[test]
fn a_pcr_that_moved_stops_the_identity_key_from_signing() {
    let Some((_swtpm, mut tpm)) = tpm("pcrmove") else {
        return;
    };
    let (_resp, att) = exchange(&mut tpm, "gw-tpm-pcr");
    let digest = [0x42u8; 32];
    sign(&mut tpm, &att, &digest).expect("signs in the enrolled state");

    // Another binary measured after the enrolled one (or the same one
    // twice): PolicyPCR folds in the new value, the session digest no
    // longer equals the key's authPolicy, and the TPM refuses to sign.
    measure(&mut tpm, PCR, &[0x66; 32]).unwrap();
    match sign(&mut tpm, &att, &digest) {
        Err(Error::TpmRc { command: "TPM2_Sign", rc }) => {
            eprintln!("TPM refused to sign after the PCR moved: TPM_RC 0x{rc:03x}")
        }
        other => panic!("signing with a moved PCR must be refused by the TPM, got {other:?}"),
    }
}

#[test]
fn statements_not_bound_to_the_activation_are_refused() {
    let Some((_swtpm, mut tpm)) = tpm("tamper") else {
        return;
    };
    let (resp, good) = exchange(&mut tpm, "gw-tpm-tamper");
    let entry = &resp.identity_entry;

    // A corrupted quote signature is positive evidence of tampering.
    let mut att = good.clone();
    let mut raw = hex::decode(&att.quote).unwrap();
    let n = raw.len();
    raw[n - 1] ^= 0x01;
    att.quote = hex::encode(raw);
    assert!(matches!(verify_attestation(entry, &att), Err(CoreError::BadAttestation(_))));

    // A different expected PCR than the TPM measured: the wrong-binary case.
    let mut att = good.clone();
    att.expected_pcrs[0].digest = hex::encode([0xAAu8; 32]);
    assert!(verify_attestation(entry, &att).is_err());

    // The wrong nonce: not the one the statements were qualified with.
    let mut att = good.clone();
    att.activation.as_mut().unwrap().nonce = hex::encode([0u8; 32]);
    mismatch(verify_attestation(entry, &att), "not qualified");

    // A credential the TPM never released: a forged secret.
    let mut att = good.clone();
    att.activation.as_mut().unwrap().secret = hex::encode([0u8; 32]);
    mismatch(verify_attestation(entry, &att), "not qualified");

    // The missing nonce: real TPM statements made without qualifying data,
    // the pre-v4 shape, spliced under the activation record (a replay of an
    // earlier enrollment).
    let req = request(&mut tpm, &[]).unwrap();
    let alg = alg_of(&req);
    let ak = tpm.create_primary(TPM_RH_ENDORSEMENT, &ak_template(alg)).unwrap();
    let policy = obsign_audit_core::attestation::pcr_policy_digest(&good.expected_pcrs).unwrap();
    let id = tpm
        .create_primary(TPM_RH_OWNER, &obsign_tpm_enroll::tpm::identity_template(alg, &policy))
        .unwrap();
    let signed = |s: obsign_tpm_enroll::tpm::SignedAttest| {
        let mut v = s.attest;
        v.extend_from_slice(&s.sig);
        hex::encode(v)
    };
    let mut att = good.clone();
    att.certify = signed(tpm.certify(id.handle, ak.handle, &[]).unwrap());
    att.quote = signed(tpm.quote(ak.handle, PCR, &[]).unwrap());
    mismatch(verify_attestation(entry, &att), "not qualified");
    tpm.flush(id.handle).unwrap();

    // An identity key without the PCR policy (the pre-v4 template:
    // password-usable, empty authPolicy), honestly certified with the right
    // qualifier: the verifier refuses the key itself.
    let act = good.activation.as_ref().unwrap();
    let q = obsign_audit_core::attestation::activation_qualifier(
        &hex::decode(&act.nonce).unwrap(),
        &hex::decode(&act.secret).unwrap(),
    );
    let legacy = tpm.create_primary(TPM_RH_OWNER, &legacy_identity_template(alg)).unwrap();
    let mut att = good.clone();
    att.identity_pub = Some(hex::encode(&legacy.public));
    att.certify = signed(tpm.certify(legacy.handle, ak.handle, &q).unwrap());
    let mut legacy_entry = entry.clone();
    legacy_entry.public_key = hex::encode(public_key_bytes(&legacy.public).unwrap().1);
    mismatch(verify_attestation(&legacy_entry, &att), "forbidden");
    tpm.flush(legacy.handle).unwrap();
    tpm.flush(ak.handle).unwrap();

    // A truncated attest must be a refusal, never a panic.
    let mut att = good.clone();
    let raw = hex::decode(&att.quote).unwrap();
    att.quote = hex::encode(&raw[..70]);
    assert!(verify_attestation(entry, &att).is_err());

    // A response replayed against another challenge never finishes.
    let req = request(&mut tpm, &[]).unwrap();
    let (_ch, other_state) = challenge(&req).unwrap();
    assert!(matches!(finish(&other_state, &resp, None), Err(Error::Refused(_))));
}

#[test]
fn an_ak_from_another_tpm_cannot_activate() {
    let Some((_a, mut tpm_a)) = tpm("tpm-a") else {
        return;
    };
    let (_b, mut tpm_b) = tpm("tpm-b").expect("swtpm present");
    let req_a = request(&mut tpm_a, &[]).unwrap();
    let req_b = request(&mut tpm_b, &[]).unwrap();
    assert_ne!(req_a.ek_pub, req_b.ek_pub, "two TPMs, two EKs");

    // The attack: TPM A's genuine EK paired with an AK from elsewhere (here
    // TPM B's, a perfectly well-formed AK). Both public areas pass the
    // shape checks, so ops makes the challenge...
    let mixed = ActivationRequest {
        ek_pub: req_a.ek_pub.clone(),
        ak_public: req_b.ak_public.clone(),
        ..req_a.clone()
    };
    let (ch, _state) = challenge(&mixed).unwrap();

    // ...and no TPM can answer it. TPM A holds the EK but not that AK: our
    // own check refuses first, and the TPM itself refuses when asked anyway
    // with A's own AK (the credential's integrity is keyed on B's AK Name).
    let r = respond(
        &mut tpm_a,
        &ch,
        &EnrollmentRequest { key_id: "gw-mixed".into(), pcr: PCR, measure: None },
    );
    assert!(matches!(r, Err(Error::Refused(_))), "got {:?}", r.err());
    let alg = alg_of(&req_a);
    let ek_a = tpm_a.create_primary(TPM_RH_ENDORSEMENT, &ek_template()).unwrap();
    let ak_a = tpm_a.create_primary(TPM_RH_ENDORSEMENT, &ak_template(alg)).unwrap();
    match activate(&mut tpm_a, ak_a.handle, ek_a.handle, &ch) {
        Err(Error::TpmRc { command: "TPM2_ActivateCredential", rc }) => {
            eprintln!("TPM A refused a credential made for another AK: TPM_RC 0x{rc:03x}")
        }
        other => panic!("TPM A activated a credential for TPM B's AK: {other:?}"),
    }

    // TPM B holds that AK but not the EK the credential was encrypted to.
    let ek_b = tpm_b.create_primary(TPM_RH_ENDORSEMENT, &ek_template()).unwrap();
    let ak_b = tpm_b.create_primary(TPM_RH_ENDORSEMENT, &ak_template(alg)).unwrap();
    match activate(&mut tpm_b, ak_b.handle, ek_b.handle, &ch) {
        Err(Error::TpmRc { command: "TPM2_ActivateCredential", rc }) => {
            eprintln!("TPM B refused a credential encrypted to TPM A's EK: TPM_RC 0x{rc:03x}")
        }
        other => panic!("TPM B decrypted a credential made for TPM A's EK: {other:?}"),
    }

    // The control: the same TPM activates a credential made for its own
    // pair, so the refusals above are the binding, not a broken path.
    let (own, own_state) = challenge(&req_a).unwrap();
    let secret = activate(&mut tpm_a, ak_a.handle, ek_a.handle, &own).expect("own pair activates");
    assert_eq!(hex::encode(secret), own_state.secret);
    for h in [ek_a.handle, ak_a.handle] {
        tpm_a.flush(h).unwrap();
    }
    for h in [ek_b.handle, ak_b.handle] {
        tpm_b.flush(h).unwrap();
    }
}

#[test]
fn the_shipped_binary_runs_the_exchange_through_files() {
    let Some((swtpm, tpm)) = tpm("cli") else {
        return;
    };
    // swtpm serves one data client at a time: the CLI connects itself.
    drop(tpm);
    let dir = swtpm.state.join("exchange");
    std::fs::create_dir_all(&dir).unwrap();
    let bin = env!("CARGO_BIN_EXE_obsign-tpm-enroll");
    let gateway = dir.join("gateway-binary");
    std::fs::write(&gateway, b"the released gateway").unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(bin).args(args).output().expect("run obsign-tpm-enroll");
        assert!(
            out.status.success(),
            "obsign-tpm-enroll {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let p = |name: &str| dir.join(name).display().to_string();
    let tpm_addr = swtpm.tpm_addr.as_str();
    let gw = gateway.display().to_string();

    run(&["measure", "--tpm", tpm_addr, "--pcr", "16", "--binary", &gw]);
    run(&["request", "--tpm", tpm_addr, "--out", &p("request.json")]);
    run(&[
        "challenge",
        "--request",
        &p("request.json"),
        "--out",
        &p("challenge.json"),
        "--state",
        &p("state.json"),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(p("state.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the ops state holds the credential: owner-only");
    }
    run(&[
        "respond",
        "--tpm",
        tpm_addr,
        "--challenge",
        &p("challenge.json"),
        "--key-id",
        "gw-cli",
        "--pcr",
        "16",
        "--out",
        &p("response.json"),
    ]);
    let stdout = run(&[
        "finish",
        "--state",
        &p("state.json"),
        "--response",
        &p("response.json"),
        "--binary",
        &gw,
        "--out",
        &p("attestation.json"),
    ]);

    let summary: serde_json::Value = serde_json::from_slice(&stdout).expect("stdout is JSON");
    let entry: obsign_audit_core::checkpoint::PublicKeyEntry =
        serde_json::from_value(summary["identity_entry"].clone()).unwrap();
    let att: KeyAttestation =
        serde_json::from_str(&std::fs::read_to_string(p("attestation.json")).unwrap()).unwrap();
    verify_attestation(&entry, &att).expect("CLI-produced attestation verifies");

    // The ops side refuses a release the PCR does not hold.
    let other = dir.join("other-binary");
    std::fs::write(&other, b"not the release").unwrap();
    let out = Command::new(bin)
        .args(["finish", "--state", &p("state.json"), "--response", &p("response.json")])
        .args(["--binary", &other.display().to_string(), "--out", &p("refused.json")])
        .output()
        .unwrap();
    assert!(!out.status.success(), "finish accepted a PCR that does not hold the release");

    // The signing step under the PCR policy.
    let msg = dir.join("message");
    std::fs::write(&msg, b"session certificate").unwrap();
    let sig = run(&[
        "sign",
        "--tpm",
        tpm_addr,
        "--attestation",
        &p("attestation.json"),
        "--message-file",
        &msg.display().to_string(),
    ]);
    assert_eq!(String::from_utf8(sig).unwrap().trim().len(), 128);
}
