//! Integration with a real (software) TPM — the loop the attestation-v3
//! design said only real hardware could close: enrollment produces the AK,
//! the certify and the quote from an actual TPM 2.0 implementation, and
//! `obsign_audit_core::verify_attestation` accepts the output, byte for byte.
//! Nothing here is swtpm-specific above the process management: the command
//! stream is TCG-standard, which is the point.
//!
//! Gated on `swtpm` being on PATH (brew install swtpm / apt install swtpm) —
//! the SoftHSM pattern: an unprovisioned machine must not fail the suite,
//! but the skip has to be visible, not silent. The test provisions its own
//! instance: temp state dir, ephemeral ports, shut down and removed after.
//!
//! One #[test], sequential: the swtpm process and its TPM state are shared
//! ground, and the tamper cases must run against the same real output they
//! corrupt.

mod common;

use obsign_audit_core::attestation::verify_attestation;
use obsign_audit_core::error::Error as CoreError;
use common::{start_swtpm, swtpm_on_path};
use std::process::Command;
use obsign_tpm_enroll::{enroll, EnrollmentRequest, KeyAlg, Tpm};

#[test]
fn enrolls_against_a_real_software_tpm_and_the_verifier_accepts_it() {
    if !swtpm_on_path() {
        eprintln!("skipped: swtpm not on PATH (brew install swtpm)");
        return;
    }

    let swtpm = start_swtpm("base");
    swtpm
        .ctrl
        .init()
        .expect("CMD_INIT over the control channel");

    let mut tpm = Tpm::connect(&swtpm.tpm_addr).expect("connect to the TPM socket");
    tpm.startup_clear().expect("TPM2_Startup");

    // Enroll with a known binary measurement.
    let binary_hash: [u8; 32] = *obsign_audit_core::hash::sha256(b"gateway-binary").as_bytes();
    let req = EnrollmentRequest {
        key_id: "gw-tpm-1".into(),
        binary_hash,
        pcr: 16,
        ek_cert: Vec::new(),
    };
    let enrollment = enroll(&mut tpm, &req).expect("enrollment ceremony");
    eprintln!(
        "enrolled through swtpm: algorithm={}, identity key {} bytes, \
         certify {} bytes, quote {} bytes",
        enrollment.algorithm.as_str(),
        enrollment.identity_entry.public_key.len() / 2,
        enrollment.attestation.certify.len() / 2,
        enrollment.attestation.quote.len() / 2,
    );

    // The algorithm must be what the TPM's capabilities dictate — on
    // libtpms without EdDSA that is P-256, and the choice must agree with
    // the capability the enroller read, not an assumption baked in here.
    let eddsa = tpm.algorithms().expect("capabilities").contains(&0x0060);
    match enrollment.algorithm {
        KeyAlg::Ed25519 => assert!(eddsa, "picked ed25519 on a TPM without EdDSA"),
        KeyAlg::EcdsaP256 => assert!(!eddsa, "picked P-256 on a TPM with EdDSA"),
    }

    // The design-doc loop closes: real TPM output through the real verifier.
    verify_attestation(&enrollment.identity_entry, &enrollment.attestation)
        .expect("real swtpm attestation verifies offline");

    // The quote reports the extended PCR: sha256(zeros || binary_hash).
    let mut preimage = [0u8; 64];
    preimage[32..].copy_from_slice(&binary_hash);
    assert_eq!(
        enrollment.attestation.expected_pcrs[0].digest,
        hex::encode(obsign_audit_core::hash::sha256(&preimage).as_bytes()),
        "PCR 16 must hold exactly the one extension of the binary hash"
    );

    // -- Tamper cases against the real output. --------------------------

    // A corrupted quote signature is positive evidence of tampering.
    let mut att = enrollment.attestation.clone();
    let mut raw = hex::decode(&att.quote).unwrap();
    let n = raw.len();
    raw[n - 1] ^= 0x01;
    att.quote = hex::encode(raw);
    assert!(
        matches!(
            verify_attestation(&enrollment.identity_entry, &att),
            Err(CoreError::BadAttestation(_))
        ),
        "corrupted quote signature accepted"
    );

    // A different expected PCR than the TPM measured: the wrong-binary case.
    let mut att = enrollment.attestation.clone();
    att.expected_pcrs[0].digest = hex::encode([0xAAu8; 32]);
    assert!(
        matches!(
            verify_attestation(&enrollment.identity_entry, &att),
            Err(CoreError::AttestationMismatch(_))
        ),
        "wrong PCR expectation accepted"
    );

    // A substituted identity key: certify must bind the enrolled key.
    let mut entry = enrollment.identity_entry.clone();
    let mut key = hex::decode(&entry.public_key).unwrap();
    key[10] ^= 0x01;
    entry.public_key = hex::encode(key);
    assert!(
        matches!(
            verify_attestation(&entry, &enrollment.attestation),
            Err(CoreError::AttestationMismatch(_))
        ),
        "substituted identity key accepted"
    );

    // A tampered public area: the recomputed Name no longer matches the
    // certify. (Attribute byte, so the extracted key still matches.)
    let mut att = enrollment.attestation.clone();
    let mut tp = hex::decode(att.identity_pub.as_ref().unwrap()).unwrap();
    tp[5] ^= 0x01;
    att.identity_pub = Some(hex::encode(tp));
    assert!(
        matches!(
            verify_attestation(&enrollment.identity_entry, &att),
            Err(CoreError::AttestationMismatch(_))
        ),
        "tampered TPMT_PUBLIC accepted"
    );

    // A truncated attest must be a refusal, never a panic.
    let mut att = enrollment.attestation.clone();
    let raw = hex::decode(&att.quote).unwrap();
    att.quote = hex::encode(&raw[..70]);
    assert!(
        verify_attestation(&enrollment.identity_entry, &att).is_err(),
        "truncated quote accepted"
    );

    // -- The shipped binary, same TPM. ----------------------------------

    // swtpm serves one data client at a time: release ours first.
    drop(tpm);

    let out_path = swtpm.state.join("attestation.json");
    let output = Command::new(env!("CARGO_BIN_EXE_obsign-tpm-enroll"))
        .args(["--tpm", &swtpm.tpm_addr])
        .args(["--key-id", "gw-tpm-2"])
        .args(["--binary-hash", &hex::encode(binary_hash)])
        .args(["--pcr", "16"])
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run obsign-tpm-enroll");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Stdout carries the enrollment; the --out file carries the bare
    // KeyAttestation. Both must deserialize into obsign-audit-core's types and
    // verify against each other.
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let entry: obsign_audit_core::checkpoint::PublicKeyEntry =
        serde_json::from_value(summary["identity_entry"].clone()).expect("identity entry");
    let attestation: obsign_audit_core::attestation::KeyAttestation =
        serde_json::from_str(&std::fs::read_to_string(&out_path).expect("read --out file"))
            .expect("attestation JSON");
    verify_attestation(&entry, &attestation).expect("CLI-produced attestation verifies");
    eprintln!(
        "CLI enrollment verified: algorithm={}, attestation for {}",
        summary["algorithm"], attestation.key_id
    );
}
