//! The enrollment ceremony: from a live TPM to the `KeyAttestation` a
//! deployment bundle carries and the identity key entry it binds.

use crate::tpm::{
    ak_template, identity_template, public_key_bytes, KeyAlg, Tpm, ALG_EDDSA, ECC_CURVE_25519,
    TPM_RH_ENDORSEMENT, TPM_RH_OWNER,
};
use crate::Error;
use obsign_audit_core::attestation::{KeyAttestation, PcrExpectation};
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};

/// What to enroll.
pub struct EnrollmentRequest {
    /// The bundle `key_id` this attestation will bind.
    pub key_id: String,
    /// SHA-256 of the gateway binary, extended into `pcr` — the measurement
    /// that chains the quote to the release manifest.
    pub binary_hash: [u8; 32],
    /// The PCR receiving the binary measurement (16, the resettable debug
    /// PCR, for swtpm runs; a launch-wrapper PCR on real platforms).
    pub pcr: u32,
    /// EK certificate bytes (DER), carried opaquely for the out-of-band
    /// vendor-root check. May be empty where the TPM has none provisioned
    /// (a fresh swtpm) — the offline verifier never validates it either way.
    pub ek_cert: Vec<u8>,
}

/// What enrollment produced.
pub struct Enrollment {
    /// The attestation, exactly as `obsign-audit-core` verifies it.
    pub attestation: KeyAttestation,
    /// The identity key as a ready deployment-bundle entry (role `origin`).
    pub identity_entry: PublicKeyEntry,
    /// Which algorithm the TPM supported (see the crate docs).
    pub algorithm: KeyAlg,
}

/// Runs the ceremony against a started TPM.
///
/// Steps, in order: pick the key algorithm off the TPM's capabilities
/// (EdDSA/ed25519 where implemented, ECDSA-P256 otherwise); create the AK
/// (endorsement hierarchy, restricted) and the identity key (owner
/// hierarchy); extend the designated PCR with the binary hash and read the
/// resulting value back — the quote must match what the TPM actually holds,
/// not what arithmetic predicts; certify the identity key under the AK;
/// quote the PCR under the AK; flush both keys.
pub fn enroll(tpm: &mut Tpm, req: &EnrollmentRequest) -> Result<Enrollment, Error> {
    let algorithm = pick_algorithm(tpm)?;

    let ak = tpm.create_primary(TPM_RH_ENDORSEMENT, &ak_template(algorithm))?;
    let identity = match tpm.create_primary(TPM_RH_OWNER, &identity_template(algorithm)) {
        Ok(k) => k,
        Err(e) => {
            let _ = tpm.flush(ak.handle);
            return Err(e);
        }
    };

    let result = ceremony(tpm, req, algorithm, &ak, &identity);
    // Flush unconditionally: a failed ceremony must not leak loaded keys —
    // TPM object slots are scarce and a retry would hit TPM_RC_OBJECT_MEMORY.
    let _ = tpm.flush(ak.handle);
    let _ = tpm.flush(identity.handle);
    result
}

fn ceremony(
    tpm: &mut Tpm,
    req: &EnrollmentRequest,
    algorithm: KeyAlg,
    ak: &crate::tpm::CreatedKey,
    identity: &crate::tpm::CreatedKey,
) -> Result<Enrollment, Error> {
    tpm.pcr_extend(req.pcr, &req.binary_hash)?;
    let pcr_value = tpm.pcr_read_sha256(req.pcr)?;

    let certify = tpm.certify(identity.handle, ak.handle)?;
    let quote = tpm.quote(ak.handle, req.pcr)?;

    let (ak_alg, ak_pub) = public_key_bytes(&ak.public)?;
    let (id_alg, id_pub) = public_key_bytes(&identity.public)?;
    debug_assert_eq!(ak_alg, algorithm);
    debug_assert_eq!(id_alg, algorithm);

    let signed = |s: &crate::tpm::SignedAttest| {
        let mut v = s.attest.clone();
        v.extend_from_slice(&s.sig);
        hex::encode(v)
    };

    Ok(Enrollment {
        attestation: KeyAttestation {
            key_id: req.key_id.clone(),
            ak_pub: hex::encode(ak_pub),
            ek_cert: hex::encode(&req.ek_cert),
            certify: signed(&certify),
            quote: signed(&quote),
            expected_pcrs: vec![PcrExpectation {
                index: req.pcr,
                digest: hex::encode(&pcr_value),
            }],
            identity_pub: Some(hex::encode(&identity.public)),
        },
        identity_entry: PublicKeyEntry {
            key_id: req.key_id.clone(),
            algo: algorithm.as_str().to_string(),
            public_key: hex::encode(id_pub),
            role: KeyRole::Origin,
        },
        algorithm,
    })
}

/// Ed25519 if the TPM implements it — the system-uniform choice — else
/// ECDSA-P256, which every TPM 2.0 carries.
fn pick_algorithm(tpm: &mut Tpm) -> Result<KeyAlg, Error> {
    let algs = tpm.algorithms()?;
    if algs.contains(&ALG_EDDSA) && tpm.ecc_curves()?.contains(&ECC_CURVE_25519) {
        Ok(KeyAlg::Ed25519)
    } else {
        Ok(KeyAlg::EcdsaP256)
    }
}
