//! The enrollment exchange: from a live TPM to the `KeyAttestation` a
//! deployment bundle carries and the identity key entry it binds.
//!
//! Four steps, two sides, files in between (the gateway host makes no
//! network call, and the ops side holds no TPM):
//!
//! 1. **[`request`]**, gateway host: the EK (TCG template L-1) and the AK,
//!    as public areas, plus the EK certificate where the TPM has one.
//! 2. **[`challenge`]**, ops side: checks both public areas, draws a nonce
//!    and a credential, and makes the credential for the AK's Name,
//!    encrypted to the EK ([`crate::credential`]). The nonce and credential
//!    stay with ops ([`OpsState`]) until step 4.
//! 3. **[`respond`]**, gateway host: recovers the credential with
//!    `TPM2_ActivateCredential`, which the TPM performs only if it holds
//!    that EK *and* that AK; reads the measured PCR; creates the identity
//!    key under a `PolicyPCR` policy over that value; certifies it and
//!    quotes the PCR, both qualified by
//!    [`obsign_audit_core::attestation::activation_qualifier`] over the
//!    nonce and the credential.
//! 4. **[`finish`]**, ops side: checks the response answers its own
//!    challenge, records the credential, and runs the full offline verifier
//!    over the result. Only what passes is written out for the bundle.

use crate::credential::{make_credential, random32};
use crate::tpm::{
    ak_template, ek_template, identity_template, public_key_bytes, CreatedKey, KeyAlg, Tpm,
    ALG_EDDSA, ECC_CURVE_25519, TPM_RH_ENDORSEMENT, TPM_RH_OWNER,
};
use crate::Error;
use obsign_audit_core::attestation::{
    activation_qualifier, check_ak_public, check_ek_public, pcr_policy_digest, tpm_name,
    verify_attestation, Activation, KeyAttestation, PcrExpectation,
};
use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use serde::{Deserialize, Serialize};

const REQUEST_FORMAT: &str = "obsign-tpm-request/1";
const CHALLENGE_FORMAT: &str = "obsign-tpm-challenge/1";
const STATE_FORMAT: &str = "obsign-tpm-ops-state/1";

/// Step 1's output, gateway to ops. Hex throughout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActivationRequest {
    pub format: String,
    /// The EK's `TPMT_PUBLIC`.
    pub ek_pub: String,
    /// The AK's `TPMT_PUBLIC`.
    pub ak_public: String,
    /// The EK certificate (DER), empty where the TPM carries none.
    pub ek_cert: String,
}

/// Step 2's output, ops to gateway. Nothing in it is secret: the credential
/// inside is readable only by the TPM it was made for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Challenge {
    pub format: String,
    /// The AK Name the credential was made for; the gateway refuses to
    /// answer with any other AK.
    pub ak_name: String,
    /// `TPM2B_ID_OBJECT` contents.
    pub credential_blob: String,
    /// `TPM2B_ENCRYPTED_SECRET` contents.
    pub encrypted_secret: String,
    pub nonce: String,
}

/// What the ops side keeps between steps 2 and 4. **Secret** until step 4
/// completes: whoever reads `secret` can qualify statements from any AK,
/// which is the one thing the exchange exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpsState {
    pub format: String,
    pub request: ActivationRequest,
    pub nonce: String,
    pub secret: String,
}

/// Step 3's input, beyond the challenge.
pub struct EnrollmentRequest {
    /// The bundle `key_id` this attestation will bind.
    pub key_id: String,
    /// The PCR holding the gateway binary measurement (16, the resettable
    /// debug PCR, for swtpm runs; a launch-wrapper PCR on real platforms).
    pub pcr: u32,
    /// When set, extend `pcr` with this SHA-256 first ([`measure`]), for an
    /// enrollment run right after a reset. When not, the PCR is taken as the
    /// launch wrapper left it.
    pub measure: Option<[u8; 32]>,
}

/// Step 3's output, gateway to ops.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Enrollment {
    /// The attestation, its `activation.secret` still empty: the ops side
    /// fills it in step 4, from its own state.
    pub attestation: KeyAttestation,
    /// The identity key as a ready deployment-bundle entry (role `origin`).
    pub identity_entry: PublicKeyEntry,
    /// Which algorithm the TPM supported (see the crate docs).
    pub algorithm: String,
}

/// Step 1: the EK and AK public areas, the EK certificate alongside.
pub fn request(tpm: &mut Tpm, ek_cert: &[u8]) -> Result<ActivationRequest, Error> {
    let algorithm = pick_algorithm(tpm)?;
    let ek = tpm.create_primary(TPM_RH_ENDORSEMENT, &ek_template())?;
    let _ = tpm.flush(ek.handle);
    let ak = tpm.create_primary(TPM_RH_ENDORSEMENT, &ak_template(algorithm))?;
    let _ = tpm.flush(ak.handle);
    Ok(ActivationRequest {
        format: REQUEST_FORMAT.into(),
        ek_pub: hex::encode(ek.public),
        ak_public: hex::encode(ak.public),
        ek_cert: hex::encode(ek_cert),
    })
}

/// Step 2: validates the request and makes the challenge. Refuses an EK or
/// AK the verifier would refuse later, and an EK certificate that does not
/// certify the EK, so a bad pairing fails here, before any credential exists.
pub fn challenge(req: &ActivationRequest) -> Result<(Challenge, OpsState), Error> {
    if req.format != REQUEST_FORMAT {
        return Err(Error::Refused(format!("unknown request format {}", req.format)));
    }
    let ek_pub = unhex("ek_pub", &req.ek_pub)?;
    let ak_public = unhex("ak_public", &req.ak_public)?;
    let modulus = check_ek_public(&ek_pub, &unhex("ek_cert", &req.ek_cert)?)
        .map_err(|e| Error::Refused(e.to_string()))?;
    check_ak_public(&ak_public).map_err(|e| Error::Refused(e.to_string()))?;

    let ak_name = tpm_name(&ak_public);
    let nonce = random32()?;
    let secret = random32()?;
    let made = make_credential(&modulus, &ak_name, &secret)?;
    Ok((
        Challenge {
            format: CHALLENGE_FORMAT.into(),
            ak_name: hex::encode(&ak_name),
            credential_blob: hex::encode(made.credential_blob),
            encrypted_secret: hex::encode(made.encrypted_secret),
            nonce: hex::encode(nonce),
        },
        OpsState {
            format: STATE_FORMAT.into(),
            request: req.clone(),
            nonce: hex::encode(nonce),
            secret: hex::encode(secret),
        },
    ))
}

/// Step 3: activation, then the identity key, certify and quote.
///
/// The EK, AK and identity key are primaries, regenerated from their
/// hierarchy's seed and template on every `CreatePrimary`, so step 1 and
/// step 3 (and the gateway signing later, [`sign`]) meet the same keys
/// without anything persisted on the host.
pub fn respond(tpm: &mut Tpm, ch: &Challenge, req: &EnrollmentRequest) -> Result<Enrollment, Error> {
    if ch.format != CHALLENGE_FORMAT {
        return Err(Error::Refused(format!("unknown challenge format {}", ch.format)));
    }
    let algorithm = pick_algorithm(tpm)?;
    let mut loaded = Loaded(Vec::new());
    let result = (|| {
        let ek = loaded.push(tpm.create_primary(TPM_RH_ENDORSEMENT, &ek_template()))?;
        let ak = loaded.push(tpm.create_primary(TPM_RH_ENDORSEMENT, &ak_template(algorithm)))?;
        if hex::encode(tpm_name(&ak.public)) != ch.ak_name {
            return Err(Error::Refused(
                "the challenge was made for another AK than this TPM's".into(),
            ));
        }
        let secret = activate(tpm, ak.handle, ek.handle, ch)?;
        let nonce = unhex("nonce", &ch.nonce)?;
        let qualifier = activation_qualifier(&nonce, &secret);

        if let Some(hash) = &req.measure {
            measure(tpm, req.pcr, hash)?;
        }
        let pcrs = vec![PcrExpectation {
            index: req.pcr,
            digest: hex::encode(tpm.pcr_read_sha256(req.pcr)?),
        }];
        let policy = pcr_policy_digest(&pcrs).map_err(|e| Error::Refused(e.to_string()))?;
        let identity =
            loaded.push(tpm.create_primary(TPM_RH_OWNER, &identity_template(algorithm, &policy)))?;
        let certify = tpm.certify(identity.handle, ak.handle, &qualifier)?;
        let quote = tpm.quote(ak.handle, req.pcr, &qualifier)?;

        let (_, ak_raw) = public_key_bytes(&ak.public)?;
        let (_, id_raw) = public_key_bytes(&identity.public)?;
        let signed = |s: &crate::tpm::SignedAttest| {
            let mut v = s.attest.clone();
            v.extend_from_slice(&s.sig);
            hex::encode(v)
        };
        Ok(Enrollment {
            attestation: KeyAttestation {
                key_id: req.key_id.clone(),
                ak_pub: hex::encode(ak_raw),
                ek_cert: String::new(), // ops fills it from the request it checked
                certify: signed(&certify),
                quote: signed(&quote),
                expected_pcrs: pcrs,
                identity_pub: Some(hex::encode(&identity.public)),
                activation: Some(Activation {
                    ek_pub: hex::encode(&ek.public),
                    ak_public: hex::encode(&ak.public),
                    nonce: ch.nonce.clone(),
                    secret: String::new(),
                }),
            },
            identity_entry: PublicKeyEntry {
                key_id: req.key_id.clone(),
                algo: algorithm.as_str().to_string(),
                public_key: hex::encode(id_raw),
                role: KeyRole::Origin,
            },
            algorithm: algorithm.as_str().to_string(),
        })
    })();
    loaded.flush(tpm);
    result
}

/// `TPM2_ActivateCredential` under a fresh EK policy session. The session
/// is consumed on success and flushed here on failure.
pub fn activate(tpm: &mut Tpm, ak: u32, ek: u32, ch: &Challenge) -> Result<Vec<u8>, Error> {
    let blob = unhex("credential_blob", &ch.credential_blob)?;
    let secret = unhex("encrypted_secret", &ch.encrypted_secret)?;
    let session = tpm.start_policy_session()?;
    let r = tpm
        .policy_secret_endorsement(session)
        .and_then(|()| tpm.activate_credential(ak, ek, session, &blob, &secret));
    if r.is_err() {
        let _ = tpm.flush(session);
    }
    r
}

/// Step 4: the response must answer this ops side's own challenge (same
/// EK, AK, nonce), and the completed attestation must pass the offline
/// verifier. When `expected_binary` is given, the enrolled PCR must hold
/// exactly one extension of it from reset: the ops side checks the
/// measurement against the release it knows, instead of taking the gateway
/// host's word for what was measured.
pub fn finish(
    state: &OpsState,
    response: &Enrollment,
    expected_binary: Option<&[u8; 32]>,
) -> Result<KeyAttestation, Error> {
    if state.format != STATE_FORMAT {
        return Err(Error::Refused(format!("unknown ops state format {}", state.format)));
    }
    let mut att = response.attestation.clone();
    let Some(act) = att.activation.as_mut() else {
        return Err(Error::Refused("the response carries no activation".into()));
    };
    if act.ek_pub != state.request.ek_pub
        || act.ak_public != state.request.ak_public
        || act.nonce != state.nonce
    {
        return Err(Error::Refused(
            "the response answers another challenge (EK, AK or nonce differ)".into(),
        ));
    }
    act.secret = state.secret.clone();
    att.ek_cert = state.request.ek_cert.clone();

    if let Some(binary) = expected_binary {
        let want = hex::encode(extend_from_reset(binary));
        if att.expected_pcrs.len() != 1 || att.expected_pcrs[0].digest != want {
            return Err(Error::Refused(
                "the enrolled PCR does not hold exactly one extension of the expected \
                 binary hash"
                    .into(),
            ));
        }
    }
    verify_attestation(&response.identity_entry, &att)
        .map_err(|e| Error::Refused(format!("the completed attestation does not verify: {e}")))?;
    Ok(att)
}

/// The value a SHA-256 PCR holds after one extension of `hash` from reset:
/// `SHA-256(0^32 || hash)`.
pub fn extend_from_reset(hash: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[32..].copy_from_slice(hash);
    *obsign_audit_core::hash::sha256(&preimage).as_bytes()
}

/// The launch-wrapper step: extends `pcr` with a binary's SHA-256. On a
/// platform whose PCR was reset at boot, running this once before the
/// gateway starts is what makes the identity key usable (its PCR policy
/// expects exactly this value); a second extension, or another binary's,
/// leaves it unusable until the next reset.
pub fn measure(tpm: &mut Tpm, pcr: u32, binary_hash: &[u8; 32]) -> Result<(), Error> {
    tpm.pcr_extend(pcr, binary_hash)
}

/// SHA-256 of a file, the measurement [`measure`] extends.
pub fn hash_file(path: &std::path::Path) -> Result<[u8; 32], Error> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Signs a SHA-256 `digest` with the enrolled identity key: recreates the
/// key from the attestation's PCR expectations, opens a policy session,
/// runs `TPM2_PolicyPCR` over the enrolled PCRs, and signs. The TPM refuses
/// (a policy failure) unless the PCRs hold the enrolled values right now.
/// Returns the 64-byte signature (`r || s` for ECDSA).
///
/// This is the signing path a TPM-resident gateway identity key must take;
/// the gateway itself signs through PKCS#11 today (see
/// `docs/design/attestation-v4.md`, "What is not proven").
pub fn sign(tpm: &mut Tpm, att: &KeyAttestation, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
    let algorithm = pick_algorithm(tpm)?;
    let policy = pcr_policy_digest(&att.expected_pcrs).map_err(|e| Error::Refused(e.to_string()))?;
    let indices: Vec<u32> = att.expected_pcrs.iter().map(|p| p.index).collect();
    let selection = obsign_audit_core::attestation::sha256_pcr_selection(&indices)
        .map_err(|e| Error::Refused(e.to_string()))?;
    let key = tpm.create_primary(TPM_RH_OWNER, &identity_template(algorithm, &policy))?;
    let result = (|| {
        if Some(hex::encode(&key.public)) != att.identity_pub {
            return Err(Error::Refused(
                "this TPM's identity key is not the enrolled one".into(),
            ));
        }
        let session = tpm.start_policy_session()?;
        let r = tpm
            .policy_pcr(session, &selection)
            .and_then(|()| tpm.sign_with_policy(key.handle, session, digest));
        if r.is_err() {
            let _ = tpm.flush(session);
        }
        r
    })();
    let _ = tpm.flush(key.handle);
    result
}

/// Keys loaded during a step, flushed together whatever the outcome: a
/// failed step must not leak loaded keys, since TPM object slots are scarce
/// and a retry would hit `TPM_RC_OBJECT_MEMORY`.
struct Loaded(Vec<u32>);

impl Loaded {
    fn push(&mut self, k: Result<CreatedKey, Error>) -> Result<CreatedKey, Error> {
        let k = k?;
        self.0.push(k.handle);
        Ok(k)
    }
    fn flush(self, tpm: &mut Tpm) {
        for h in self.0 {
            let _ = tpm.flush(h);
        }
    }
}

fn unhex(what: &str, s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(s).map_err(|_| Error::Refused(format!("{what} is not hex")))
}

/// Ed25519 if the TPM implements it (the system-uniform choice), else
/// ECDSA-P256, which every TPM 2.0 carries.
fn pick_algorithm(tpm: &mut Tpm) -> Result<KeyAlg, Error> {
    let algs = tpm.algorithms()?;
    if algs.contains(&ALG_EDDSA) && tpm.ecc_curves()?.contains(&ECC_CURVE_25519) {
        Ok(KeyAlg::Ed25519)
    } else {
        Ok(KeyAlg::EcdsaP256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_from_reset_is_the_pcr_extend_rule() {
        // PCR_new = H(PCR_old || measurement), PCR_old = 0^32 after reset.
        let h = [0x5Au8; 32];
        let mut pre = vec![0u8; 32];
        pre.extend_from_slice(&h);
        assert_eq!(&extend_from_reset(&h), obsign_audit_core::hash::sha256(&pre).as_bytes());
    }

    #[test]
    fn a_request_with_a_bad_ek_gets_no_challenge() {
        // An AK public area in the EK's place: not a restricted decryption
        // key, so no credential is ever made for it.
        let ak = hex::encode(ak_template(KeyAlg::EcdsaP256));
        let req = ActivationRequest {
            format: REQUEST_FORMAT.into(),
            ek_pub: ak.clone(),
            ak_public: ak,
            ek_cert: String::new(),
        };
        assert!(matches!(challenge(&req), Err(Error::Refused(_))));
    }

    #[test]
    fn a_challenge_is_fresh_every_time() {
        // The template carries a zero unique; give it a plausible modulus.
        let mut ek = ek_template();
        let n = ek.len();
        ek[n - 256..].fill(0xC1);
        let req = ActivationRequest {
            format: REQUEST_FORMAT.into(),
            ek_pub: hex::encode(ek),
            ak_public: hex::encode(ak_template(KeyAlg::EcdsaP256)),
            ek_cert: String::new(),
        };
        let (c1, s1) = challenge(&req).unwrap();
        let (c2, s2) = challenge(&req).unwrap();
        assert_ne!(c1.nonce, c2.nonce);
        assert_ne!(s1.secret, s2.secret);
        assert_eq!(c1.nonce, s1.nonce);
        assert_eq!(c1.ak_name, hex::encode(tpm_name(&ak_template(KeyAlg::EcdsaP256))));
    }
}
