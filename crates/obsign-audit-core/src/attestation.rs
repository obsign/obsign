//! Remote attestation of a gateway identity key (v3).
//!
//! v2 removed signing-key material from disk, but origin authentication's
//! floor still stands: it cannot defend against a compromised gateway
//! *process*. An attacker who owns the running binary makes the hardware
//! identity key certify session keys for records the real software would have
//! refused, and every signature verifies.
//!
//! Attestation closes that by binding the identity key to a measured boot and
//! a measured gateway binary: a TPM quote, signed by the TPM's attestation
//! key (AK), reports the platform's PCR values; a TPM certify, also signed by
//! the AK, states that the identity key is TPM-resident. Enrolled in the
//! deployment bundle (so the ops key covers it), the pair lets the verifier
//! answer "which software was enforcing the policy?".
//!
//! What is proven where, following the [`crate::rfc3161`] anchor stance
//! exactly:
//!
//! * **offline** (here): the AK signed the quote and the certify; the certify
//!   binds *this* identity key; the quote's PCR digest matches the
//!   expectations the ops key signed. This proves the identity key is bound
//!   to a TPM reporting these measurements.
//! * **out of band** (named, not performed here): the EK certificate chains
//!   to the TPM vendor root, proving the AK is genuine silicon. An air-gapped
//!   verifier has no vendor PKI; the report says so
//!   (`attestation_not_rooted`), it does not pretend otherwise.
//!
//! Interop note (resolved against a real software TPM, swtpm/libtpms driven
//! by `obsign-tpm-enroll`): the `TPMS_ATTEST` wire format below is the
//! TCG-standard subset the checks need, bounds-checked in the DER
//! discipline, and it parses real TPM output byte-for-byte. Two facts that
//! only real TPM output could settle, both now settled:
//!
//! * **AK algorithm.** The AK signs Ed25519 where the TPM implements EdDSA,
//!   the system-uniform choice. The libtpms swtpm builds on (0.10) implements
//!   no EdDSA at all (no `TPM_ALG_EDDSA`, no 25519 curve; an EdDSA
//!   `CreatePrimary` fails `TPM_RC_SCHEME`), and real silicon rarely does
//!   better, so the verifier equally accepts an **ECDSA-P256** AK: a 65-byte
//!   uncompressed `ak_pub` and a raw `r || s` signature over the SHA-256 of
//!   the attest bytes (see [`crate::p256`]). Which algorithm applies is read
//!   off the key material, never off attacker-controlled fields.
//! * **Name binding.** A real `TPM2_Certify` names the key as
//!   `alg || H(TPMT_PUBLIC)`, the hash of the full marshalled public area,
//!   not of the bare key. An attestation therefore carries the identity
//!   key's `TPMT_PUBLIC` (`identity_pub`), from which the verifier both
//!   recomputes the Name the certify must match and extracts the raw public
//!   key that must equal the enrolled bundle entry. Attestations without
//!   `identity_pub` keep verifying under the earlier synthetic binding,
//!   `alg || H(raw ed25519 key)`. The two forms are documented on
//!   [`KeyAttestation::identity_pub`].
//!
//! **Activation form** (attestation v4, `docs/design/attestation-v4.md`). An
//! attestation carrying an [`Activation`] proves three things the earlier
//! forms did not, and the verifier checks each offline:
//!
//! * the AK sits in the same TPM as the EK the bundle records: the ops side
//!   encrypted a credential to that EK for the AK's Name
//!   (`TPM2_MakeCredential`), and the quote and the certify are qualified by
//!   a value only a holder of that credential could compute
//!   ([`activation_qualifier`]). `TPM2_ActivateCredential` releases the
//!   credential only to a TPM that holds both keys;
//! * the quote and the certify answer *this* enrollment's challenge, not an
//!   earlier one: the qualifier also covers the ops nonce;
//! * the identity key can sign only while the PCRs hold the enrolled values:
//!   its `authPolicy` is the `TPM2_PolicyPCR` digest over them and
//!   `userWithAuth` is clear, so its empty password does not open it. Its
//!   `fixedTPM`, `fixedParent` and `sensitiveDataOrigin` bits are checked,
//!   and the AK's `restricted` and `sign`.
//!
//! What it still does not prove: that the EK is genuine silicon (the vendor
//! chain stays out of band), and that the ops side kept the credential secret
//! until the exchange closed, which the ops signature over the bundle vouches
//! for and nothing here can.

use crate::checkpoint::PublicKeyEntry;
use crate::error::Error;
use crate::hash::sha256;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// `TPM_GENERATED_VALUE`, the magic prefixing every genuine `TPMS_ATTEST`,
/// so a caller cannot pass an arbitrary blob off as an attestation.
const TPM_GENERATED: u32 = 0xFF54_4347; // "\xFFTCG"
const ST_ATTEST_CERTIFY: u16 = 0x8017;
const ST_ATTEST_QUOTE: u16 = 0x8018;
/// `TPM_ALG_SHA256`, the name algorithm this verifier supports.
const ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_ECC`, the object type of both key shapes this verifier reads.
const ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_ECDSA` / `TPM_ALG_EDDSA`, the two signing schemes an identity
/// key's `TPMT_PUBLIC` may carry (see the module interop note).
const ALG_ECDSA: u16 = 0x0018;
const ALG_EDDSA: u16 = 0x0060;
const ALG_NULL: u16 = 0x0010;
/// `TPM_ECC_NIST_P256` / `TPM_ECC_25519` curve identifiers.
const ECC_NIST_P256: u16 = 0x0003;
const ECC_CURVE_25519: u16 = 0x0040;
/// `TPM_ALG_RSA`, `TPM_ALG_AES`, `TPM_ALG_CFB`: the EK shape of the TCG
/// default template L-1 (RSA 2048, AES-128-CFB storage parameters).
const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_CFB: u16 = 0x0043;

/// `TPMA_OBJECT` bits the activation form judges (TPM 2.0 Part 2, §8.3).
pub const ATTR_FIXED_TPM: u32 = 1 << 1;
pub const ATTR_FIXED_PARENT: u32 = 1 << 4;
pub const ATTR_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const ATTR_USER_WITH_AUTH: u32 = 1 << 6;
pub const ATTR_ADMIN_WITH_POLICY: u32 = 1 << 7;
pub const ATTR_RESTRICTED: u32 = 1 << 16;
pub const ATTR_DECRYPT: u32 = 1 << 17;
pub const ATTR_SIGN: u32 = 1 << 18;

const CC_POLICY_SECRET: u32 = 0x0000_0151;
const CC_POLICY_PCR: u32 = 0x0000_017F;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

/// Domain prefix of [`activation_qualifier`], so the qualifying data of an
/// obsign enrollment cannot be confused with any other use of the nonce.
const ACTIVATION_DOMAIN: &[u8] = b"obsign-tpm-activation/1\0";

/// `algo` string of a P-256 identity key entry (see
/// [`KeyAttestation::identity_pub`] for when one exists at all).
pub const ALGO_ECDSA_P256: &str = "ecdsa-p256";
const ALGO_ED25519: &str = "ed25519";

/// One PCR the quote must report, with the value the ops key expects it to
/// hold. The gateway-binary PCR is the hash of the released binary (chained
/// to the release manifest), so a running gateway proves it *is* that binary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PcrExpectation {
    pub index: u32,
    /// Expected PCR value, hex.
    pub digest: String,
}

/// A gateway identity key's enrollment attestation, carried in the deployment
/// bundle and covered by the ops signature over it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyAttestation {
    /// Which identity key (by id) this attestation binds.
    pub key_id: String,
    /// AK public key, hex: signs the quote and the certify. 32 bytes for an
    /// ed25519 AK; 65 bytes (`04 || x || y`, the uncompressed point) for an
    /// ECDSA-P256 AK. That is the fallback for TPMs that implement no EdDSA,
    /// which includes the swtpm this tree tests against (module interop note).
    pub ak_pub: String,
    /// EK certificate (DER, hex). Chains to the TPM vendor root, validated
    /// out of band and never here.
    pub ek_cert: String,
    /// `TPM2_Certify` output binding the identity key to the AK: the
    /// marshalled `TPMS_ATTEST` followed by the AK's 64-byte signature, hex.
    pub certify: String,
    /// `TPM2_Quote` over the PCRs: marshalled `TPMS_ATTEST` followed by the
    /// AK's 64-byte signature, hex.
    pub quote: String,
    /// The PCR values the quote must report, ops-signed via the bundle.
    pub expected_pcrs: Vec<PcrExpectation>,
    /// The identity key's marshalled `TPMT_PUBLIC` (hex), the structure a
    /// real TPM hashes into the Name its certify reports.
    ///
    /// The two binding forms, in order of preference:
    ///
    /// * **Present** (everything a real TPM emits, via `obsign-tpm-enroll`): the
    ///   certify must name `alg || H(these bytes)`, and the raw public key
    ///   extracted from them must equal the enrolled bundle entry, closing
    ///   the chain from bundle entry to public area to Name to AK signature
    ///   with no gap an attacker could stand in.
    /// * **Absent** (pre-hardware attestations): the certify must name
    ///   `alg || H(raw ed25519 key)`, the synthetic binding the verifier
    ///   shipped with. Kept so existing attestations verify unchanged; a
    ///   real TPM never produces this form.
    ///
    /// `serde(default)`: attestations minted before this field parse as the
    /// legacy form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_pub: Option<String>,
    /// The credential-activation binding (attestation v4). Present, it makes
    /// the verifier require everything listed under "Activation form" in the
    /// module docs; absent, the attestation verifies in its earlier form and
    /// the report says what that form leaves unproven. Signed only by an
    /// `obsign-deployment/2` bundle: a `/1` bundle carrying it is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<Activation>,
}

/// What the enrollment exchange recorded about credential activation, from
/// which the verifier recomputes the binding between EK, AK and the signed
/// statements. Every field is hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Activation {
    /// The EK's marshalled `TPMT_PUBLIC`: the key the credential was
    /// encrypted to. Must have the TCG default RSA-2048 EK shape (template
    /// L-1: restricted decryption key, `PolicySecret(TPM_RH_ENDORSEMENT)`),
    /// and when `ek_cert` is present, the certificate must certify its
    /// modulus.
    pub ek_pub: String,
    /// The AK's marshalled `TPMT_PUBLIC`, whose Name the credential was made
    /// for. Must hold the `ak_pub` key and be a restricted signing key that
    /// was generated in, and cannot leave, its TPM.
    pub ak_public: String,
    /// The ops challenge nonce, 32 bytes.
    pub nonce: String,
    /// The credential the TPM recovered with `TPM2_ActivateCredential`,
    /// 32 bytes. Released by the ops side once the exchange closed: it has
    /// done its job, and recording it lets anyone recompute the qualifier.
    pub secret: String,
}

/// The `qualifyingData` an enrollment's certify and quote carry:
/// `SHA-256(domain || nonce || secret)`. Computing it needs the credential,
/// which only the TPM holding both the EK and the AK can recover.
pub fn activation_qualifier(nonce: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut m = ACTIVATION_DOMAIN.to_vec();
    m.extend_from_slice(nonce);
    m.extend_from_slice(secret);
    *sha256(&m).as_bytes()
}

/// The TPM Name of a marshalled public area: `TPM_ALG_SHA256 || H(area)`.
pub fn tpm_name(tpmt_public: &[u8]) -> Vec<u8> {
    let mut name = ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(sha256(tpmt_public).as_bytes());
    name
}

/// A `TPML_PCR_SELECTION` naming `indices` in the SHA-256 bank, three-byte
/// bitmap (PCRs 0..23). The enroller sends exactly these bytes to
/// `TPM2_Quote` and `TPM2_PolicyPCR`, and [`pcr_policy_digest`] hashes them,
/// so the two agree by construction.
pub fn sha256_pcr_selection(indices: &[u32]) -> Result<Vec<u8>, Error> {
    let mut bitmap = [0u8; 3];
    for &i in indices {
        if i >= 24 {
            return Err(Error::BadAttestation(format!(
                "PCR {i} out of range: a TPM 2.0 bank holds PCRs 0..23"
            )));
        }
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
    }
    let mut v = 1u32.to_be_bytes().to_vec();
    v.extend_from_slice(&ALG_SHA256.to_be_bytes());
    v.push(3);
    v.extend_from_slice(&bitmap);
    Ok(v)
}

/// The policy digest `TPM2_PolicyPCR` leaves in a fresh SHA-256 policy
/// session when the selected PCRs hold `pcrs`: `H(0^32 || TPM_CC_PolicyPCR ||
/// selection || H(values in index order))` (TPM 2.0 Part 3, §23.7). An
/// identity key whose `authPolicy` is this digest signs only in that state.
pub fn pcr_policy_digest(pcrs: &[PcrExpectation]) -> Result<Vec<u8>, Error> {
    if pcrs.is_empty() {
        return Err(Error::AttestationMismatch(
            "no expected PCRs: a PCR policy over nothing gates nothing".into(),
        ));
    }
    let indices: Vec<u32> = pcrs.iter().map(|p| p.index).collect();
    let mut m = vec![0u8; 32];
    m.extend_from_slice(&CC_POLICY_PCR.to_be_bytes());
    m.extend_from_slice(&sha256_pcr_selection(&indices)?);
    m.extend_from_slice(&expected_pcr_digest(pcrs)?);
    Ok(sha256(&m).as_bytes().to_vec())
}

/// The `authPolicy` of the TCG default EK templates:
/// `PolicySecret(TPM_RH_ENDORSEMENT)` from a zero digest, empty policyRef
/// (TCG EK Credential Profile, §B.3.3; the published value is pinned by a
/// test). Using the EK therefore needs the endorsement hierarchy's auth.
pub fn ek_policy() -> Vec<u8> {
    let mut m = vec![0u8; 32];
    m.extend_from_slice(&CC_POLICY_SECRET.to_be_bytes());
    m.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes()); // the hierarchy's Name
    let d = sha256(&m);
    // PolicyUpdate's second hash, over the (empty) policyRef.
    sha256(d.as_bytes()).as_bytes().to_vec()
}

/// Checks that `ek_pub` is an EK of the shape the credential exchange relies
/// on, and, when `ek_cert` is not empty, that the certificate certifies it.
/// Returns the RSA modulus.
///
/// Why each requirement: `restricted` + `decrypt` is what makes the TPM
/// refuse to decrypt the credential seed outside `ActivateCredential` (an
/// unrestricted decryption key would hand it to `TPM2_RSA_Decrypt` and to
/// anyone); `fixedTPM` + `sensitiveDataOrigin` mean the private part was
/// generated inside and cannot leave; the EK policy means the hierarchy
/// owner, not any process, decides when it is used.
pub fn check_ek_public(ek_pub: &[u8], ek_cert: &[u8]) -> Result<Vec<u8>, Error> {
    let ek = parse_rsa_ek(ek_pub)?;
    check_attributes(
        "EK",
        ek.attributes,
        ATTR_FIXED_TPM
            | ATTR_FIXED_PARENT
            | ATTR_SENSITIVE_DATA_ORIGIN
            | ATTR_ADMIN_WITH_POLICY
            | ATTR_RESTRICTED
            | ATTR_DECRYPT,
        ATTR_SIGN | ATTR_USER_WITH_AUTH,
    )?;
    if ek.auth_policy != ek_policy() {
        return Err(Error::AttestationMismatch(
            "the EK's authPolicy is not the TCG EK policy".into(),
        ));
    }
    if !ek_cert.is_empty() {
        let (modulus, exponent) = certificate_rsa_key(ek_cert)?;
        if modulus != ek.modulus || exponent != 65537 {
            return Err(Error::AttestationMismatch(
                "the EK certificate certifies a different key than the recorded EK".into(),
            ));
        }
    }
    Ok(ek.modulus)
}

/// Checks that `ak_public` is an attestation key: a restricted signing key
/// generated in its TPM and unable to leave it. Returns the raw key in the
/// `ak_pub` wire form.
///
/// Restricted is the property the whole quote rests on: a restricted
/// signing key refuses to sign anything that begins with `TPM_GENERATED`
/// unless the TPM produced it. `fixedTPM` is what lets the credential
/// exchange prove where the AK lives: a key the TPM did not generate could
/// be loaded alongside a genuine EK.
pub fn check_ak_public(ak_public: &[u8]) -> Result<Vec<u8>, Error> {
    let ak = parse_tpmt_public(ak_public)?;
    if ak.name_alg != ALG_SHA256 {
        return Err(Error::BadAttestation(format!(
            "unsupported AK name algorithm 0x{:04X}",
            ak.name_alg
        )));
    }
    check_attributes(
        "AK",
        ak.attributes,
        ATTR_FIXED_TPM | ATTR_FIXED_PARENT | ATTR_SENSITIVE_DATA_ORIGIN | ATTR_RESTRICTED | ATTR_SIGN,
        ATTR_DECRYPT,
    )?;
    Ok(match ak.key {
        TpmPublicKey::Ed25519(raw) => raw.to_vec(),
        TpmPublicKey::EcdsaP256(point) => point,
    })
}

fn check_attributes(what: &str, attrs: u32, required: u32, forbidden: u32) -> Result<(), Error> {
    if attrs & required != required {
        return Err(Error::AttestationMismatch(format!(
            "the {what} lacks required attributes 0x{:08X} (has 0x{attrs:08X})",
            required & !attrs
        )));
    }
    if attrs & forbidden != 0 {
        return Err(Error::AttestationMismatch(format!(
            "the {what} carries forbidden attributes 0x{:08X}",
            attrs & forbidden
        )));
    }
    Ok(())
}

/// The activation-form checks that do not need the signed statements, and
/// the qualifier those statements must then carry.
fn verify_activation(att: &KeyAttestation, act: &Activation) -> Result<[u8; 32], Error> {
    let unhex = |s: &String| hex::decode(s).map_err(|_| Error::BadHex(s.clone()));

    let ak_raw = check_ak_public(&unhex(&act.ak_public)?)?;
    if ak_raw != unhex(&att.ak_pub)? {
        return Err(Error::AttestationMismatch(
            "the AK public area holds a different key than ak_pub".into(),
        ));
    }
    check_ek_public(&unhex(&act.ek_pub)?, &unhex(&att.ek_cert)?)?;

    // The identity key: TPM-generated, TPM-bound, and openable only by the
    // PCR policy. userWithAuth set would let its empty password sign
    // whatever the PCRs hold, which is exactly what the policy is for.
    let Some(tp_hex) = &att.identity_pub else {
        return Err(Error::AttestationMismatch(
            "the activation form requires the identity key's TPMT_PUBLIC".into(),
        ));
    };
    let identity = parse_tpmt_public(&unhex(tp_hex)?)?;
    check_attributes(
        "identity key",
        identity.attributes,
        ATTR_FIXED_TPM | ATTR_FIXED_PARENT | ATTR_SENSITIVE_DATA_ORIGIN | ATTR_SIGN,
        ATTR_USER_WITH_AUTH | ATTR_RESTRICTED | ATTR_DECRYPT,
    )?;
    if identity.auth_policy != pcr_policy_digest(&att.expected_pcrs)? {
        return Err(Error::AttestationMismatch(
            "the identity key's authPolicy is not the PCR policy over the enrolled \
             measurements: it could sign whatever the platform runs"
                .into(),
        ));
    }

    let nonce = unhex(&act.nonce)?;
    let secret = unhex(&act.secret)?;
    if nonce.len() != 32 || secret.len() != 32 {
        return Err(Error::BadAttestation(
            "activation nonce and secret must be 32 bytes each".into(),
        ));
    }
    Ok(activation_qualifier(&nonce, &secret))
}

/// The legacy TPM Name of an identity key: `alg || H(raw ed25519 key)`.
///
/// A real TPM names a key `alg || H(TPMT_PUBLIC)`, carried and recomputed
/// via [`KeyAttestation::identity_pub`]. This synthetic form remains what an
/// attestation *without* that field must bind, so pre-hardware attestations
/// keep verifying; it is equally sufficient to prove the certify names
/// *this* key and no other.
pub fn identity_name(key: &VerifyingKey) -> Vec<u8> {
    let mut out = ALG_SHA256.to_be_bytes().to_vec();
    out.extend_from_slice(sha256(key.as_bytes()).as_bytes());
    out
}

/// The AK's public key, in whichever of the two accepted shapes the hex
/// material decodes to. The shape decides the signature check: ed25519 over
/// the attest bytes, ECDSA-P256 over their SHA-256 (a TPM signs digests).
enum AkPublic {
    Ed25519(VerifyingKey),
    /// Uncompressed point, `04 || x || y`. Curve membership is checked at
    /// every verification by [`crate::p256::verify_ecdsa_p256`].
    EcdsaP256(Vec<u8>),
}

fn parse_ak(hexed: &str) -> Result<AkPublic, Error> {
    let raw = hex::decode(hexed).map_err(|_| Error::BadHex(hexed.to_string()))?;
    match raw.len() {
        32 => {
            let arr: [u8; 32] = raw.try_into().expect("checked length");
            Ok(AkPublic::Ed25519(
                VerifyingKey::from_bytes(&arr).map_err(|_| Error::BadKey(hexed.to_string()))?,
            ))
        }
        65 if raw[0] == 0x04 => Ok(AkPublic::EcdsaP256(raw)),
        _ => Err(Error::BadKey(hexed.to_string())),
    }
}

impl AkPublic {
    fn verify(&self, attest: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let ok = match self {
            AkPublic::Ed25519(vk) => vk.verify(attest, &Signature::from_bytes(sig)).is_ok(),
            AkPublic::EcdsaP256(point) => {
                crate::p256::verify_ecdsa_p256(point, sha256(attest).as_bytes(), sig)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::BadAttestation("AK signature does not verify".into()))
        }
    }
}

/// A parsed, AK-verified `TPMS_ATTEST`: the caller's `extraData`
/// (`qualifyingData` at signing time), then the type-specific body.
struct SignedStatement {
    extra_data: Vec<u8>,
    body: Attested,
}

/// What a parsed `TPMS_ATTEST` yields, for the two statement types used.
enum Attested {
    Quote {
        pcr_digest: Vec<u8>,
        /// The PCRs the AK actually signed over, as (bank algorithm, index)
        /// pairs decoded from the quote's `TPML_PCR_SELECTION`.
        selected: Vec<(u16, u32)>,
    },
    Certify {
        name: Vec<u8>,
    },
}

/// Verifies one identity key's attestation, offline and structurally.
///
/// `entry` is the identity key as it appears in the deployment bundle. On
/// success the caller may trust that this key is bound to a TPM reporting the
/// expected measurements, subject to the out-of-band EK-root check the
/// caller must still surface.
pub fn verify_attestation(entry: &PublicKeyEntry, att: &KeyAttestation) -> Result<(), Error> {
    let ak = parse_ak(&att.ak_pub)?;
    let expected_name = expected_identity_name(entry, att)?;
    let qualifier = match &att.activation {
        None => None,
        Some(act) => Some(verify_activation(att, act)?),
    };

    // The certify must bind THIS identity key.
    let certify = verify_signed_attest(&att.certify, &ak)?;
    check_qualified("certify", &certify, qualifier.as_ref())?;
    match certify.body {
        Attested::Certify { name } => {
            if name != expected_name {
                return Err(Error::AttestationMismatch(
                    "the certify names a different key than the enrolled identity key".into(),
                ));
            }
        }
        Attested::Quote { .. } => {
            return Err(Error::AttestationMismatch(
                "the certify field is a quote, not a certify".into(),
            ))
        }
    }

    // The quote must report the ops-expected PCR values, and must have
    // signed over exactly the expected PCRs. Comparing the digest alone
    // would let a quote over a *different* PCR holding the same value pass,
    // and with resettable PCRs that value is reproducible at will.
    let quote = verify_signed_attest(&att.quote, &ak)?;
    check_qualified("quote", &quote, qualifier.as_ref())?;
    match quote.body {
        Attested::Quote {
            pcr_digest,
            selected,
        } => {
            let mut expected_idx: Vec<u32> =
                att.expected_pcrs.iter().map(|p| p.index).collect();
            expected_idx.sort_unstable();
            expected_idx.dedup();
            let mut selected_idx = Vec::new();
            for (alg, idx) in &selected {
                if *alg != ALG_SHA256 {
                    return Err(Error::AttestationMismatch(format!(
                        "the quote selects PCR bank 0x{alg:04X}: only the SHA-256 \
                         bank is expected"
                    )));
                }
                selected_idx.push(*idx);
            }
            selected_idx.sort_unstable();
            selected_idx.dedup();
            if selected_idx != expected_idx {
                return Err(Error::AttestationMismatch(format!(
                    "the quote signed over PCRs {selected_idx:?}, the enrollment \
                     expects {expected_idx:?}"
                )));
            }
            if pcr_digest != expected_pcr_digest(&att.expected_pcrs)? {
                return Err(Error::AttestationMismatch(
                    "the quote's PCR digest does not match the enrolled expectations: \
                     the platform booted a different binary or state"
                        .into(),
                ));
            }
        }
        Attested::Certify { .. } => {
            return Err(Error::AttestationMismatch(
                "the quote field is a certify, not a quote".into(),
            ))
        }
    }

    if att.expected_pcrs.is_empty() {
        return Err(Error::AttestationMismatch(
            "no expected PCRs: an attestation that measures nothing proves nothing".into(),
        ));
    }
    Ok(())
}

/// In the activation form, a signed statement must carry the enrollment's
/// qualifier as its `extraData`: one that does not was either produced for
/// another challenge (a replay) or by an AK that never recovered the
/// credential.
fn check_qualified(what: &str, st: &SignedStatement, qualifier: Option<&[u8; 32]>) -> Result<(), Error> {
    match qualifier {
        Some(q) if st.extra_data != q => Err(Error::AttestationMismatch(format!(
            "the {what} is not qualified by this enrollment's activation: replayed, \
             or signed by an AK that never recovered the credential"
        ))),
        _ => Ok(()),
    }
}

/// The Name the certify must report for this enrollment and, when the
/// attestation carries the identity key's `TPMT_PUBLIC`, the proof that the
/// public area is the enrolled key's and not a substitute.
///
/// Two forms (documented on [`KeyAttestation::identity_pub`]):
///
/// * `identity_pub` present, the real-TPM form: parse the public area,
///   require the raw key inside it to equal the bundle entry (same bytes,
///   consistent `algo`), and return `alg || H(TPMT_PUBLIC)`.
/// * absent, the legacy synthetic form: `alg || H(raw ed25519 key)`.
fn expected_identity_name(entry: &PublicKeyEntry, att: &KeyAttestation) -> Result<Vec<u8>, Error> {
    let Some(tp_hex) = &att.identity_pub else {
        return Ok(identity_name(&entry.to_verifying_key()?));
    };
    let tp = hex::decode(tp_hex).map_err(|_| Error::BadHex(tp_hex.clone()))?;
    let parsed = parse_tpmt_public(&tp)?;
    if parsed.name_alg != ALG_SHA256 {
        return Err(Error::BadAttestation(format!(
            "unsupported TPMT_PUBLIC name algorithm 0x{:04X}",
            parsed.name_alg
        )));
    }
    let entry_raw =
        hex::decode(&entry.public_key).map_err(|_| Error::BadHex(entry.public_key.clone()))?;
    let (raw, algo) = match &parsed.key {
        TpmPublicKey::Ed25519(raw) => (&raw[..], ALGO_ED25519),
        TpmPublicKey::EcdsaP256(point) => (&point[..], ALGO_ECDSA_P256),
    };
    if entry.algo != algo {
        return Err(Error::AttestationMismatch(format!(
            "the identity TPMT_PUBLIC holds a {algo} key but the enrolled entry says {}",
            entry.algo
        )));
    }
    if raw != entry_raw {
        return Err(Error::AttestationMismatch(
            "the identity TPMT_PUBLIC holds a different key than the enrolled entry".into(),
        ));
    }
    Ok(tpm_name(&tp))
}

/// What a `TPMT_PUBLIC` yields: its name algorithm and the raw key inside.
struct TpmtPublic {
    name_alg: u16,
    attributes: u32,
    auth_policy: Vec<u8>,
    key: TpmPublicKey,
}

enum TpmPublicKey {
    /// Raw 32-byte ed25519 public key (the `x` of a curve-25519 EdDSA point).
    Ed25519([u8; 32]),
    /// Uncompressed P-256 point, `04 || x || y`, 65 bytes.
    EcdsaP256(Vec<u8>),
}

/// Parses the marshalled `TPMT_PUBLIC` of an ECC signing key, the exact
/// bytes the TPM hashes into the key's Name, so the parse must consume them
/// all: trailing bytes would mean naming something this parser did not read.
fn parse_tpmt_public(b: &[u8]) -> Result<TpmtPublic, Error> {
    let mut r = Reader::new(b);
    let object_type = r.u16()?;
    if object_type != ALG_ECC {
        return Err(Error::BadAttestation(format!(
            "unsupported TPMT_PUBLIC type 0x{object_type:04X}: only ECC signing keys are attested"
        )));
    }
    let name_alg = r.u16()?;
    // Judged by the activation form's checks (check_ak_public and the
    // identity checks); the earlier forms only name them via the certify.
    let attributes = r.u32()?;
    let auth_policy = r.tpm2b()?.to_vec();
    let symmetric = r.u16()?;
    if symmetric != ALG_NULL {
        // A signing key carries no symmetric parameters; anything else is a
        // storage-key shape this parser does not model.
        return Err(Error::BadAttestation(
            "TPMT_PUBLIC carries symmetric parameters: not a signing key".into(),
        ));
    }
    let scheme = r.u16()?;
    if scheme != ALG_NULL {
        r.u16()?; // the scheme's hash algorithm
    }
    let curve = r.u16()?;
    let kdf = r.u16()?;
    if kdf != ALG_NULL {
        return Err(Error::BadAttestation(
            "TPMT_PUBLIC carries a KDF: not a signing key".into(),
        ));
    }
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    if r.remaining() != 0 {
        return Err(Error::BadAttestation(
            "trailing bytes after TPMT_PUBLIC".into(),
        ));
    }
    let key = match (scheme, curve) {
        (ALG_EDDSA, ECC_CURVE_25519) => {
            let raw: [u8; 32] = x.try_into().map_err(|_| {
                Error::BadAttestation("ed25519 TPMT_PUBLIC point is not 32 bytes".into())
            })?;
            TpmPublicKey::Ed25519(raw)
        }
        (ALG_ECDSA, ECC_NIST_P256) => {
            if x.len() > 32 || y.len() > 32 {
                return Err(Error::BadAttestation(
                    "P-256 TPMT_PUBLIC coordinate longer than 32 bytes".into(),
                ));
            }
            // Fixed-width coordinates: a TPM may in principle emit short
            // ones, the curve check downstream needs exactly 32 + 32.
            let mut point = vec![0x04];
            point.extend_from_slice(&[0u8; 32][..32 - x.len()]);
            point.extend_from_slice(x);
            point.extend_from_slice(&[0u8; 32][..32 - y.len()]);
            point.extend_from_slice(y);
            TpmPublicKey::EcdsaP256(point)
        }
        (s, c) => {
            return Err(Error::BadAttestation(format!(
                "unsupported TPMT_PUBLIC scheme/curve 0x{s:04X}/0x{c:04X}"
            )))
        }
    };
    Ok(TpmtPublic {
        name_alg,
        attributes,
        auth_policy,
        key,
    })
}

/// What an RSA EK's `TPMT_PUBLIC` yields.
struct RsaEk {
    attributes: u32,
    auth_policy: Vec<u8>,
    modulus: Vec<u8>,
}

/// Parses an EK public area of the TCG default RSA-2048 shape (template L-1):
/// SHA-256 names, AES-128-CFB storage parameters, null scheme, 2048-bit key,
/// default exponent, 256-byte modulus. Anything else is refused, not adapted
/// to: the credential exchange is only implemented for this shape.
fn parse_rsa_ek(b: &[u8]) -> Result<RsaEk, Error> {
    let mut r = Reader::new(b);
    let refuse = |what: &str| {
        Err(Error::BadAttestation(format!(
            "EK public area: {what} (only the TCG RSA-2048 EK template L-1 is supported)"
        )))
    };
    if r.u16()? != ALG_RSA {
        return refuse("not an RSA key");
    }
    if r.u16()? != ALG_SHA256 {
        return refuse("name algorithm is not SHA-256");
    }
    let attributes = r.u32()?;
    let auth_policy = r.tpm2b()?.to_vec();
    if (r.u16()?, r.u16()?, r.u16()?) != (ALG_AES, 128, ALG_CFB) {
        return refuse("storage parameters are not AES-128-CFB");
    }
    if r.u16()? != ALG_NULL {
        return refuse("a restricted decryption key carries a null scheme");
    }
    if r.u16()? != 2048 {
        return refuse("key size is not 2048 bits");
    }
    let exponent = r.u32()?;
    if exponent != 0 && exponent != 65537 {
        return refuse("exponent is not the default 65537");
    }
    let modulus = r.tpm2b()?.to_vec();
    if modulus.len() != 256 {
        return refuse("modulus is not 256 bytes");
    }
    if r.remaining() != 0 {
        return refuse("trailing bytes");
    }
    Ok(RsaEk {
        attributes,
        auth_policy,
        modulus,
    })
}

/// The RSA public key an X.509 certificate certifies, as (modulus without
/// leading zeros, exponent). Walks `Certificate -> tbsCertificate ->
/// subjectPublicKeyInfo` and nothing more: the certificate's own signature
/// and chain are the out-of-band vendor-root check, never performed here.
fn certificate_rsa_key(der: &[u8]) -> Result<(Vec<u8>, u64), Error> {
    use crate::rfc3161::Der;
    const SEQ: u8 = 0x30;
    const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    let mut outer = Der::new(der);
    let cert = outer.expect(SEQ, "Certificate")?;
    outer.finish("Certificate")?;
    let mut cert = Der::new(cert);
    let mut tbs = Der::new(cert.expect(SEQ, "tbsCertificate")?);
    let (mut tag, _) = tbs.tlv()?;
    if tag == 0xA0 {
        tag = tbs.tlv()?.0; // [0] version, then the serial number
    }
    if tag != 0x02 {
        return Err(Error::BadDer("tbsCertificate: no serial number".into()));
    }
    for what in ["signature", "issuer", "validity", "subject"] {
        tbs.expect(SEQ, what)?;
    }
    let mut spki = Der::new(tbs.expect(SEQ, "subjectPublicKeyInfo")?);
    let mut alg = Der::new(spki.expect(SEQ, "algorithm")?);
    if alg.expect(0x06, "algorithm OID")? != OID_RSA_ENCRYPTION {
        return Err(Error::AttestationMismatch(
            "the EK certificate does not certify an RSA key".into(),
        ));
    }
    let bits = spki.expect(0x03, "subjectPublicKey")?;
    spki.finish("subjectPublicKeyInfo")?;
    let Some((&0, key)) = bits.split_first() else {
        return Err(Error::BadDer("subjectPublicKey: unused bits".into()));
    };
    let mut outer = Der::new(key);
    let mut rsa = Der::new(outer.expect(SEQ, "RSAPublicKey")?);
    outer.finish("RSAPublicKey")?;
    let mut modulus = rsa.expect(0x02, "modulus")?;
    while let Some((&0, rest)) = modulus.split_first() {
        modulus = rest;
    }
    let e = rsa.expect(0x02, "publicExponent")?;
    rsa.finish("RSAPublicKey")?;
    if e.is_empty() || e.len() > 8 {
        return Err(Error::BadDer("publicExponent out of range".into()));
    }
    let exponent = e.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
    Ok((modulus.to_vec(), exponent))
}

/// The aggregate the TPM quote reports: the hash of the selected PCR values
/// concatenated in index order. The verifier recomputes it from the
/// ops-signed expectations and compares.
fn expected_pcr_digest(pcrs: &[PcrExpectation]) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&PcrExpectation> = pcrs.iter().collect();
    sorted.sort_by_key(|p| p.index);
    let mut concat = Vec::new();
    for p in sorted {
        let raw = hex::decode(&p.digest).map_err(|_| Error::BadHex(p.digest.clone()))?;
        concat.extend_from_slice(&raw);
    }
    Ok(sha256(&concat).as_bytes().to_vec())
}

/// Splits `attest || sig`, verifies the AK signature over the attest bytes,
/// and parses the attest. The signature is always the trailing 64 bytes:
/// an ed25519 signature, or ECDSA-P256 `r || s` each 32 bytes.
fn verify_signed_attest(hexed: &str, ak: &AkPublic) -> Result<SignedStatement, Error> {
    let raw = hex::decode(hexed).map_err(|_| Error::BadHex(hexed.to_string()))?;
    if raw.len() < 64 {
        return Err(Error::BadAttestation(
            "attest blob shorter than a signature".into(),
        ));
    }
    let (attest, sig) = raw.split_at(raw.len() - 64);
    let sig: [u8; 64] = sig.try_into().expect("checked length");
    ak.verify(attest, &sig)?;
    parse_attest(attest)
}

/// Bounds-checked reader over a byte slice, no recursion, in the `rfc3161`
/// parser discipline: a hostile blob must not panic or spin.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(over)?;
        let slice = self.b.get(self.pos..end).ok_or_else(over)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    /// `TPM2B_*`: a u16 length prefix, then that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// Skips a `TPM2B_*` without copying.
    fn skip_tpm2b(&mut self) -> Result<(), Error> {
        self.tpm2b().map(|_| ())
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
}

fn over() -> Error {
    Error::BadAttestation("TPMS_ATTEST truncated".into())
}

/// Parses the TCG-standard `TPMS_ATTEST` subset: the fixed header, then the
/// quote- or certify-specific tail.
fn parse_attest(b: &[u8]) -> Result<SignedStatement, Error> {
    let mut r = Reader::new(b);
    if r.u32()? != TPM_GENERATED {
        return Err(Error::BadAttestation(
            "missing TPM_GENERATED magic: not a genuine attestation structure".into(),
        ));
    }
    let st = r.u16()?;
    r.skip_tpm2b()?; // qualifiedSigner (TPM2B_NAME)
    let extra_data = r.tpm2b()?.to_vec(); // extraData (TPM2B_DATA)
    r.take(17)?; // TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1)
    r.take(8)?; // firmwareVersion (u64)

    let body = match st {
        ST_ATTEST_CERTIFY => {
            let name = r.tpm2b()?.to_vec();
            r.skip_tpm2b()?; // qualifiedName
            Attested::Certify { name }
        }
        ST_ATTEST_QUOTE => {
            // TPML_PCR_SELECTION: count, then that many TPMS_PCR_SELECTION.
            // The selection is part of what the AK signed: it names WHICH
            // PCRs the digest covers, so it is surfaced for the caller to
            // match against the ops-expected indices. A digest alone would
            // verify against the same value sitting in a different PCR.
            let count = r.u32()?;
            let mut selected = Vec::new();
            for _ in 0..count {
                let alg = r.u16()?;
                let size_of_select = r.u8()? as usize;
                let bitmap = r.take(size_of_select)?;
                for (byte_idx, byte) in bitmap.iter().enumerate() {
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            selected.push((alg, (byte_idx * 8 + bit) as u32));
                        }
                    }
                }
            }
            let pcr_digest = r.tpm2b()?.to_vec();
            Attested::Quote {
                pcr_digest,
                selected,
            }
        }
        other => {
            return Err(Error::BadAttestation(format!(
                "unsupported TPMS_ATTEST type 0x{other:04X}"
            )))
        }
    };
    Ok(SignedStatement { extra_data, body })
}

#[cfg(test)]
pub mod testutil {
    //! Synthesizes AK-signed `TPMS_ATTEST` blobs, the way
    //! `rfc3161::testutil` forges TSA responses. `#[cfg(test)]`: a helper that
    //! mints attestations must never be reachable from shipped code.

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn header(st: u16, extra_data: &[u8]) -> Vec<u8> {
        let mut v = TPM_GENERATED.to_be_bytes().to_vec();
        v.extend_from_slice(&st.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner: empty
        v.extend_from_slice(&tpm2b(extra_data)); // extraData
        v.extend_from_slice(&[0u8; 17]); // clockInfo
        v.extend_from_slice(&[0u8; 8]); // firmwareVersion
        v
    }

    fn tpm2b(bytes: &[u8]) -> Vec<u8> {
        let mut v = (bytes.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(bytes);
        v
    }

    fn sign(ak: &SigningKey, attest: Vec<u8>) -> String {
        let sig = ak.sign(&attest).to_bytes();
        let mut out = attest;
        out.extend_from_slice(&sig);
        hex::encode(out)
    }

    /// A certify naming `identity`, signed by `ak`.
    pub fn certify(ak: &SigningKey, identity: &VerifyingKey) -> String {
        certify_naming(ak, &identity_name(identity))
    }

    /// A certify carrying an arbitrary Name, signed by `ak`.
    pub fn certify_naming(ak: &SigningKey, name: &[u8]) -> String {
        certify_qualified(ak, name, &[])
    }

    /// A certify carrying `name` and `extra_data`, signed by `ak`.
    pub fn certify_qualified(ak: &SigningKey, name: &[u8], extra_data: &[u8]) -> String {
        let mut a = header(ST_ATTEST_CERTIFY, extra_data);
        a.extend_from_slice(&tpm2b(name)); // name
        a.extend_from_slice(&tpm2b(&[])); // qualifiedName
        sign(ak, a)
    }

    /// The marshalled `TPMT_PUBLIC` of an ed25519 identity key, the shape an
    /// EdDSA-capable TPM emits: ECC object, EdDSA scheme, curve 25519, the
    /// raw key as the point's x coordinate.
    pub fn tpmt_public_ed25519(identity: &VerifyingKey) -> Vec<u8> {
        tpmt_public_ed25519_with(identity, 0x0004_0072, &[])
    }

    /// An ed25519 `TPMT_PUBLIC` with chosen attributes and authPolicy.
    pub fn tpmt_public_ed25519_with(key: &VerifyingKey, attributes: u32, policy: &[u8]) -> Vec<u8> {
        let mut v = ALG_ECC.to_be_bytes().to_vec();
        v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // nameAlg
        v.extend_from_slice(&attributes.to_be_bytes());
        v.extend_from_slice(&tpm2b(policy)); // authPolicy
        v.extend_from_slice(&ALG_NULL.to_be_bytes()); // symmetric
        v.extend_from_slice(&ALG_EDDSA.to_be_bytes()); // scheme
        v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // scheme hash
        v.extend_from_slice(&ECC_CURVE_25519.to_be_bytes()); // curve
        v.extend_from_slice(&ALG_NULL.to_be_bytes()); // kdf
        v.extend_from_slice(&tpm2b(key.as_bytes())); // unique.x
        v.extend_from_slice(&tpm2b(&[])); // unique.y
        v
    }

    /// The attributes a v4 enrollment gives each key.
    pub const AK_ATTRS: u32 = ATTR_FIXED_TPM
        | ATTR_FIXED_PARENT
        | ATTR_SENSITIVE_DATA_ORIGIN
        | ATTR_USER_WITH_AUTH
        | ATTR_RESTRICTED
        | ATTR_SIGN;
    pub const IDENTITY_ATTRS: u32 =
        ATTR_FIXED_TPM | ATTR_FIXED_PARENT | ATTR_SENSITIVE_DATA_ORIGIN | ATTR_SIGN;
    pub const EK_ATTRS: u32 = ATTR_FIXED_TPM
        | ATTR_FIXED_PARENT
        | ATTR_SENSITIVE_DATA_ORIGIN
        | ATTR_ADMIN_WITH_POLICY
        | ATTR_RESTRICTED
        | ATTR_DECRYPT;

    /// An RSA EK public area of template L-1's shape around `modulus`.
    pub fn tpmt_public_rsa_ek(modulus: &[u8; 256], attributes: u32, policy: &[u8]) -> Vec<u8> {
        let mut v = ALG_RSA.to_be_bytes().to_vec();
        v.extend_from_slice(&ALG_SHA256.to_be_bytes());
        v.extend_from_slice(&attributes.to_be_bytes());
        v.extend_from_slice(&tpm2b(policy));
        v.extend_from_slice(&ALG_AES.to_be_bytes());
        v.extend_from_slice(&128u16.to_be_bytes());
        v.extend_from_slice(&ALG_CFB.to_be_bytes());
        v.extend_from_slice(&ALG_NULL.to_be_bytes()); // scheme
        v.extend_from_slice(&2048u16.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // exponent: default
        v.extend_from_slice(&tpm2b(modulus));
        v
    }

    /// The Name a real TPM computes for a public area.
    pub fn name_of(tpmt_public: &[u8]) -> Vec<u8> {
        tpm_name(tpmt_public)
    }

    /// A quote reporting `pcrs`, signed by `ak`.
    pub fn quote(ak: &SigningKey, pcrs: &[PcrExpectation]) -> String {
        quote_qualified(ak, pcrs, &[])
    }

    /// A quote reporting `pcrs` and carrying `extra_data`, signed by `ak`.
    pub fn quote_qualified(ak: &SigningKey, pcrs: &[PcrExpectation], extra_data: &[u8]) -> String {
        let mut a = header(ST_ATTEST_QUOTE, extra_data);
        // One TPML_PCR_SELECTION entry, SHA-256 bank, 3-byte bitmap (24
        // PCRs) selecting exactly the quoted indices, the way a real TPM
        // echoes the selection it was asked to quote.
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&ALG_SHA256.to_be_bytes());
        a.push(3);
        let mut bitmap = [0u8; 3];
        for p in pcrs {
            bitmap[(p.index / 8) as usize] |= 1 << (p.index % 8);
        }
        a.extend_from_slice(&bitmap);
        let digest = expected_pcr_digest(pcrs).unwrap();
        a.extend_from_slice(&tpm2b(&digest));
        sign(ak, a)
    }

    /// A complete, valid attestation for `identity`, signed by a fresh AK, in
    /// the legacy form with no `TPMT_PUBLIC` carried.
    pub fn attestation(
        key_id: &str,
        identity: &VerifyingKey,
        ak: &SigningKey,
        pcrs: Vec<PcrExpectation>,
    ) -> KeyAttestation {
        KeyAttestation {
            key_id: key_id.to_string(),
            ak_pub: hex::encode(ak.verifying_key().to_bytes()),
            ek_cert: hex::encode(b"demo-ek-cert"),
            certify: certify(ak, identity),
            quote: quote(ak, &pcrs),
            expected_pcrs: pcrs,
            identity_pub: None,
            activation: None,
        }
    }

    /// The real-TPM form: carries the identity key's `TPMT_PUBLIC`, and the
    /// certify names `alg || H(TPMT_PUBLIC)` as real hardware does.
    pub fn attestation_with_public(
        key_id: &str,
        identity: &VerifyingKey,
        ak: &SigningKey,
        pcrs: Vec<PcrExpectation>,
    ) -> KeyAttestation {
        let tpmt = tpmt_public_ed25519(identity);
        let mut att = attestation(key_id, identity, ak, pcrs);
        att.certify = certify_naming(ak, &name_of(&tpmt));
        att.identity_pub = Some(hex::encode(tpmt));
        att
    }

    /// The activation form (v4) as a correct enrollment produces it: an AK
    /// and an EK of the required shapes, an identity key under the PCR
    /// policy, both statements qualified by the activation. The EK modulus
    /// is filler: the verifier never computes with it, it hashes and
    /// compares it.
    pub fn attestation_activated(
        key_id: &str,
        identity: &VerifyingKey,
        ak: &SigningKey,
        pcrs: Vec<PcrExpectation>,
    ) -> KeyAttestation {
        let policy = pcr_policy_digest(&pcrs).unwrap();
        let tpmt = tpmt_public_ed25519_with(identity, IDENTITY_ATTRS, &policy);
        let ak_public = tpmt_public_ed25519_with(&ak.verifying_key(), AK_ATTRS, &[]);
        let ek_pub = tpmt_public_rsa_ek(&[0xC5; 256], EK_ATTRS, &ek_policy());
        let (nonce, secret) = ([0x11u8; 32], [0x22u8; 32]);
        let q = activation_qualifier(&nonce, &secret);
        let mut att = attestation(key_id, identity, ak, pcrs.clone());
        att.ek_cert = String::new();
        att.certify = certify_qualified(ak, &name_of(&tpmt), &q);
        att.quote = quote_qualified(ak, &pcrs, &q);
        att.identity_pub = Some(hex::encode(tpmt));
        att.activation = Some(Activation {
            ek_pub: hex::encode(ek_pub),
            ak_public: hex::encode(ak_public),
            nonce: hex::encode(nonce),
            secret: hex::encode(secret),
        });
        att
    }

    /// Re-signs both statements of an activation-form attestation after a
    /// test changed its public areas or qualifier, so the AK signature is
    /// never the reason a mutation is refused.
    pub fn resign_activated(att: &mut KeyAttestation, ak: &SigningKey, extra_data: &[u8]) {
        let tpmt = hex::decode(att.identity_pub.as_ref().unwrap()).unwrap();
        att.certify = certify_qualified(ak, &name_of(&tpmt), extra_data);
        att.quote = quote_qualified(ak, &att.expected_pcrs, extra_data);
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::checkpoint::KeyRole;
    use ed25519_dalek::SigningKey;

    fn pcr(index: u32, seed: u8) -> PcrExpectation {
        PcrExpectation {
            index,
            digest: hex::encode(sha256(&[seed]).as_bytes()),
        }
    }

    fn identity_entry(key: &SigningKey) -> PublicKeyEntry {
        PublicKeyEntry {
            key_id: "id-1".into(),
            algo: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: KeyRole::Origin,
        }
    }

    #[test]
    fn a_valid_attestation_verifies() {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let pcrs = vec![pcr(0, 10), pcr(7, 11)];
        let att = attestation("id-1", &identity.verifying_key(), &ak, pcrs);
        assert!(verify_attestation(&identity_entry(&identity), &att).is_ok());
    }

    #[test]
    fn a_quote_over_a_different_pcr_with_the_same_value_is_rejected() {
        // The digest matches, same value, wrong register. With resettable
        // PCRs (16, 23) that value is reproducible by anyone with TPM
        // access, so the *selection* the AK signed must name the enrolled
        // index, not merely hash to the enrolled value.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let mut att =
            attestation("id-1", &identity.verifying_key(), &ak, vec![pcr(16, 10)]);
        att.expected_pcrs = vec![pcr(23, 10)];
        let err = verify_attestation(&identity_entry(&identity), &att).unwrap_err();
        assert!(
            err.to_string().contains("signed over PCRs"),
            "got: {err}"
        );
    }

    #[test]
    fn a_certify_for_another_key_is_rejected() {
        // The attacker holds a genuine TPM, but its identity key is not the
        // one enrolled: the certify names the wrong key.
        let enrolled = SigningKey::from_bytes(&[1u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[9u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let pcrs = vec![pcr(0, 10)];
        let mut att = attestation("id-1", &attacker_key.verifying_key(), &ak, pcrs);
        att.key_id = "id-1".into();
        let err = verify_attestation(&identity_entry(&enrolled), &att).unwrap_err();
        assert!(matches!(err, Error::AttestationMismatch(_)));
    }

    #[test]
    fn a_forged_ak_signature_is_rejected() {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let mut att = attestation("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        // Corrupt one byte of the quote signature region.
        let mut bytes = hex::decode(&att.quote).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0x01;
        att.quote = hex::encode(bytes);
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::BadAttestation(_))
        ));
    }

    #[test]
    fn a_quote_over_the_wrong_pcrs_is_rejected() {
        // The running binary measures differently than the ops policy: the
        // quote is honestly signed, but its PCR digest does not match.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let good = vec![pcr(0, 10)];
        let mut att = attestation("id-1", &identity.verifying_key(), &ak, good);
        // Swap the expected policy to a different value; the quote still
        // reports the original, so they disagree.
        att.expected_pcrs = vec![pcr(0, 99)];
        let err = verify_attestation(&identity_entry(&identity), &att).unwrap_err();
        assert!(matches!(err, Error::AttestationMismatch(_)));
    }

    #[test]
    fn a_truncated_attest_blob_does_not_panic() {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        // Keep a valid signature over a truncated attest: force the parser to
        // walk off the end.
        let raw = hex::decode(&att.quote).unwrap();
        let attest = &raw[..raw.len() - 64];
        let short = &attest[..10];
        let sig = ak_sign(&ak, short);
        let mut blob = short.to_vec();
        blob.extend_from_slice(&sig);
        let mut bad = att.clone();
        bad.quote = hex::encode(blob);
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &bad),
            Err(Error::BadAttestation(_))
        ));
    }

    fn ak_sign(ak: &SigningKey, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        ak.sign(msg).to_bytes()
    }

    #[test]
    fn an_empty_pcr_set_proves_nothing() {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation("id-1", &identity.verifying_key(), &ak, vec![]);
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::AttestationMismatch(_))
        ));
    }

    #[test]
    fn the_tpmt_public_form_verifies() {
        // The real-TPM binding: the certify names alg || H(TPMT_PUBLIC), the
        // attestation carries the public area, the verifier closes the loop.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation_with_public("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        assert!(verify_attestation(&identity_entry(&identity), &att).is_ok());
    }

    #[test]
    fn a_tpmt_public_of_another_key_is_rejected() {
        // The certify honestly names the key inside the carried TPMT_PUBLIC:
        // but that key is not the enrolled one. The substitution attack the
        // pubkey-equality check exists for.
        let enrolled = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation_with_public("id-1", &attacker.verifying_key(), &ak, vec![pcr(0, 10)]);
        let err = verify_attestation(&identity_entry(&enrolled), &att).unwrap_err();
        assert!(matches!(err, Error::AttestationMismatch(_)));
    }

    #[test]
    fn a_swapped_tpmt_public_breaks_the_name() {
        // The carried TPMT_PUBLIC holds the right key, but the certify was
        // made over a different public area: the recomputed Name disagrees.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let mut att =
            attestation_with_public("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        // Flip one bit inside the carried public area (an attribute byte, so
        // the extracted key still matches the entry).
        let mut tp = hex::decode(att.identity_pub.as_ref().unwrap()).unwrap();
        tp[5] ^= 0x01;
        att.identity_pub = Some(hex::encode(tp));
        let err = verify_attestation(&identity_entry(&identity), &att).unwrap_err();
        assert!(matches!(err, Error::AttestationMismatch(_)));
    }

    #[test]
    fn a_legacy_named_certify_cannot_claim_the_tpmt_public_form() {
        // certify names the legacy raw-key form while the attestation
        // carries a TPMT_PUBLIC: the two binding forms must not cross.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let mut att =
            attestation_with_public("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        att.certify = certify(&ak, &identity.verifying_key());
        let err = verify_attestation(&identity_entry(&identity), &att).unwrap_err();
        assert!(matches!(err, Error::AttestationMismatch(_)));
    }

    #[test]
    fn a_malformed_tpmt_public_does_not_panic() {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let good =
            attestation_with_public("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        let tp = hex::decode(good.identity_pub.as_ref().unwrap()).unwrap();
        // Truncations at every length, trailing garbage, and junk: every
        // shape must be a clean refusal.
        for cut in 0..tp.len() {
            let mut att = good.clone();
            att.identity_pub = Some(hex::encode(&tp[..cut]));
            assert!(
                verify_attestation(&identity_entry(&identity), &att).is_err(),
                "truncation at {cut} was accepted"
            );
        }
        let mut trailing = tp.clone();
        trailing.push(0);
        let mut att = good.clone();
        att.identity_pub = Some(hex::encode(trailing));
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::BadAttestation(_))
        ));
        let mut att = good;
        att.identity_pub = Some("zz".into());
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::BadHex(_))
        ));
    }

    #[test]
    fn attestation_json_without_identity_pub_still_parses() {
        // The serialized form of a pre-hardware attestation has no
        // identity_pub field: it must deserialize and verify as before.
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation("id-1", &identity.verifying_key(), &ak, vec![pcr(0, 10)]);
        let json = serde_json::to_string(&att).unwrap();
        assert!(
            !json.contains("identity_pub"),
            "absent field must not serialize"
        );
        let back: KeyAttestation = serde_json::from_str(&json).unwrap();
        assert!(verify_attestation(&identity_entry(&identity), &back).is_ok());
    }

    // --- v4: the activation form ------------------------------------------

    fn activated() -> (SigningKey, SigningKey, KeyAttestation) {
        let identity = SigningKey::from_bytes(&[1u8; 32]);
        let ak = SigningKey::from_bytes(&[2u8; 32]);
        let att = attestation_activated("id-1", &identity.verifying_key(), &ak, vec![pcr(16, 10)]);
        (identity, ak, att)
    }

    fn expect_mismatch(identity: &SigningKey, att: &KeyAttestation, needle: &str) {
        match verify_attestation(&identity_entry(identity), att) {
            Err(Error::AttestationMismatch(m)) => assert!(m.contains(needle), "got: {m}"),
            other => panic!("expected a mismatch naming {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn the_ek_policy_is_the_tcg_published_value() {
        // TCG EK Credential Profile 2.0, B.3.3: PolicySecret(TPM_RH_ENDORSEMENT).
        assert_eq!(
            hex::encode(ek_policy()),
            "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"
        );
    }

    #[test]
    fn an_activated_attestation_verifies() {
        let (identity, _ak, att) = activated();
        verify_attestation(&identity_entry(&identity), &att).unwrap();
        // And survives its JSON round trip, the form the bundle carries.
        let back: KeyAttestation = serde_json::from_str(&serde_json::to_string(&att).unwrap()).unwrap();
        verify_attestation(&identity_entry(&identity), &back).unwrap();
    }

    #[test]
    fn statements_without_the_qualifier_are_refused() {
        // The missing-nonce case: certify and quote carry no extraData, as
        // every pre-v4 enrollment produced them. Replaying one under a new
        // activation record must not pass.
        let (identity, ak, mut att) = activated();
        resign_activated(&mut att, &ak, &[]);
        expect_mismatch(&identity, &att, "not qualified");
    }

    #[test]
    fn statements_for_another_challenge_are_refused() {
        // Honestly qualified, but for a different nonce: an enrollment
        // answered once and replayed against a later challenge.
        let (identity, ak, mut att) = activated();
        let stale = activation_qualifier(&[0x33; 32], &[0x22; 32]);
        resign_activated(&mut att, &ak, &stale);
        expect_mismatch(&identity, &att, "not qualified");
        // Same statements, the recorded nonce swapped instead.
        let (identity, _ak, mut att) = activated();
        att.activation.as_mut().unwrap().nonce = hex::encode([0x33u8; 32]);
        expect_mismatch(&identity, &att, "not qualified");
    }

    #[test]
    fn a_short_nonce_or_secret_is_refused() {
        let (identity, _ak, mut att) = activated();
        att.activation.as_mut().unwrap().nonce = hex::encode([0x11u8; 8]);
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::BadAttestation(_))
        ));
    }

    /// Rebuilds the identity public area with other attributes or policy and
    /// re-signs, so the certify honestly names it and only the property
    /// under test is wrong.
    fn with_identity(att: &mut KeyAttestation, ak: &SigningKey, identity: &SigningKey, attrs: u32, policy: &[u8]) {
        let tpmt = tpmt_public_ed25519_with(&identity.verifying_key(), attrs, policy);
        att.identity_pub = Some(hex::encode(tpmt));
        let act = att.activation.clone().unwrap();
        let q = activation_qualifier(&hex::decode(act.nonce).unwrap(), &hex::decode(act.secret).unwrap());
        resign_activated(att, ak, &q);
    }

    #[test]
    fn an_identity_key_without_the_pcr_policy_is_refused() {
        let (identity, ak, mut att) = activated();
        with_identity(&mut att, &ak, &identity, IDENTITY_ATTRS, &[]);
        expect_mismatch(&identity, &att, "authPolicy");
        // A PCR policy, but over other values than the enrolled ones.
        let other = pcr_policy_digest(&[pcr(16, 99)]).unwrap();
        let (identity, ak, mut att) = activated();
        with_identity(&mut att, &ak, &identity, IDENTITY_ATTRS, &other);
        expect_mismatch(&identity, &att, "authPolicy");
    }

    #[test]
    fn identity_key_attribute_violations_are_refused() {
        let policy = pcr_policy_digest(&[pcr(16, 10)]).unwrap();
        for (attrs, needle) in [
            (IDENTITY_ATTRS | ATTR_USER_WITH_AUTH, "forbidden"),
            (IDENTITY_ATTRS & !ATTR_FIXED_TPM, "lacks"),
            (IDENTITY_ATTRS & !ATTR_FIXED_PARENT, "lacks"),
            (IDENTITY_ATTRS & !ATTR_SENSITIVE_DATA_ORIGIN, "lacks"),
            (IDENTITY_ATTRS | ATTR_RESTRICTED, "forbidden"),
        ] {
            let (identity, ak, mut att) = activated();
            with_identity(&mut att, &ak, &identity, attrs, &policy);
            expect_mismatch(&identity, &att, needle);
        }
    }

    #[test]
    fn ak_attribute_violations_are_refused() {
        for attrs in [
            AK_ATTRS & !ATTR_RESTRICTED,
            AK_ATTRS & !ATTR_FIXED_TPM,
            AK_ATTRS & !ATTR_SENSITIVE_DATA_ORIGIN,
            AK_ATTRS | ATTR_DECRYPT,
        ] {
            let (identity, ak, mut att) = activated();
            att.activation.as_mut().unwrap().ak_public =
                hex::encode(tpmt_public_ed25519_with(&ak.verifying_key(), attrs, &[]));
            expect_mismatch(&identity, &att, "the AK");
        }
        // An AK public area holding another key than the one that signed.
        let (identity, _ak, mut att) = activated();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        att.activation.as_mut().unwrap().ak_public =
            hex::encode(tpmt_public_ed25519_with(&other.verifying_key(), AK_ATTRS, &[]));
        expect_mismatch(&identity, &att, "different key than ak_pub");
    }

    #[test]
    fn ek_shape_violations_are_refused() {
        // An unrestricted EK would decrypt the credential seed for anyone.
        let (identity, _ak, mut att) = activated();
        att.activation.as_mut().unwrap().ek_pub =
            hex::encode(tpmt_public_rsa_ek(&[0xC5; 256], EK_ATTRS & !ATTR_RESTRICTED, &ek_policy()));
        expect_mismatch(&identity, &att, "the EK lacks");
        // An EK usable without the endorsement hierarchy's policy.
        let (identity, _ak, mut att) = activated();
        att.activation.as_mut().unwrap().ek_pub =
            hex::encode(tpmt_public_rsa_ek(&[0xC5; 256], EK_ATTRS, &[]));
        expect_mismatch(&identity, &att, "EK policy");
        // Not the supported template shape at all: an ECC key in its place.
        let (identity, ak, mut att) = activated();
        att.activation.as_mut().unwrap().ek_pub =
            hex::encode(tpmt_public_ed25519_with(&ak.verifying_key(), EK_ATTRS, &ek_policy()));
        assert!(matches!(
            verify_attestation(&identity_entry(&identity), &att),
            Err(Error::BadAttestation(_))
        ));
    }

    /// A minimal X.509 shape around an RSA key: just enough structure for
    /// the SPKI walk. Signature and names are filler, as the verifier never
    /// judges them (the vendor chain is out of band).
    fn ek_certificate(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        use crate::rfc3161::testutil::tlv;
        let mut n = vec![0u8];
        n.extend_from_slice(modulus);
        let rsa = tlv(0x30, &[tlv(0x02, &n), tlv(0x02, exponent)].concat());
        let mut bits = vec![0u8];
        bits.extend_from_slice(&rsa);
        let alg = tlv(
            0x30,
            &[tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]), tlv(0x05, &[])].concat(),
        );
        let spki = tlv(0x30, &[alg.clone(), tlv(0x03, &bits)].concat());
        let tbs = tlv(
            0x30,
            &[
                tlv(0xA0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                alg.clone(),
                tlv(0x30, &[]),
                tlv(0x30, &[]),
                tlv(0x30, &[]),
                spki,
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, alg, tlv(0x03, &[0, 0xAA])].concat())
    }

    #[test]
    fn the_ek_certificate_must_certify_the_recorded_ek() {
        let (identity, _ak, mut att) = activated();
        att.ek_cert = hex::encode(ek_certificate(&[0xC5; 256], &[1, 0, 1]));
        verify_attestation(&identity_entry(&identity), &att).unwrap();

        // A genuine certificate for another EK: the pairing the activation
        // form exists to refuse.
        att.ek_cert = hex::encode(ek_certificate(&[0xC6; 256], &[1, 0, 1]));
        expect_mismatch(&identity, &att, "EK certificate");
        att.ek_cert = hex::encode(ek_certificate(&[0xC5; 256], &[3]));
        expect_mismatch(&identity, &att, "EK certificate");

        // Truncated or garbage certificates are refusals, never panics.
        let good = ek_certificate(&[0xC5; 256], &[1, 0, 1]);
        for cut in 0..good.len() {
            att.ek_cert = hex::encode(&good[..cut]);
            if cut == 0 {
                continue; // empty: no certificate, the out-of-band caveat
            }
            assert!(verify_attestation(&identity_entry(&identity), &att).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn the_activation_form_requires_the_identity_public_area() {
        let (identity, _ak, mut att) = activated();
        att.identity_pub = None;
        assert!(verify_attestation(&identity_entry(&identity), &att).is_err());
    }
}

#[cfg(test)]
mod swtpm_fixture_tests {
    //! Real TPM output, captured once from `obsign-tpm-enroll` against a swtpm
    //! (libtpms 0.10) and embedded, so the ECDSA-P256 path and the real Name
    //! binding are exercised on every `cargo test`, with no TPM anywhere near
    //! the test run. The gated integration test in `obsign-tpm-enroll`
    //! regenerates this material live.

    use super::*;
    use crate::checkpoint::KeyRole;

    /// Emitted by `obsign-tpm-enroll` pointed at a fresh swtpm: PCR 16
    /// extended with sha256("gateway-binary"), then certify + quote.
    const FIXTURE_ATTESTATION: &str = include_str!("../tests/fixtures/swtpm-attestation.json");
    const FIXTURE_ENTRY: &str = include_str!("../tests/fixtures/swtpm-identity-entry.json");

    fn fixture() -> (PublicKeyEntry, KeyAttestation) {
        let entry: PublicKeyEntry = serde_json::from_str(FIXTURE_ENTRY).unwrap();
        assert_eq!(
            entry.role,
            KeyRole::Origin,
            "fixture entry is an origin key"
        );
        (entry, serde_json::from_str(FIXTURE_ATTESTATION).unwrap())
    }

    #[test]
    fn real_swtpm_output_verifies() {
        let (entry, att) = fixture();
        verify_attestation(&entry, &att).unwrap();
    }

    #[test]
    fn real_swtpm_output_rejects_tampering() {
        let (entry, good) = fixture();

        // Corrupt one byte of the quote's ECDSA signature.
        let mut att = good.clone();
        let mut raw = hex::decode(&att.quote).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0x01;
        att.quote = hex::encode(raw);
        assert!(matches!(
            verify_attestation(&entry, &att),
            Err(Error::BadAttestation(_))
        ));

        // Claim a different PCR value than the TPM measured.
        let mut att = good.clone();
        att.expected_pcrs[0].digest = hex::encode([0u8; 32]);
        assert!(matches!(
            verify_attestation(&entry, &att),
            Err(Error::AttestationMismatch(_))
        ));

        // Enroll a different key than the TPM certified.
        let mut entry2 = entry;
        let mut key = hex::decode(&entry2.public_key).unwrap();
        key[10] ^= 0x01;
        entry2.public_key = hex::encode(key);
        assert!(matches!(
            verify_attestation(&entry2, &good),
            Err(Error::AttestationMismatch(_))
        ));
    }
}
