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

    // The certify must bind THIS identity key.
    let certify = verify_signed_attest(&att.certify, &ak)?;
    match certify {
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
    match quote {
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
    let mut name = parsed.name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(sha256(&tp).as_bytes());
    Ok(name)
}

/// What a `TPMT_PUBLIC` yields: its name algorithm and the raw key inside.
struct TpmtPublic {
    name_alg: u16,
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
    r.u32()?; // objectAttributes: named by the certify, not re-judged here
    r.skip_tpm2b()?; // authPolicy
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
    Ok(TpmtPublic { name_alg, key })
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
fn verify_signed_attest(hexed: &str, ak: &AkPublic) -> Result<Attested, Error> {
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
fn parse_attest(b: &[u8]) -> Result<Attested, Error> {
    let mut r = Reader::new(b);
    if r.u32()? != TPM_GENERATED {
        return Err(Error::BadAttestation(
            "missing TPM_GENERATED magic: not a genuine attestation structure".into(),
        ));
    }
    let st = r.u16()?;
    r.skip_tpm2b()?; // qualifiedSigner (TPM2B_NAME)
    r.skip_tpm2b()?; // extraData (TPM2B_DATA)
    r.take(17)?; // TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1)
    r.take(8)?; // firmwareVersion (u64)

    match st {
        ST_ATTEST_CERTIFY => {
            let name = r.tpm2b()?.to_vec();
            r.skip_tpm2b()?; // qualifiedName
            Ok(Attested::Certify { name })
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
            Ok(Attested::Quote {
                pcr_digest,
                selected,
            })
        }
        other => Err(Error::BadAttestation(format!(
            "unsupported TPMS_ATTEST type 0x{other:04X}"
        ))),
    }
}

#[cfg(test)]
pub mod testutil {
    //! Synthesizes AK-signed `TPMS_ATTEST` blobs, the way
    //! `rfc3161::testutil` forges TSA responses. `#[cfg(test)]`: a helper that
    //! mints attestations must never be reachable from shipped code.

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn header(st: u16) -> Vec<u8> {
        let mut v = TPM_GENERATED.to_be_bytes().to_vec();
        v.extend_from_slice(&st.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner: empty
        v.extend_from_slice(&0u16.to_be_bytes()); // extraData: empty
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
        let mut a = header(ST_ATTEST_CERTIFY);
        a.extend_from_slice(&tpm2b(name)); // name
        a.extend_from_slice(&tpm2b(&[])); // qualifiedName
        sign(ak, a)
    }

    /// The marshalled `TPMT_PUBLIC` of an ed25519 identity key, the shape an
    /// EdDSA-capable TPM emits: ECC object, EdDSA scheme, curve 25519, the
    /// raw key as the point's x coordinate.
    pub fn tpmt_public_ed25519(identity: &VerifyingKey) -> Vec<u8> {
        let mut v = ALG_ECC.to_be_bytes().to_vec();
        v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // nameAlg
        v.extend_from_slice(&0x0004_0072u32.to_be_bytes()); // attributes: signing key
        v.extend_from_slice(&tpm2b(&[])); // authPolicy
        v.extend_from_slice(&ALG_NULL.to_be_bytes()); // symmetric
        v.extend_from_slice(&ALG_EDDSA.to_be_bytes()); // scheme
        v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // scheme hash
        v.extend_from_slice(&ECC_CURVE_25519.to_be_bytes()); // curve
        v.extend_from_slice(&ALG_NULL.to_be_bytes()); // kdf
        v.extend_from_slice(&tpm2b(identity.as_bytes())); // unique.x
        v.extend_from_slice(&tpm2b(&[])); // unique.y
        v
    }

    /// The Name a real TPM computes for a public area.
    pub fn name_of(tpmt_public: &[u8]) -> Vec<u8> {
        let mut name = ALG_SHA256.to_be_bytes().to_vec();
        name.extend_from_slice(sha256(tpmt_public).as_bytes());
        name
    }

    /// A quote reporting `pcrs`, signed by `ak`.
    pub fn quote(ak: &SigningKey, pcrs: &[PcrExpectation]) -> String {
        let mut a = header(ST_ATTEST_QUOTE);
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
