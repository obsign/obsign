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
//! What is proven where — the [`crate::rfc3161`] anchor stance exactly:
//!
//! * **offline** (here): the AK signed the quote and the certify; the certify
//!   binds *this* identity key; the quote's PCR digest matches the
//!   expectations the ops key signed. This proves the identity key is bound
//!   to a TPM reporting these measurements.
//! * **out of band** (named, not performed here): the EK certificate chains
//!   to the TPM vendor root, proving the AK is genuine silicon and not a
//!   software fake. An air-gapped verifier has no vendor PKI; the report says
//!   so (`attestation_not_rooted`), it does not pretend otherwise.
//!
//! Interop note: the AK signs Ed25519, like every key in this system; the
//! `TPMS_ATTEST` wire format below is the TCG-standard subset the checks
//! need, bounds-checked in the DER discipline. It has been exercised against
//! the `#[cfg(test)]` synthesizer, **not** against a real TPM in this tree —
//! real-hardware interop is the gated, deferred integration point.

use crate::checkpoint::PublicKeyEntry;
use crate::error::Error;
use crate::hash::sha256;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// `TPM_GENERATED_VALUE` — the magic prefixing every genuine `TPMS_ATTEST`,
/// so a caller cannot pass an arbitrary blob off as an attestation.
const TPM_GENERATED: u32 = 0xFF54_4347; // "\xFFTCG"
const ST_ATTEST_CERTIFY: u16 = 0x8017;
const ST_ATTEST_QUOTE: u16 = 0x8018;
/// `TPM_ALG_SHA256`, the name algorithm this verifier supports.
const ALG_SHA256: u16 = 0x000B;

/// One PCR the quote must report, with the value the ops key expects it to
/// hold. The gateway-binary PCR is the hash of the released binary — chained
/// to the release manifest — so a running gateway proves it *is* that binary.
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
    /// AK public key (ed25519, hex): signs the quote and the certify.
    pub ak_pub: String,
    /// EK certificate (DER, hex). Chains to the TPM vendor root — validated
    /// out of band, never here.
    pub ek_cert: String,
    /// `TPM2_Certify` output binding the identity key to the AK: the
    /// marshalled `TPMS_ATTEST` followed by the AK's 64-byte signature, hex.
    pub certify: String,
    /// `TPM2_Quote` over the PCRs: marshalled `TPMS_ATTEST` followed by the
    /// AK's 64-byte signature, hex.
    pub quote: String,
    /// The PCR values the quote must report, ops-signed via the bundle.
    pub expected_pcrs: Vec<PcrExpectation>,
}

/// The TPM Name of an identity key, as the certify carries it.
///
/// A real TPM Name is `alg || H(TPMT_PUBLIC)`; this verifier binds by
/// `alg || H(raw ed25519 public key)`, sufficient to prove the certify names
/// *this* key and no other. (The full-`TPMT_PUBLIC` form is the real-hardware
/// interop point, gated and unverified here.)
pub fn identity_name(key: &VerifyingKey) -> Vec<u8> {
    let mut out = ALG_SHA256.to_be_bytes().to_vec();
    out.extend_from_slice(sha256(key.as_bytes()).as_bytes());
    out
}

/// What a parsed `TPMS_ATTEST` yields, for the two statement types used.
enum Attested {
    Quote { pcr_digest: Vec<u8> },
    Certify { name: Vec<u8> },
}

/// Verifies one identity key's attestation, offline and structurally.
///
/// `entry` is the identity key as it appears in the deployment bundle. On
/// success the caller may trust that this key is bound to a TPM reporting the
/// expected measurements — subject to the out-of-band EK-root check the
/// caller must still surface.
pub fn verify_attestation(entry: &PublicKeyEntry, att: &KeyAttestation) -> Result<(), Error> {
    let ak = parse_ed25519(&att.ak_pub)?;
    let identity = entry.to_verifying_key()?;

    // The certify must bind THIS identity key.
    let certify = verify_signed_attest(&att.certify, &ak)?;
    match certify {
        Attested::Certify { name } => {
            if name != identity_name(&identity) {
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

    // The quote must report the ops-expected PCR values.
    let quote = verify_signed_attest(&att.quote, &ak)?;
    match quote {
        Attested::Quote { pcr_digest } => {
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
/// and parses the attest.
fn verify_signed_attest(hexed: &str, ak: &VerifyingKey) -> Result<Attested, Error> {
    let raw = hex::decode(hexed).map_err(|_| Error::BadHex(hexed.to_string()))?;
    if raw.len() < 64 {
        return Err(Error::BadAttestation("attest blob shorter than a signature".into()));
    }
    let (attest, sig) = raw.split_at(raw.len() - 64);
    let sig: [u8; 64] = sig.try_into().expect("checked length");
    ak.verify(attest, &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadAttestation("AK signature does not verify".into()))?;
    parse_attest(attest)
}

fn parse_ed25519(hexed: &str) -> Result<VerifyingKey, Error> {
    let raw = hex::decode(hexed).map_err(|_| Error::BadHex(hexed.to_string()))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| Error::BadKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::BadKey(hexed.to_string()))
}

/// Bounds-checked reader over a byte slice, no recursion — the `rfc3161`
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
            let count = r.u32()?;
            for _ in 0..count {
                r.u16()?; // hash alg
                let size_of_select = r.u8()? as usize;
                r.take(size_of_select)?; // pcrSelect bitmap
            }
            let pcr_digest = r.tpm2b()?.to_vec();
            Ok(Attested::Quote { pcr_digest })
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
        let mut a = header(ST_ATTEST_CERTIFY);
        a.extend_from_slice(&tpm2b(&identity_name(identity))); // name
        a.extend_from_slice(&tpm2b(&[])); // qualifiedName
        sign(ak, a)
    }

    /// A quote reporting `pcrs`, signed by `ak`.
    pub fn quote(ak: &SigningKey, pcrs: &[PcrExpectation]) -> String {
        let mut a = header(ST_ATTEST_QUOTE);
        // One TPML_PCR_SELECTION entry, SHA-256 bank, 3-byte bitmap (24 PCRs).
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&ALG_SHA256.to_be_bytes());
        a.push(3);
        a.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let digest = expected_pcr_digest(pcrs).unwrap();
        a.extend_from_slice(&tpm2b(&digest));
        sign(ak, a)
    }

    /// A complete, valid attestation for `identity`, signed by a fresh AK.
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
        }
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
}
