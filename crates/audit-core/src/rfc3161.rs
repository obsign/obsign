//! Structural reader for RFC 3161 timestamp responses.
//!
//! A checkpoint signature proves *who* sealed; it does not prove *when*. The
//! sealing key holder could backdate `ts_ms` at will. Anchoring the checkpoint
//! hash at a timestamping authority (TSA) closes that hole: the date becomes
//! enforceable against a third party who trusts the TSA, not us.
//!
//! What this module checks — and deliberately nothing more:
//!
//! * the TSA **granted** the request;
//! * the token's message imprint **is the checkpoint hash** (SHA-256).
//!
//! It does NOT validate the token's CMS signature. Doing so requires a full
//! X.509/CMS stack, and that dependency weight contradicts the rule that an
//! auditor must be able to read this crate's dependency list end to end. The
//! cryptographic validation is delegated to standard tooling against the TSA
//! certificate (`openssl ts -verify`), and the verifier's report says so
//! explicitly — a structural check silently presented as a cryptographic one
//! would be worse than none.
//!
//! The DER walker below handles exactly the subset RFC 3161 emits: definite
//! lengths, single-byte tags. Indefinite lengths are BER, not DER, and are
//! rejected.

use crate::error::Error;
use crate::hash::Hash;
use serde::{Deserialize, Serialize};

/// A timestamp token attached to a checkpoint in an evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    /// `Checkpoint::hash()` of the checkpoint the TSA timestamped.
    pub checkpoint_hash: Hash,
    /// Complete RFC 3161 `TimeStampResp`, DER, hex-encoded. Hex rather than
    /// base64: same alphabet as every other binary field in the pack.
    pub token_hex: String,
    /// Where the token came from. Informational, not proof.
    pub tsa: Option<String>,
}

/// What the structural pass extracts from a `TimeStampResp`.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampInfo {
    /// PKIStatus: granted(0) or grantedWithMods(1). Anything else never
    /// reaches this struct — the parse fails with `TimestampRejected`.
    pub status: u64,
    /// TSTInfo `messageImprint.hashedMessage`: the bytes the TSA vouches
    /// existed at `gen_time`. Must equal the checkpoint hash.
    pub hashed_message: Vec<u8>,
    /// TSTInfo `genTime` (GeneralizedTime, e.g. `20260728120000Z`), kept as
    /// text: the auditor compares it to a retention obligation, not to a
    /// clock.
    pub gen_time: Option<String>,
}

// OID content bytes (without tag/length).
const OID_ID_CT_TST_INFO: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xA0;

/// Cursor over a run of sibling TLV elements.
struct Der<'a> {
    b: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self {
        Der { b }
    }

    /// Reads one element, returns (tag, content) and advances past it.
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let b = self.b;
        if b.len() < 2 {
            return Err(Error::BadDer("truncated element".into()));
        }
        let tag = b[0];
        if tag & 0x1F == 0x1F {
            return Err(Error::BadDer("multi-byte tag".into()));
        }
        let (len, header) = match b[1] {
            n @ 0..=0x7F => (n as usize, 2),
            0x80 => {
                return Err(Error::BadDer(
                    "indefinite length (BER, not DER)".into(),
                ))
            }
            n => {
                let k = (n & 0x7F) as usize;
                if k > 4 || b.len() < 2 + k {
                    return Err(Error::BadDer("truncated length".into()));
                }
                let mut len = 0usize;
                for byte in &b[2..2 + k] {
                    len = (len << 8) | *byte as usize;
                }
                (len, 2 + k)
            }
        };
        if b.len() < header + len {
            return Err(Error::BadDer("value overruns the buffer".into()));
        }
        self.b = &b[header + len..];
        Ok((tag, &b[header..header + len]))
    }

    /// Reads one element and checks its tag.
    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8], Error> {
        let (t, v) = self.tlv()?;
        if t != tag {
            return Err(Error::BadDer(format!(
                "{what}: tag 0x{t:02X}, expected 0x{tag:02X}"
            )));
        }
        Ok(v)
    }

    /// Requires that the container held nothing beyond what was read. Trailing
    /// bytes tolerated anywhere would let one blob parse as two different
    /// tokens depending on the reader.
    fn finish(self, what: &str) -> Result<(), Error> {
        if !self.b.is_empty() {
            return Err(Error::BadDer(format!("{what}: trailing bytes")));
        }
        Ok(())
    }
}

fn int_value(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Error::BadDer("unusable INTEGER".into()));
    }
    Ok(bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

/// Parses a `TimeStampResp` down to its TSTInfo.
///
/// Path walked: TimeStampResp → PKIStatusInfo.status, then
/// ContentInfo → `[0]` → SignedData → version, digestAlgorithms,
/// encapContentInfo (eContentType must be id-ct-TSTInfo) → `[0]` →
/// OCTET STRING → TSTInfo.
///
/// Every field is read at its RFC 5652 position and every closed container
/// must be fully consumed. Scanning SignedData for a TSTInfo-shaped child
/// instead — as this function once did — would let a decoy placed ahead of
/// the real encapContentInfo shadow the eContent the TSA actually signed,
/// diverging from what `openssl ts -verify` validates.
pub fn parse_timestamp_response(der: &[u8]) -> Result<TimestampInfo, Error> {
    let mut top = Der::new(der);
    let mut resp = Der::new(top.expect(TAG_SEQUENCE, "TimeStampResp")?);
    top.finish("TimeStampResp")?;

    let status_info = resp.expect(TAG_SEQUENCE, "PKIStatusInfo")?;
    let status = int_value(Der::new(status_info).expect(TAG_INTEGER, "PKIStatus")?)?;
    if status > 1 {
        // rejection(2), waiting(3), … carry no token: surfacing the status is
        // all we can do.
        return Err(Error::TimestampRejected(status));
    }

    let mut content_info = Der::new(resp.expect(TAG_SEQUENCE, "ContentInfo")?);
    resp.finish("TimeStampResp body")?;
    content_info.expect(TAG_OID, "contentType")?;
    let wrapped = content_info.expect(TAG_CONTEXT_0, "content [0]")?;
    content_info.finish("ContentInfo")?;
    let mut outer = Der::new(wrapped);
    let signed_data = outer.expect(TAG_SEQUENCE, "SignedData")?;
    outer.finish("content [0]")?;

    // SignedData is not consumed to the end: certificates, crls and
    // signerInfos legitimately follow encapContentInfo, and their contents
    // are the CMS layer's business, not ours.
    let mut sd = Der::new(signed_data);
    sd.expect(TAG_INTEGER, "SignedData.version")?;
    sd.expect(TAG_SET, "digestAlgorithms")?;
    let mut eci = Der::new(sd.expect(TAG_SEQUENCE, "encapContentInfo")?);
    if eci.expect(TAG_OID, "eContentType")? != OID_ID_CT_TST_INFO {
        return Err(Error::BadDer("eContentType is not id-ct-TSTInfo".into()));
    }
    let econtent = eci.expect(TAG_CONTEXT_0, "eContent [0]")?;
    eci.finish("encapContentInfo")?;
    let mut econtent_wrap = Der::new(econtent);
    let tst_der = econtent_wrap.expect(TAG_OCTET_STRING, "eContent")?;
    econtent_wrap.finish("eContent [0]")?;

    let mut tst_wrap = Der::new(tst_der);
    let mut tst = Der::new(tst_wrap.expect(TAG_SEQUENCE, "TSTInfo")?);
    tst_wrap.finish("eContent OCTET STRING")?;
    tst.expect(TAG_INTEGER, "TSTInfo.version")?;
    tst.expect(TAG_OID, "TSTInfo.policy")?;
    let mut imprint = Der::new(tst.expect(TAG_SEQUENCE, "MessageImprint")?);
    imprint.expect(TAG_SEQUENCE, "hashAlgorithm")?;
    let hashed = imprint.expect(TAG_OCTET_STRING, "hashedMessage")?;
    tst.expect(TAG_INTEGER, "TSTInfo.serialNumber")?;

    let gen_time = match tst.tlv() {
        Ok((TAG_GENERALIZED_TIME, v)) => Some(String::from_utf8_lossy(v).into_owned()),
        _ => None,
    };

    Ok(TimestampInfo {
        status,
        hashed_message: hashed.to_vec(),
        gen_time,
    })
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Test-only DER builder, used to synthesize TSA responses. Lives here so
    //! evidence tests can craft anchors too; never compiled into the binary.

    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const OID_DEMO_POLICY: &[u8] = &[0x2A, 0x03, 0x04];

    /// A bare TSTInfo SEQUENCE over the given imprint.
    pub fn tst_info(imprint: &[u8], gen_time: &[u8]) -> Vec<u8> {
        let message_imprint = tlv(
            0x30,
            &[
                tlv(0x30, &tlv(0x06, OID_SHA256)),
                tlv(0x04, imprint),
            ]
            .concat(),
        );
        tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x06, OID_DEMO_POLICY),
                message_imprint,
                tlv(0x02, &[0x2A]),
                tlv(0x18, gen_time),
            ]
            .concat(),
        )
    }

    /// An encapContentInfo carrying the given TSTInfo.
    pub fn tst_encap(imprint: &[u8], gen_time: &[u8]) -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0x06, super::OID_ID_CT_TST_INFO),
                tlv(0xA0, &tlv(0x04, &tst_info(imprint, gen_time))),
            ]
            .concat(),
        )
    }

    /// Wraps raw SignedData children into a granted TimeStampResp.
    pub fn granted_response_from(signed_data_fields: &[u8]) -> Vec<u8> {
        let signed_data = tlv(0x30, signed_data_fields);
        let content_info = tlv(
            0x30,
            &[tlv(0x06, OID_SIGNED_DATA), tlv(0xA0, &signed_data)].concat(),
        );
        let status_info = tlv(0x30, &tlv(0x02, &[0]));
        tlv(0x30, &[status_info, content_info].concat())
    }

    /// A minimal granted TimeStampResp over the given imprint.
    pub fn granted_response(imprint: &[u8], gen_time: &[u8]) -> Vec<u8> {
        granted_response_from(
            &[
                tlv(0x02, &[3]),   // version
                tlv(0x31, &[]),    // digestAlgorithms SET
                tst_encap(imprint, gen_time),
                tlv(0x31, &[]),    // signerInfos SET
            ]
            .concat(),
        )
    }

    /// A response where the TSA refused (status 2, no token).
    pub fn rejected_response() -> Vec<u8> {
        tlv(0x30, &tlv(0x30, &tlv(0x02, &[2])))
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{granted_response, granted_response_from, rejected_response, tlv, tst_encap, tst_info};
    use super::*;

    #[test]
    fn granted_token_yields_imprint_and_time() {
        let imprint = [0xABu8; 32];
        let der = granted_response(&imprint, b"20260728120000Z");
        let info = parse_timestamp_response(&der).unwrap();
        assert_eq!(info.status, 0);
        assert_eq!(info.hashed_message, imprint);
        assert_eq!(info.gen_time.as_deref(), Some("20260728120000Z"));
    }

    #[test]
    fn rejection_is_surfaced_not_swallowed() {
        let err = parse_timestamp_response(&rejected_response()).unwrap_err();
        assert!(matches!(err, Error::TimestampRejected(2)));
    }

    #[test]
    fn truncation_is_detected() {
        let der = granted_response(&[0xABu8; 32], b"20260728120000Z");
        for cut in [1, der.len() / 2, der.len() - 1] {
            assert!(
                parse_timestamp_response(&der[..cut]).is_err(),
                "a response truncated at {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn indefinite_length_is_rejected() {
        // 0x80 length is BER. Accepting it would open the door to
        // multiple encodings of the same content — exactly what DER exists
        // to prevent.
        let err = parse_timestamp_response(&[0x30, 0x80, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, Error::BadDer(_)));
    }

    #[test]
    fn decoy_encap_content_info_is_rejected() {
        // A TSTInfo-shaped SEQUENCE smuggled in where digestAlgorithms
        // belongs. The shape-scanning parser this module used to have
        // returned the decoy's imprint and time — diverging from the
        // eContent the CMS layer verifies. Positional parsing refuses
        // the token outright.
        let decoy = tst_encap(&[0xEEu8; 32], b"19990101000000Z");
        let real = tst_encap(&[0xABu8; 32], b"20260728120000Z");
        let der = granted_response_from(
            &[tlv(0x02, &[3]), decoy, tlv(0x31, &[]), real, tlv(0x31, &[])].concat(),
        );
        assert!(matches!(
            parse_timestamp_response(&der),
            Err(Error::BadDer(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // After the TimeStampResp itself.
        let mut der = granted_response(&[0xABu8; 32], b"20260728120000Z");
        der.push(0x00);
        assert!(matches!(
            parse_timestamp_response(&der),
            Err(Error::BadDer(_))
        ));

        // Inside eContent [0], after the OCTET STRING: a NULL rides along
        // next to the TSTInfo.
        let encap = tlv(
            0x30,
            &[
                tlv(0x06, OID_ID_CT_TST_INFO),
                tlv(
                    0xA0,
                    &[
                        tlv(0x04, &tst_info(&[0xABu8; 32], b"20260728120000Z")),
                        tlv(0x05, &[]),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let der = granted_response_from(
            &[tlv(0x02, &[3]), tlv(0x31, &[]), encap, tlv(0x31, &[])].concat(),
        );
        assert!(matches!(
            parse_timestamp_response(&der),
            Err(Error::BadDer(_))
        ));
    }

    #[test]
    fn garbage_between_fields_does_not_panic() {
        let mut der = granted_response(&[0x01u8; 32], b"20260101000000Z");
        let mid = der.len() / 2;
        der[mid] ^= 0xFF;
        // Either a parse error or a clean result — never a panic. (If the
        // flipped byte lands in the imprint, the mismatch is caught by the
        // evidence layer comparing it to the checkpoint hash.)
        let _ = parse_timestamp_response(&der);
    }
}
