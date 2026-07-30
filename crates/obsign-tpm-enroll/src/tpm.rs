//! The TPM 2.0 command subset enrollment needs, marshalled by hand.
//!
//! Every command here is TCG-standard (Part 3 of the TPM 2.0 spec); the
//! transport is a raw byte stream — swtpm's TCP command socket, or a real
//! TPM's character device (`/dev/tpmrm0`) on Linux. The two differ only in
//! framing: TCP delivers the response as a stream (header first, then the
//! body it announces), a character device answers one `read` with the whole
//! response.
//! Authorization is the password session with an empty password throughout:
//! enrollment runs against a freshly provisioned (or simulated) TPM whose
//! hierarchies carry no auth yet; taking owner/endorsement passwords is a
//! production-hardening step, not a protocol change.
//!
//! Response parsing follows the obsign-audit-core `Reader` discipline: bounds
//! checked, no recursion, a hostile or truncated response is a named error,
//! never a panic.

use crate::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// Command codes (TPM 2.0 Part 2, TPM_CC constants).
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_STARTUP: u32 = 0x0000_0144;
const CC_CERTIFY: u32 = 0x0000_0148;
const CC_QUOTE: u32 = 0x0000_0158;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_GET_CAPABILITY: u32 = 0x0000_017A;
const CC_PCR_READ: u32 = 0x0000_017E;
const CC_PCR_EXTEND: u32 = 0x0000_0182;

const TAG_NO_SESSIONS: u16 = 0x8001;
const TAG_SESSIONS: u16 = 0x8002;

pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM_RS_PW: u32 = 0x4000_0009;

/// `TPM_RC_INITIALIZE`: Startup after the TPM already started — the one
/// response code treated as success (a re-run against a live TPM).
const RC_INITIALIZE: u32 = 0x100;

const CAP_ALGS: u32 = 0x0000_0000;
const CAP_ECC_CURVES: u32 = 0x0000_0008;
/// Properties requested per `TPM2_GetCapability` page; a page claiming more
/// than this is a protocol violation.
const CAP_PROPERTY_COUNT: u32 = 256;

pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_EDDSA: u16 = 0x0060;
pub const ECC_NIST_P256: u16 = 0x0003;
pub const ECC_CURVE_25519: u16 = 0x0040;

/// Object attributes: fixedTPM | fixedParent | sensitiveDataOrigin |
/// userWithAuth | sign, plus restricted for the AK. The identity key is
/// deliberately *not* restricted — it must sign session certificates, which
/// are external bytes a restricted key refuses.
const ATTRS_AK: u32 = 0x0005_0072;
const ATTRS_IDENTITY: u32 = 0x0004_0072;

/// Largest response accepted. The biggest legitimate answer here is a
/// CreatePrimary (~600 bytes); the cap only bounds a hostile size field.
const MAX_RESPONSE: u32 = 0x10000;

/// The signing algorithm of the keys enrollment creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    Ed25519,
    EcdsaP256,
}

impl KeyAlg {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlg::Ed25519 => "ed25519",
            KeyAlg::EcdsaP256 => obsign_audit_core::attestation::ALGO_ECDSA_P256,
        }
    }
}

/// A key the TPM created and holds loaded.
pub struct CreatedKey {
    pub handle: u32,
    /// The marshalled `TPMT_PUBLIC` the TPM reported — the exact bytes it
    /// hashes into the key's Name.
    pub public: Vec<u8>,
}

/// An AK-signed attestation statement.
pub struct SignedAttest {
    /// Marshalled `TPMS_ATTEST`.
    pub attest: Vec<u8>,
    /// 64 bytes: ed25519 signature, or ECDSA `r || s` each 32.
    pub sig: [u8; 64],
}

/// One TPM connected over a byte-stream transport.
pub struct Tpm {
    transport: Transport,
}

/// The two transports a TPM 2.0 command stream rides here.
enum Transport {
    /// swtpm's `--server type=tcp` socket: raw command bytes on a stream.
    Tcp(TcpStream),
    /// A real TPM's character device (`/dev/tpmrm0`): one `write` per
    /// command, one `read` returns the entire response.
    Device(std::fs::File),
}

impl Tpm {
    /// Connects to `target`: an absolute path opens a TPM character device
    /// (`/dev/tpmrm0`), anything else is a `host:port` TCP command socket.
    pub fn open(target: &str) -> Result<Tpm, Error> {
        if target.starts_with('/') {
            Tpm::open_device(target)
        } else {
            Tpm::connect(target)
        }
    }

    pub fn connect(addr: &str) -> Result<Tpm, Error> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Tpm {
            transport: Transport::Tcp(stream),
        })
    }

    /// Opens a TPM character device. Prefer `/dev/tpmrm0` (the kernel
    /// resource manager) over `/dev/tpm0`: the raw device is exclusive and
    /// unmanaged. The kernel has already run `TPM2_Startup`, which is why
    /// `startup_clear` treats `TPM_RC_INITIALIZE` as success.
    pub fn open_device(path: &str) -> Result<Tpm, Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Tpm {
            transport: Transport::Device(file),
        })
    }

    /// `TPM2_Startup(SU_CLEAR)`. `TPM_RC_INITIALIZE` (already started) is
    /// success: enrollment may join a TPM another process brought up.
    pub fn startup_clear(&mut self) -> Result<(), Error> {
        match self.exec(
            "TPM2_Startup",
            TAG_NO_SESSIONS,
            CC_STARTUP,
            &0u16.to_be_bytes(),
        ) {
            Ok(_) => Ok(()),
            Err(Error::TpmRc {
                rc: RC_INITIALIZE, ..
            }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The algorithms the TPM implements (`TPM_CAP_ALGS`).
    pub fn algorithms(&mut self) -> Result<Vec<u16>, Error> {
        self.capability_u16_list("TPM2_GetCapability(algs)", CAP_ALGS, |r| {
            let alg = r.u16()?; // TPM_ALG_ID
            r.u32()?; // TPMA_ALGORITHM
            Ok(alg)
        })
    }

    /// The ECC curves the TPM implements (`TPM_CAP_ECC_CURVES`).
    pub fn ecc_curves(&mut self) -> Result<Vec<u16>, Error> {
        self.capability_u16_list("TPM2_GetCapability(curves)", CAP_ECC_CURVES, |r| r.u16())
    }

    /// Reads a complete `u16`-keyed capability list. Real TPMs may answer in
    /// pages (moreData set); libtpms answers in one. The next page starts
    /// after the last property seen. A response this loop cannot prove
    /// complete — the page budget exhausted with moreData still set, an
    /// empty page claiming more, a count above what was asked for — is an
    /// error, never a silently shortened list: callers pick key algorithms
    /// off this answer.
    fn capability_u16_list(
        &mut self,
        name: &'static str,
        cap: u32,
        parse: fn(&mut Reader) -> Result<u16, Error>,
    ) -> Result<Vec<u16>, Error> {
        let mut values = Vec::new();
        let mut first = 0u32;
        for _page in 0..8 {
            let (more, body) = self.get_capability(name, cap, first)?;
            let mut r = Reader::new(name, &body);
            let count = r.u32()?;
            if count > CAP_PROPERTY_COUNT {
                return Err(Error::Protocol {
                    command: name,
                    what: format!("count {count} exceeds the {CAP_PROPERTY_COUNT} requested"),
                });
            }
            for _ in 0..count {
                let v = parse(&mut r)?;
                values.push(v);
                first = v as u32 + 1;
            }
            if !more {
                return Ok(values);
            }
            if count == 0 {
                return Err(Error::Protocol {
                    command: name,
                    what: "empty capability page with moreData set".into(),
                });
            }
        }
        Err(Error::Protocol {
            command: name,
            what: "capability list still incomplete after 8 pages".into(),
        })
    }

    fn get_capability(
        &mut self,
        name: &'static str,
        cap: u32,
        first_property: u32,
    ) -> Result<(bool, Vec<u8>), Error> {
        let mut c = Vec::new();
        c.extend_from_slice(&cap.to_be_bytes());
        c.extend_from_slice(&first_property.to_be_bytes());
        c.extend_from_slice(&CAP_PROPERTY_COUNT.to_be_bytes());
        let body = self.exec(name, TAG_NO_SESSIONS, CC_GET_CAPABILITY, &c)?;
        // moreData (u8) + capability (u32), then the capability-specific list.
        let mut r = Reader::new(name, &body);
        let more = r.u8()? != 0;
        r.u32()?;
        Ok((more, r.rest().to_vec()))
    }

    /// `TPM2_CreatePrimary` under `hierarchy` with the given `TPMT_PUBLIC`
    /// template, empty auth throughout.
    pub fn create_primary(&mut self, hierarchy: u32, template: &[u8]) -> Result<CreatedKey, Error> {
        let name = "TPM2_CreatePrimary";
        let mut c = Vec::new();
        c.extend_from_slice(&hierarchy.to_be_bytes());
        c.extend_from_slice(&password_auth_area(1));
        // inSensitive: TPM2B wrapping (userAuth: empty, data: empty).
        c.extend_from_slice(&tpm2b(&[&tpm2b(&[])[..], &tpm2b(&[])[..]].concat()));
        c.extend_from_slice(&tpm2b(template)); // inPublic
        c.extend_from_slice(&tpm2b(&[])); // outsideInfo
        c.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
        let body = self.exec(name, TAG_SESSIONS, CC_CREATE_PRIMARY, &c)?;
        let mut r = Reader::new(name, &body);
        let handle = r.u32()?;
        r.u32()?; // parameterSize
        let public = r.tpm2b()?.to_vec(); // outPublic → TPMT_PUBLIC bytes
        Ok(CreatedKey { handle, public })
    }

    /// `TPM2_PCR_Extend` of one SHA-256 PCR.
    pub fn pcr_extend(&mut self, pcr: u32, digest: &[u8; 32]) -> Result<(), Error> {
        let name = "TPM2_PCR_Extend";
        let mut c = Vec::new();
        c.extend_from_slice(&pcr.to_be_bytes());
        c.extend_from_slice(&password_auth_area(1));
        c.extend_from_slice(&1u32.to_be_bytes()); // TPML_DIGEST_VALUES: one
        c.extend_from_slice(&ALG_SHA256.to_be_bytes());
        c.extend_from_slice(digest);
        self.exec(name, TAG_SESSIONS, CC_PCR_EXTEND, &c)?;
        Ok(())
    }

    /// `TPM2_PCR_Read` of one SHA-256 PCR: its current value.
    pub fn pcr_read_sha256(&mut self, pcr: u32) -> Result<Vec<u8>, Error> {
        let name = "TPM2_PCR_Read";
        let body = self.exec(name, TAG_NO_SESSIONS, CC_PCR_READ, &pcr_selection(pcr)?)?;
        let mut r = Reader::new(name, &body);
        r.u32()?; // pcrUpdateCounter
        let count = r.u32()?; // pcrSelectionOut
        for _ in 0..count.min(16) {
            r.u16()?; // hash alg
            let n = r.u8()? as usize;
            r.take(n)?;
        }
        let digests = r.u32()?; // TPML_DIGEST count
        if digests != 1 {
            return Err(Error::Protocol {
                command: name,
                what: format!("expected one PCR value back, got {digests}"),
            });
        }
        Ok(r.tpm2b()?.to_vec())
    }

    /// `TPM2_Certify(object, ak)`: the AK-signed statement that `object` is
    /// TPM-resident, carrying its Name.
    pub fn certify(&mut self, object: u32, ak: u32) -> Result<SignedAttest, Error> {
        let name = "TPM2_Certify";
        let mut c = Vec::new();
        c.extend_from_slice(&object.to_be_bytes());
        c.extend_from_slice(&ak.to_be_bytes());
        c.extend_from_slice(&password_auth_area(2)); // both handles authorize
        c.extend_from_slice(&tpm2b(&[])); // qualifyingData
        c.extend_from_slice(&ALG_NULL.to_be_bytes()); // inScheme: the key's own
        let body = self.exec(name, TAG_SESSIONS, CC_CERTIFY, &c)?;
        parse_attest_and_signature(name, &body)
    }

    /// `TPM2_Quote` over one SHA-256 PCR.
    pub fn quote(&mut self, ak: u32, pcr: u32) -> Result<SignedAttest, Error> {
        let name = "TPM2_Quote";
        let mut c = Vec::new();
        c.extend_from_slice(&ak.to_be_bytes());
        c.extend_from_slice(&password_auth_area(1));
        c.extend_from_slice(&tpm2b(&[])); // qualifyingData
        c.extend_from_slice(&ALG_NULL.to_be_bytes()); // inScheme: the key's own
        c.extend_from_slice(&pcr_selection(pcr)?);
        let body = self.exec(name, TAG_SESSIONS, CC_QUOTE, &c)?;
        parse_attest_and_signature(name, &body)
    }

    /// `TPM2_FlushContext`: unloads a created key.
    pub fn flush(&mut self, handle: u32) -> Result<(), Error> {
        self.exec(
            "TPM2_FlushContext",
            TAG_NO_SESSIONS,
            CC_FLUSH_CONTEXT,
            &handle.to_be_bytes(),
        )?;
        Ok(())
    }

    /// Sends one command, reads one response, returns the bytes after the
    /// 10-byte header. A nonzero response code is the named error.
    fn exec(
        &mut self,
        name: &'static str,
        tag: u16,
        cc: u32,
        params: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let size = 10 + params.len() as u32;
        let mut cmd = Vec::with_capacity(size as usize);
        cmd.extend_from_slice(&tag.to_be_bytes());
        cmd.extend_from_slice(&size.to_be_bytes());
        cmd.extend_from_slice(&cc.to_be_bytes());
        cmd.extend_from_slice(params);

        match &mut self.transport {
            Transport::Tcp(stream) => {
                stream.write_all(&cmd)?;
                let mut header = [0u8; 10];
                stream.read_exact(&mut header)?;
                let size = announced_size(name, &header)?;
                let mut response = header.to_vec();
                response.resize(size, 0);
                stream.read_exact(&mut response[10..])?;
                parse_response(name, &response)
            }
            Transport::Device(file) => {
                file.write_all(&cmd)?;
                // A TPM character device answers one read with the whole
                // response; a second read would block on the next command.
                let mut response = vec![0u8; MAX_RESPONSE as usize];
                let n = loop {
                    match file.read(&mut response) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                };
                response.truncate(n);
                let size = announced_size(name, &response)?;
                if size != n {
                    return Err(Error::Protocol {
                        command: name,
                        what: format!("device returned {n} bytes, header announces {size}"),
                    });
                }
                parse_response(name, &response)
            }
        }
    }
}

/// The response size a 10-byte TPM response header announces, bounds-checked.
fn announced_size(name: &'static str, header: &[u8]) -> Result<usize, Error> {
    if header.len() < 10 {
        return Err(Error::Protocol {
            command: name,
            what: format!("response header is {} bytes, needs 10", header.len()),
        });
    }
    let size = u32::from_be_bytes(header[2..6].try_into().expect("fixed slice"));
    if !(10..=MAX_RESPONSE).contains(&size) {
        return Err(Error::Protocol {
            command: name,
            what: format!("response size {size} out of bounds"),
        });
    }
    Ok(size as usize)
}

/// Splits a complete response into its verdict: the body after the header,
/// or the named `TPM_RC` error.
fn parse_response(name: &'static str, response: &[u8]) -> Result<Vec<u8>, Error> {
    let rc = u32::from_be_bytes(response[6..10].try_into().expect("checked length"));
    if rc != 0 {
        return Err(Error::TpmRc { command: name, rc });
    }
    Ok(response[10..].to_vec())
}

/// The authorization area for `n` password sessions with empty passwords:
/// the area's byte length, then per session `TPM_RS_PW`, an empty nonce,
/// continueSession, and an empty hmac.
fn password_auth_area(n: usize) -> Vec<u8> {
    let mut session = Vec::new();
    session.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    session.extend_from_slice(&tpm2b(&[])); // nonce
    session.push(0x01); // continueSession
    session.extend_from_slice(&tpm2b(&[])); // hmac (the empty password)
    let mut area = ((session.len() * n) as u32).to_be_bytes().to_vec();
    for _ in 0..n {
        area.extend_from_slice(&session);
    }
    area
}

/// `TPM2B_*`: u16 length prefix, then the bytes.
fn tpm2b(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// A `TPML_PCR_SELECTION` naming one PCR in the SHA-256 bank.
fn pcr_selection(pcr: u32) -> Result<Vec<u8>, Error> {
    if pcr >= 24 {
        return Err(Error::Unsupported(format!(
            "PCR {pcr} out of range: a TPM 2.0 bank holds PCRs 0..23"
        )));
    }
    let mut v = 1u32.to_be_bytes().to_vec(); // one selection
    v.extend_from_slice(&ALG_SHA256.to_be_bytes());
    v.push(3); // sizeofSelect: 24 PCRs
    let mut bitmap = [0u8; 3];
    bitmap[(pcr / 8) as usize] |= 1 << (pcr % 8);
    v.extend_from_slice(&bitmap);
    Ok(v)
}

/// The `TPMT_PUBLIC` template for the AK: restricted ECC signing key.
pub fn ak_template(alg: KeyAlg) -> Vec<u8> {
    ecc_signing_template(ATTRS_AK, alg)
}

/// The `TPMT_PUBLIC` template for the identity key: ordinary ECC signing
/// key — non-restricted, it signs session certificates (external bytes).
pub fn identity_template(alg: KeyAlg) -> Vec<u8> {
    ecc_signing_template(ATTRS_IDENTITY, alg)
}

fn ecc_signing_template(attrs: u32, alg: KeyAlg) -> Vec<u8> {
    let (scheme, curve) = match alg {
        KeyAlg::Ed25519 => (ALG_EDDSA, ECC_CURVE_25519),
        KeyAlg::EcdsaP256 => (ALG_ECDSA, ECC_NIST_P256),
    };
    let mut v = ALG_ECC.to_be_bytes().to_vec();
    v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // nameAlg
    v.extend_from_slice(&attrs.to_be_bytes());
    v.extend_from_slice(&tpm2b(&[])); // authPolicy
    v.extend_from_slice(&ALG_NULL.to_be_bytes()); // symmetric
    v.extend_from_slice(&scheme.to_be_bytes());
    v.extend_from_slice(&ALG_SHA256.to_be_bytes()); // scheme hash
    v.extend_from_slice(&curve.to_be_bytes());
    v.extend_from_slice(&ALG_NULL.to_be_bytes()); // kdf
    v.extend_from_slice(&tpm2b(&[])); // unique.x
    v.extend_from_slice(&tpm2b(&[])); // unique.y
    v
}

/// Extracts the raw public key from a marshalled ECC `TPMT_PUBLIC`, in the
/// verifier's wire form: the 32-byte ed25519 key, or the 65-byte
/// uncompressed P-256 point.
pub fn public_key_bytes(tpmt_public: &[u8]) -> Result<(KeyAlg, Vec<u8>), Error> {
    let name = "TPMT_PUBLIC";
    let mut r = Reader::new(name, tpmt_public);
    let object_type = r.u16()?;
    if object_type != ALG_ECC {
        return Err(Error::Protocol {
            command: name,
            what: format!("unexpected object type 0x{object_type:04X}"),
        });
    }
    r.u16()?; // nameAlg
    r.u32()?; // attributes
    r.tpm2b()?; // authPolicy
    let symmetric = r.u16()?;
    if symmetric != ALG_NULL {
        return Err(Error::Protocol {
            command: name,
            what: "symmetric parameters on a signing key".into(),
        });
    }
    let scheme = r.u16()?;
    if scheme != ALG_NULL {
        r.u16()?; // scheme hash
    }
    let curve = r.u16()?;
    r.u16()?; // kdf
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    match (scheme, curve) {
        (ALG_EDDSA, ECC_CURVE_25519) => Ok((KeyAlg::Ed25519, x.to_vec())),
        (ALG_ECDSA, ECC_NIST_P256) => {
            if x.len() > 32 || y.len() > 32 {
                return Err(Error::Protocol {
                    command: name,
                    what: "P-256 coordinate longer than 32 bytes".into(),
                });
            }
            let mut point = vec![0x04];
            point.extend_from_slice(&[0u8; 32][..32 - x.len()]);
            point.extend_from_slice(x);
            point.extend_from_slice(&[0u8; 32][..32 - y.len()]);
            point.extend_from_slice(y);
            Ok((KeyAlg::EcdsaP256, point))
        }
        (s, c) => Err(Error::Protocol {
            command: name,
            what: format!("unexpected scheme/curve 0x{s:04X}/0x{c:04X}"),
        }),
    }
}

/// Parses `parameterSize, TPM2B_ATTEST, TPMT_SIGNATURE` — the shared
/// response shape of Certify and Quote — into attest bytes and a 64-byte
/// signature (`r || s` zero-padded for ECDSA; EdDSA rides the same ECC
/// signature structure).
fn parse_attest_and_signature(name: &'static str, body: &[u8]) -> Result<SignedAttest, Error> {
    let mut r = Reader::new(name, body);
    r.u32()?; // parameterSize
    let attest = r.tpm2b()?.to_vec();
    let sig_alg = r.u16()?;
    if sig_alg != ALG_ECDSA && sig_alg != ALG_EDDSA {
        return Err(Error::Protocol {
            command: name,
            what: format!("unexpected signature algorithm 0x{sig_alg:04X}"),
        });
    }
    let hash_alg = r.u16()?;
    if hash_alg != ALG_SHA256 {
        return Err(Error::Protocol {
            command: name,
            what: format!("unexpected signature hash 0x{hash_alg:04X}"),
        });
    }
    let part_r = r.tpm2b()?;
    let part_s = r.tpm2b()?;
    if part_r.len() > 32 || part_s.len() > 32 {
        return Err(Error::Protocol {
            command: name,
            what: "signature part longer than 32 bytes".into(),
        });
    }
    let mut sig = [0u8; 64];
    sig[32 - part_r.len()..32].copy_from_slice(part_r);
    sig[64 - part_s.len()..].copy_from_slice(part_s);
    Ok(SignedAttest { attest, sig })
}

/// Bounds-checked reader — the obsign-audit-core `Reader` discipline, with the
/// command name carried so a malformed response says which answer broke.
struct Reader<'a> {
    name: &'static str,
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(name: &'static str, b: &'a [u8]) -> Self {
        Reader { name, b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.truncated())?;
        let slice = self.b.get(self.pos..end).ok_or_else(|| self.truncated())?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed slice"),
        ))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed slice"),
        ))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn rest(&mut self) -> &'a [u8] {
        let slice = &self.b[self.pos..];
        self.pos = self.b.len();
        slice
    }
    fn truncated(&self) -> Error {
        Error::Protocol {
            command: self.name,
            what: "truncated response".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TPM that serves scripted responses over a loopback socket: each
    /// incoming command (whatever it says) is answered with the next one.
    fn scripted_tpm(responses: Vec<Vec<u8>>) -> Tpm {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            for resp in responses {
                let mut head = [0u8; 10];
                if s.read_exact(&mut head).is_err() {
                    return;
                }
                let size = u32::from_be_bytes(head[2..6].try_into().unwrap()) as usize;
                if s.read_exact(&mut vec![0u8; size - 10]).is_err() {
                    return;
                }
                if s.write_all(&resp).is_err() {
                    return;
                }
            }
        });
        Tpm::connect(&addr.to_string()).unwrap()
    }

    /// One success-framed `TPM2_GetCapability(algs)` response page. `count`
    /// overrides the announced entry count where it must lie.
    fn algs_page(more: bool, algs: &[u16], count: Option<u32>) -> Vec<u8> {
        let mut body = vec![more as u8];
        body.extend_from_slice(&CAP_ALGS.to_be_bytes());
        body.extend_from_slice(&count.unwrap_or(algs.len() as u32).to_be_bytes());
        for a in algs {
            body.extend_from_slice(&a.to_be_bytes());
            body.extend_from_slice(&0u32.to_be_bytes()); // TPMA_ALGORITHM
        }
        let mut resp = 0x8001u16.to_be_bytes().to_vec();
        resp.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&body);
        resp
    }

    #[test]
    fn paged_capabilities_assemble_across_pages() {
        let mut tpm = scripted_tpm(vec![
            algs_page(true, &[ALG_ECDSA, ALG_ECC], None),
            algs_page(false, &[ALG_EDDSA], None),
        ]);
        assert_eq!(
            tpm.algorithms().unwrap(),
            vec![ALG_ECDSA, ALG_ECC, ALG_EDDSA]
        );
    }

    #[test]
    fn an_unfinished_capability_list_is_an_error_not_a_truncation() {
        // moreData still set when the page budget runs out: the list is
        // provably incomplete, and an incomplete list must not be returned —
        // pick_algorithm would silently choose off missing data.
        let mut tpm = scripted_tpm(vec![algs_page(true, &[ALG_ECDSA], None); 8]);
        match tpm.algorithms() {
            Err(Error::Protocol { what, .. }) => assert!(what.contains("incomplete")),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_page_claiming_more_is_an_error() {
        let mut tpm = scripted_tpm(vec![algs_page(true, &[], None)]);
        match tpm.algorithms() {
            Err(Error::Protocol { what, .. }) => assert!(what.contains("moreData")),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn a_count_beyond_the_request_is_an_error() {
        let mut tpm = scripted_tpm(vec![algs_page(false, &[], Some(CAP_PROPERTY_COUNT + 1))]);
        match tpm.algorithms() {
            Err(Error::Protocol { what, .. }) => assert!(what.contains("exceeds")),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn pcr_selection_sets_the_right_bit() {
        let sel = pcr_selection(16).unwrap();
        // count(4) + alg(2) + sizeofSelect(1) + bitmap(3)
        assert_eq!(sel.len(), 10);
        assert_eq!(
            &sel[7..10],
            &[0x00, 0x00, 0x01],
            "PCR 16 is bit 0 of byte 2"
        );
        let sel = pcr_selection(0).unwrap();
        assert_eq!(&sel[7..10], &[0x01, 0x00, 0x00]);
        assert!(pcr_selection(24).is_err(), "beyond the bank");
    }

    #[test]
    fn the_password_auth_area_is_the_spec_shape() {
        // One session: 4-byte area size, then 9 bytes of session.
        let area = password_auth_area(1);
        assert_eq!(area.len(), 13);
        assert_eq!(&area[..4], &9u32.to_be_bytes());
        assert_eq!(&area[4..8], &TPM_RS_PW.to_be_bytes());
        // Two sessions double the payload, not the size prefix.
        let area = password_auth_area(2);
        assert_eq!(area.len(), 22);
        assert_eq!(&area[..4], &18u32.to_be_bytes());
    }

    #[test]
    fn a_template_roundtrips_through_public_key_extraction() {
        // The template has an empty unique — extraction must still walk it,
        // yielding an empty point (a real response carries the coordinates).
        let t = identity_template(KeyAlg::Ed25519);
        let (alg, raw) = public_key_bytes(&t).unwrap();
        assert_eq!(alg, KeyAlg::Ed25519);
        assert!(raw.is_empty());
        let t = ak_template(KeyAlg::EcdsaP256);
        let (alg, point) = public_key_bytes(&t).unwrap();
        assert_eq!(alg, KeyAlg::EcdsaP256);
        assert_eq!(
            point.len(),
            65,
            "empty coordinates still pad to a full point"
        );
    }

    #[test]
    fn response_framing_is_validated_before_parsing() {
        // A well-formed success response: tag, size, rc 0, one body byte.
        let mut resp = 0x8001u16.to_be_bytes().to_vec();
        resp.extend_from_slice(&11u32.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.push(0xAB);
        assert_eq!(announced_size("test", &resp).unwrap(), 11);
        assert_eq!(parse_response("test", &resp).unwrap(), vec![0xAB]);

        // A nonzero response code is the named error, body discarded.
        let mut resp = 0x8001u16.to_be_bytes().to_vec();
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&0x100u32.to_be_bytes());
        assert!(matches!(
            parse_response("test", &resp),
            Err(Error::TpmRc { rc: 0x100, .. })
        ));

        // Sizes outside [10, MAX_RESPONSE] and short headers are refused.
        for bad in [0u32, 9, MAX_RESPONSE + 1] {
            let mut resp = 0x8001u16.to_be_bytes().to_vec();
            resp.extend_from_slice(&bad.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes());
            assert!(announced_size("test", &resp).is_err(), "size {bad}");
        }
        assert!(announced_size("test", &[0u8; 9]).is_err());
    }

    #[test]
    fn open_dispatches_paths_to_the_device_transport() {
        // An absolute path that is not a TPM device must fail to open as
        // one — and must not be tried as a TCP address.
        match Tpm::open("/nonexistent/tpmrm0") {
            Err(Error::Io(_)) => {}
            Err(e) => panic!("expected an I/O error, got {e}"),
            Ok(_) => panic!("opened a TPM on a nonexistent path"),
        }
    }

    #[test]
    fn truncated_responses_are_refused_not_panicked() {
        for cut in 0..8 {
            let body = vec![0u8; cut];
            assert!(parse_attest_and_signature("test", &body).is_err());
        }
        assert!(public_key_bytes(&[0x00]).is_err());
    }
}
