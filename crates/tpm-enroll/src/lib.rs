//! TPM enrollment for attestation v3 — the gateway-side signer the design
//! doc deferred until a TPM existed to exercise it against.
//!
//! What it produces, pointed at a TPM 2.0 command socket:
//!
//! * an **AK** (restricted signing key, endorsement hierarchy),
//! * an **identity key** (ordinary signing key, owner hierarchy),
//! * a designated PCR extended with the gateway binary hash,
//! * `TPM2_Certify(identity, AK)` and `TPM2_Quote(AK, PCR)`,
//!
//! assembled into the exact [`audit_core::attestation::KeyAttestation`] the
//! offline verifier checks, plus the identity public key for the deployment
//! bundle entry.
//!
//! The TPM2 marshalling is hand-rolled — the PKCS#11/DER/HTTP stance: only
//! the command subset enrollment needs, bounds-checked response parsing, no
//! recursion, no TSS stack in the dependency tree. The transport is a raw
//! command stream: swtpm's `--server type=tcp` socket, or a real TPM's
//! character device (`/dev/tpmrm0`) on Linux hardware. The [`ctrl`] module
//! drives swtpm's control channel to bring the simulated TPM up, which real
//! hardware does not need.
//!
//! Algorithm choice is read off the TPM's capabilities: EdDSA/ed25519 where
//! implemented (system-uniform), ECDSA-P256 otherwise. The swtpm builds this
//! tree tests against (libtpms 0.10) implement no EdDSA — the capability
//! list carries neither `TPM_ALG_EDDSA` nor the 25519 curve, and an EdDSA
//! `CreatePrimary` fails `TPM_RC_SCHEME` — so the exercised path is P-256;
//! the verifier accepts both (see `audit_core::attestation`).

pub mod ctrl;
pub mod enroll;
pub mod tpm;

pub use enroll::{enroll, Enrollment, EnrollmentRequest};
pub use tpm::{KeyAlg, Tpm};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("TPM transport: {0}")]
    Io(#[from] std::io::Error),

    #[error("{command} failed with {}", format_rc(*.rc))]
    TpmRc { command: &'static str, rc: u32 },

    #[error("malformed TPM response to {command}: {what}")]
    Protocol { command: &'static str, what: String },

    #[error("swtpm control command {command} refused (code 0x{code:08x})")]
    Ctrl { command: &'static str, code: u32 },

    #[error("{0}")]
    Unsupported(String),
}

/// Renders a TPM_RC the way an operator will look it up: raw, plus the
/// decoded format-one error number and offending parameter when applicable.
fn format_rc(rc: u32) -> String {
    if rc & 0x80 != 0 {
        // Format-one response code: bits 0..5 the error, bit 6 set when the
        // subject is a parameter, bits 8..11 its number.
        let err = rc & 0x3F;
        let n = (rc >> 8) & 0xF;
        let subject = if rc & 0x40 != 0 {
            "parameter"
        } else {
            "handle/session"
        };
        format!("TPM_RC 0x{rc:03x} (format-one error 0x{err:02x}, {subject} {n})")
    } else {
        format!("TPM_RC 0x{rc:03x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_rendering_names_the_offending_parameter() {
        // 0x2d2 is what libtpms 0.10 answers to an EdDSA CreatePrimary:
        // TPM_RC_SCHEME (0x12) on parameter 2, the inPublic template.
        let msg = format_rc(0x2D2);
        assert!(msg.contains("0x2d2"), "{msg}");
        assert!(msg.contains("0x12"), "{msg}");
        assert!(msg.contains("parameter 2"), "{msg}");
        // Format-zero codes pass through raw.
        assert_eq!(format_rc(0x100), "TPM_RC 0x100");
    }
}
