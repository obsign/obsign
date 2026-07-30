//! `probant-tpm-enroll` — runs the enrollment ceremony against a TPM 2.0
//! command socket and emits the attestation the deployment bundle carries.
//!
//! ```sh
//! probant-tpm-enroll \
//!     --tpm 127.0.0.1:2321 --ctrl 127.0.0.1:2322 \
//!     --key-id gw-1 --binary-hash "$(sha256sum gateway | cut -d' ' -f1)" \
//!     --out attestation.json
//! ```
//!
//! Stdout is one JSON object: the attestation, the ready bundle entry for
//! the identity key, and the algorithm used. `--out` additionally writes the
//! bare `KeyAttestation` JSON — the file `deployment/attestation.json`
//! entries are assembled from.

use anyhow::{bail, Context};
use clap::Parser;
use tpm_enroll::{ctrl::SwtpmCtrl, enroll, EnrollmentRequest, Tpm};

#[derive(Parser)]
#[command(
    name = "probant-tpm-enroll",
    about = "Enroll a gateway identity key with a TPM 2.0: AK, certify, quote"
)]
struct Args {
    /// TPM to enroll against: host:port of a TCP command socket (swtpm:
    /// --server type=tcp,port=...), or the absolute path of a TPM character
    /// device on real hardware (/dev/tpmrm0).
    #[arg(long)]
    tpm: String,

    /// swtpm control socket, host:port. When given, the TPM is initialized
    /// through it first (CMD_INIT) — needed for a freshly started swtpm,
    /// meaningless for real hardware.
    #[arg(long)]
    ctrl: Option<String>,

    /// Bundle key id the attestation binds.
    #[arg(long)]
    key_id: String,

    /// SHA-256 of the gateway binary (hex), extended into the PCR.
    #[arg(long)]
    binary_hash: String,

    /// PCR index receiving the binary measurement.
    #[arg(long, default_value_t = 16)]
    pcr: u32,

    /// EK certificate file (DER), carried opaquely for the out-of-band
    /// vendor-root check. Omitted: an empty certificate is carried, which
    /// the report will flag as unverifiable out of band.
    #[arg(long)]
    ek_cert_file: Option<std::path::PathBuf>,

    /// Where to write the bare KeyAttestation JSON.
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let binary_hash: [u8; 32] = hex::decode(&args.binary_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("--binary-hash must be 32 bytes of hex (a SHA-256)")?;
    let ek_cert = match &args.ek_cert_file {
        None => Vec::new(),
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
    };

    if let Some(ctrl) = &args.ctrl {
        SwtpmCtrl::new(ctrl.clone())
            .init()
            .context("initializing swtpm over the control channel")?;
    }

    let mut tpm =
        Tpm::open(&args.tpm).with_context(|| format!("connecting to the TPM at {}", args.tpm))?;
    tpm.startup_clear().context("TPM2_Startup")?;

    let enrollment = enroll(
        &mut tpm,
        &EnrollmentRequest {
            key_id: args.key_id,
            binary_hash,
            pcr: args.pcr,
            ek_cert,
        },
    )
    .context("enrollment ceremony")?;

    // Sanity: what was enrolled must verify before anyone is told it exists.
    if let Err(e) = audit_core::attestation::verify_attestation(
        &enrollment.identity_entry,
        &enrollment.attestation,
    ) {
        bail!("the freshly produced attestation does not verify: {e}");
    }

    if let Some(out) = &args.out {
        std::fs::write(out, serde_json::to_string_pretty(&enrollment.attestation)?)
            .with_context(|| format!("writing {}", out.display()))?;
    }

    // The bundle's origin keys are ed25519-only today: a P-256 identity
    // entry pasted into deployment/origin-keys.json fails
    // active_origin_keys() and takes the WHOLE bundle down as
    // deployment_bundle_invalid. The attestation itself is fine — only the
    // entry must wait for P-256 origin-key support.
    if enrollment.algorithm.as_str() != "ed25519" {
        eprintln!(
            "[probant-tpm-enroll] warning: this TPM produced a {} identity key; \
             deployment bundles accept only ed25519 origin keys for now, so do \
             NOT paste identity_entry into origin-keys.json — the bundle would \
             stop verifying. Keep the attestation; enroll the entry once P-256 \
             origin keys are supported.",
            enrollment.algorithm.as_str()
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "algorithm": enrollment.algorithm.as_str(),
            "attestation": enrollment.attestation,
            "identity_entry": enrollment.identity_entry,
        }))?
    );
    Ok(())
}
