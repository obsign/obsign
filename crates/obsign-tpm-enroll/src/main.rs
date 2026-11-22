//! `obsign-tpm-enroll` runs both sides of the enrollment exchange
//! (attestation v4), one subcommand per step, files in between:
//!
//! ```sh
//! # gateway host
//! obsign-tpm-enroll request --tpm /dev/tpmrm0 --ek-cert-file ek.der --out request.json
//! # ops side (no TPM): keep ops-state.json secret until `finish`
//! obsign-tpm-enroll challenge --request request.json \
//!     --out challenge.json --state ops-state.json
//! # gateway host
//! obsign-tpm-enroll respond --tpm /dev/tpmrm0 --challenge challenge.json \
//!     --key-id gw-1 --pcr 16 --out response.json
//! # ops side
//! obsign-tpm-enroll finish --state ops-state.json --response response.json \
//!     --binary gateway --out attestation.json
//! ```
//!
//! `finish` writes the bare `KeyAttestation`, the file
//! `deployment/attestation.json` entries are assembled from, and prints the
//! attestation with the identity key's bundle entry. `measure` is the
//! launch-wrapper step (extend the PCR with the gateway binary before it
//! starts); `sign` signs with the enrolled identity key under its PCR policy.

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use obsign_tpm_enroll::enroll::{hash_file, measure};
use obsign_tpm_enroll::{
    challenge, ctrl::SwtpmCtrl, finish, request, respond, sign, ActivationRequest, Challenge,
    Enrollment, EnrollmentRequest, OpsState, Tpm,
};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "obsign-tpm-enroll",
    about = "Enroll a gateway identity key with a TPM 2.0: credential activation, certify, quote"
)]
struct Args {
    #[command(subcommand)]
    step: Step,
}

/// Where the TPM is.
#[derive(clap::Args)]
struct TpmArgs {
    /// TPM to talk to: host:port of a TCP command socket (swtpm:
    /// --server type=tcp,port=...), or the absolute path of a TPM character
    /// device on real hardware (/dev/tpmrm0).
    #[arg(long)]
    tpm: String,

    /// swtpm control socket, host:port. When given, the TPM is initialized
    /// through it first (CMD_INIT), which a freshly started swtpm needs and
    /// real hardware does not.
    #[arg(long)]
    ctrl: Option<String>,
}

/// The gateway binary measurement: a file to hash, or its SHA-256 in hex.
#[derive(clap::Args)]
#[group(multiple = false)]
struct BinaryArgs {
    /// The gateway binary, hashed with SHA-256.
    #[arg(long)]
    binary: Option<PathBuf>,
    /// SHA-256 of the gateway binary (hex).
    #[arg(long)]
    binary_hash: Option<String>,
}

#[derive(Subcommand)]
enum Step {
    /// Gateway host, step 1: emit the EK and AK public areas.
    Request {
        #[command(flatten)]
        tpm: TpmArgs,
        /// EK certificate file (DER, from NV 0x01C00002 on real hardware).
        /// Omitted: none is carried, and the report flags the vendor root
        /// as unverifiable.
        #[arg(long)]
        ek_cert_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ops side, step 2: check the request, make the credential challenge.
    Challenge {
        #[arg(long)]
        request: PathBuf,
        /// The challenge, for the gateway host.
        #[arg(long)]
        out: PathBuf,
        /// The ops state, kept on the ops side: it holds the credential and
        /// must stay secret until `finish`. Created owner-only; must not
        /// exist yet.
        #[arg(long)]
        state: PathBuf,
    },
    /// Gateway host, step 3: activate the credential, create the identity
    /// key under its PCR policy, certify it and quote the PCR.
    Respond {
        #[command(flatten)]
        tpm: TpmArgs,
        #[arg(long)]
        challenge: PathBuf,
        /// Bundle key id the attestation binds.
        #[arg(long)]
        key_id: String,
        /// PCR holding the gateway binary measurement.
        #[arg(long, default_value_t = 16)]
        pcr: u32,
        /// Measure this binary into the PCR first. Only for a PCR the launch
        /// wrapper has not already extended since reset: a second extension
        /// makes the enrolled value unreproducible at the next boot.
        #[command(flatten)]
        measure: BinaryArgs,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ops side, step 4: check the response, complete and verify the
    /// attestation.
    Finish {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        response: PathBuf,
        /// The released gateway binary (or its hash): the enrolled PCR must
        /// hold exactly one extension of it from reset.
        #[command(flatten)]
        expect: BinaryArgs,
        /// Where to write the bare KeyAttestation JSON.
        #[arg(long)]
        out: PathBuf,
    },
    /// Launch wrapper: extend the PCR with the gateway binary.
    Measure {
        #[command(flatten)]
        tpm: TpmArgs,
        #[arg(long, default_value_t = 16)]
        pcr: u32,
        #[command(flatten)]
        binary: BinaryArgs,
    },
    /// Sign a file's SHA-256 with the enrolled identity key, under its PCR
    /// policy: refused by the TPM unless the PCRs hold the enrolled values.
    Sign {
        #[command(flatten)]
        tpm: TpmArgs,
        /// The finished attestation (the `finish --out` file).
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        message_file: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    match Args::parse().step {
        Step::Request {
            tpm,
            ek_cert_file,
            out,
        } => {
            let ek_cert = match &ek_cert_file {
                None => Vec::new(),
                Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
            };
            let mut tpm = open(&tpm)?;
            let req = request(&mut tpm, &ek_cert).context("reading the EK and AK")?;
            write_json(&out, &req)?;
        }
        Step::Challenge {
            request,
            out,
            state,
        } => {
            let req: ActivationRequest = read_json(&request)?;
            let (ch, st) = challenge(&req).context("making the challenge")?;
            write_secret_json(&state, &st)?;
            write_json(&out, &ch)?;
        }
        Step::Respond {
            tpm,
            challenge,
            key_id,
            pcr,
            measure,
            out,
        } => {
            let ch: Challenge = read_json(&challenge)?;
            let measure = binary_hash(&measure)?;
            let mut tpm = open(&tpm)?;
            let enrollment = respond(
                &mut tpm,
                &ch,
                &EnrollmentRequest {
                    key_id,
                    pcr,
                    measure,
                },
            )
            .context("answering the challenge")?;
            write_json(&out, &enrollment)?;
        }
        Step::Finish {
            state,
            response,
            expect,
            out,
        } => {
            let st: OpsState = read_json(&state)?;
            let resp: Enrollment = read_json(&response)?;
            let expected = binary_hash(&expect)?;
            if expected.is_none() {
                eprintln!(
                    "[obsign-tpm-enroll] warning: no --binary/--binary-hash: the enrolled \
                     PCR value is accepted as the gateway host measured it, unchecked \
                     against a release"
                );
            }
            let att = finish(&st, &resp, expected.as_ref()).context("checking the response")?;
            write_json(&out, &att)?;
            warn_p256(&resp.algorithm);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "algorithm": resp.algorithm,
                    "attestation": att,
                    "identity_entry": resp.identity_entry,
                }))?
            );
        }
        Step::Measure { tpm, pcr, binary } => {
            let Some(hash) = binary_hash(&binary)? else {
                bail!("measure needs --binary or --binary-hash");
            };
            let mut tpm = open(&tpm)?;
            measure(&mut tpm, pcr, &hash).context("TPM2_PCR_Extend")?;
        }
        Step::Sign {
            tpm,
            attestation,
            message_file,
        } => {
            let att = read_json(&attestation)?;
            let digest = hash_file(&message_file)
                .with_context(|| format!("reading {}", message_file.display()))?;
            let mut tpm = open(&tpm)?;
            let sig = sign(&mut tpm, &att, &digest).context("signing under the PCR policy")?;
            println!("{}", hex::encode(sig));
        }
    }
    Ok(())
}

fn open(args: &TpmArgs) -> anyhow::Result<Tpm> {
    if let Some(ctrl) = &args.ctrl {
        SwtpmCtrl::new(ctrl.clone())
            .init()
            .context("initializing swtpm over the control channel")?;
    }
    let mut tpm =
        Tpm::open(&args.tpm).with_context(|| format!("connecting to the TPM at {}", args.tpm))?;
    tpm.startup_clear().context("TPM2_Startup")?;
    Ok(tpm)
}

fn binary_hash(b: &BinaryArgs) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(p) = &b.binary {
        return Ok(Some(
            hash_file(p).with_context(|| format!("hashing {}", p.display()))?,
        ));
    }
    match &b.binary_hash {
        None => Ok(None),
        Some(h) => Ok(Some(
            hex::decode(h)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("--binary-hash must be 32 bytes of hex (a SHA-256)")?,
        )),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(v)?)
        .with_context(|| format!("writing {}", path.display()))
}

/// The ops state holds the credential: created owner-only, and never over
/// an existing file someone else may already be able to read.
fn write_secret_json<T: serde::Serialize>(path: &Path, v: &T) -> anyhow::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    f.write_all(serde_json::to_string_pretty(v)?.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// The bundle's origin keys are ed25519-only today: a P-256 identity entry
/// pasted into deployment/origin-keys.json fails active_origin_keys() and
/// takes the WHOLE bundle down as deployment_bundle_invalid. The attestation
/// itself is fine, only the entry must wait for P-256 origin-key support.
fn warn_p256(algorithm: &str) {
    if algorithm != "ed25519" {
        eprintln!(
            "[obsign-tpm-enroll] warning: this TPM produced a {algorithm} identity key; \
             deployment bundles accept only ed25519 origin keys for now, so do \
             NOT paste identity_entry into origin-keys.json — the bundle would \
             stop verifying. Keep the attestation; enroll the entry once P-256 \
             origin keys are supported."
        );
    }
}
