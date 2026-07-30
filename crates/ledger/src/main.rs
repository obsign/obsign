//! Sealing service CLI: the counterpart of the gateway.
//!
//! The gateway writes the WAL and forwards calls; this binary — running on
//! another host, or at least under another identity — seals that log with a
//! key the gateway never holds, anchors the seals at a TSA, and assembles the
//! evidence pack. `seal` does one pass and exits (cron- and air-gap-
//! friendly); `run` loops for hosts that prefer a daemon.
//!
//! All output goes to stderr except data explicitly written to files.

use anyhow::{bail, Context, Result};
use audit_core::rfc3161::{parse_timestamp_response, Anchor};
use audit_core::Hash;
use clap::{Args, Parser, Subcommand};
use ledger::{
    export, seal_pass, timestamp_request, validate_response, FileSealer, Sealer, Store,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "probant-ledger",
    about = "Seals the gateway's audit log with a key the gateway never holds",
    long_about = "Reads the WAL the gateway produced (never writes to it),\n\
                  seals it into signed checkpoints, anchors them per RFC 3161\n\
                  by file exchange, and assembles offline-verifiable evidence\n\
                  packs."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct StoreArgs {
    /// Ledger store directory (checkpoints, anchors, sealing public keys)
    #[arg(long)]
    store: PathBuf,

    /// Audit chain identifier
    #[arg(long, default_value = "default")]
    chain_id: String,
}

#[derive(Args)]
struct SealArgs {
    #[command(flatten)]
    store: StoreArgs,

    /// WAL directory written by the gateway. Read-only here.
    #[arg(long)]
    wal: PathBuf,

    /// Sealing key seed, 32 bytes in hex. Development-grade by construction:
    /// production seals through an HSM (--hsm-module) so the key material
    /// never sits in a file at all.
    #[arg(long, conflicts_with = "hsm_module")]
    key: Option<PathBuf>,

    /// PKCS#11 module (.so) of the HSM that holds the sealing key
    #[arg(long)]
    hsm_module: Option<PathBuf>,

    /// Label of the Ed25519 key pair on the token
    #[arg(long, requires = "hsm_module")]
    hsm_key_label: Option<String>,

    /// Token to use, by label, when the module exposes several
    #[arg(long, requires = "hsm_module", conflicts_with = "hsm_slot")]
    hsm_token_label: Option<String>,

    /// Token to use, by slot id, when labels are not unique
    #[arg(long, requires = "hsm_module")]
    hsm_slot: Option<u64>,

    /// File holding the user PIN. Without it, the PROBANT_HSM_PIN
    /// environment variable. Never an argument: arguments end up in `ps`
    /// output and shell history.
    #[arg(long, requires = "hsm_module")]
    hsm_pin_file: Option<PathBuf>,

    #[arg(long, default_value = "seal-ledger")]
    key_id: String,

    /// Do not produce a checkpoint for fewer than this many new records
    #[arg(long, default_value_t = 1)]
    min_new: usize,

    /// Ops-signed deployment bundle (v1): the active gateway origin keys.
    /// Verified under the ops key in --trusted-keys before any of its keys
    /// are trusted. This is the current way to source origin trust; it also
    /// flips the default to require-origin (see --allow-unsigned-legacy-chains).
    #[arg(long, conflicts_with = "trusted_origin_keys")]
    deployment_bundle: Option<PathBuf>,

    /// Ops public key(s) that sign the deployment bundle (JSON, the same file
    /// format --trusted-keys uses elsewhere).
    #[arg(long, requires = "deployment_bundle")]
    trusted_keys: Option<PathBuf>,

    /// Trusted gateway origin keys as a flat file (JSON, role "origin").
    /// The v0 path, superseded by --deployment-bundle and kept for one
    /// transition. One source of origin truth: not both.
    #[arg(long)]
    trusted_origin_keys: Option<PathBuf>,

    /// Refuse to seal any record without a signature verifiable against the
    /// trusted origin set. With --deployment-bundle this is the default
    /// (v1 posture); the flat-file path leaves it opt-in.
    #[arg(long, requires = "trusted_origin_keys")]
    require_origin: bool,

    /// Restore v0 rollout tolerance under --deployment-bundle: unsigned
    /// records seal with a warning instead of being refused. The deliberately
    /// unlovely opt-out from the v1 default — the operator accepting the
    /// asterisk types it; nobody carries it silently.
    #[arg(long, requires = "deployment_bundle")]
    allow_unsigned_legacy_chains: bool,
}

#[derive(Subcommand)]
enum Command {
    /// One sealing pass, then exit (cron- and air-gap-friendly)
    Seal(SealArgs),

    /// Seal periodically
    Run {
        #[command(flatten)]
        args: SealArgs,

        #[arg(long, default_value_t = 30)]
        interval_secs: u64,
    },

    /// Assemble the evidence pack (records + checkpoints + keys + anchors)
    Export {
        #[command(flatten)]
        store: StoreArgs,

        /// WAL directory written by the gateway
        #[arg(long)]
        wal: PathBuf,

        /// Output file for the pack (JSON)
        #[arg(long)]
        out: PathBuf,

        /// Gateway origin keys to embed in the pack (JSON, role "origin").
        /// A reading convenience, like the embedded sealing keys: the
        /// auditor still verifies with keys obtained out of band.
        #[arg(long)]
        trusted_origin_keys: Option<PathBuf>,

        /// Ops-signed deployment bundle (v1) to embed in the pack, so the
        /// whole origin chain of trust verifies from the ops key alone.
        #[arg(long, conflicts_with = "trusted_origin_keys")]
        deployment_bundle: Option<PathBuf>,
    },

    /// RFC 3161 anchoring, by file exchange with the TSA
    #[command(subcommand)]
    Anchor(AnchorCmd),
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Write the DER TimeStampReq for a checkpoint (default: the latest)
    Request {
        #[command(flatten)]
        store: StoreArgs,

        /// Hash of the checkpoint to anchor (hex). Defaults to the latest,
        /// which transitively covers every earlier one through the
        /// checkpoint chain.
        #[arg(long)]
        checkpoint: Option<String>,

        /// Output file (conventionally .tsq)
        #[arg(long)]
        out: PathBuf,
    },

    /// Attach the TSA's TimeStampResp to the checkpoint it imprints
    Attach {
        #[command(flatten)]
        store: StoreArgs,

        /// The TSA's response file (conventionally .tsr)
        #[arg(long)]
        response: PathBuf,

        /// Name or URL of the TSA, recorded with the anchor. Informational.
        #[arg(long)]
        tsa: Option<String>,
    },
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Seal(args) => {
            let sealer = make_sealer(&args)?;
            let origin = origin_policy(&args)?;
            one_pass(&args, sealer.as_ref(), &origin).map_err(anyhow::Error::from)?;
            Ok(())
        }
        Command::Run {
            args,
            interval_secs,
        } => {
            // The sealer outlives the loop on purpose: credentials are
            // presented exactly once, at startup. A retry loop that
            // re-presented a wrong PIN every interval would walk the HSM
            // to CKR_PIN_LOCKED — a config mistake must not become a
            // locked token.
            let sealer = make_sealer(&args)?;
            let origin = origin_policy(&args)?;
            run_loop(&args, sealer.as_ref(), &origin, interval_secs)
        }
        Command::Export {
            store,
            wal,
            out,
            trusted_origin_keys,
            deployment_bundle,
        } => do_export(
            &store,
            &wal,
            &out,
            trusted_origin_keys.as_deref(),
            deployment_bundle.as_deref(),
        ),
        Command::Anchor(cmd) => match cmd {
            AnchorCmd::Request {
                store,
                checkpoint,
                out,
            } => anchor_request(&store, checkpoint.as_deref(), &out),
            AnchorCmd::Attach {
                store,
                response,
                tsa,
            } => anchor_attach(&store, &response, tsa),
        },
    }
}

/// Where the sealing key lives, from the flags. Exactly one source: a seed
/// file (development) or a PKCS#11 module (production).
fn make_sealer(args: &SealArgs) -> Result<Box<dyn Sealer>> {
    match (&args.key, &args.hsm_module) {
        (Some(seed), None) => Ok(Box::new(FileSealer::from_seed_file(seed, &args.key_id)?)),
        #[cfg(unix)]
        (None, Some(module)) => {
            use ledger::{Pkcs11Sealer, TokenSelector};
            let label = args
                .hsm_key_label
                .as_deref()
                .context("--hsm-module needs --hsm-key-label: which key on the token seals")?;
            let token = match (args.hsm_slot, &args.hsm_token_label) {
                (Some(slot), None) => TokenSelector::Slot(slot),
                (None, Some(label)) => TokenSelector::Label(label.clone()),
                (None, None) => TokenSelector::Only,
                (Some(_), Some(_)) => unreachable!("clap: conflicts_with"),
            };
            let pin = match &args.hsm_pin_file {
                Some(path) => std::fs::read_to_string(path)
                    .with_context(|| format!("reading the PIN file {}", path.display()))?
                    .trim()
                    .to_string(),
                None => std::env::var("PROBANT_HSM_PIN").map_err(|_| {
                    anyhow::anyhow!("no PIN: give --hsm-pin-file or set PROBANT_HSM_PIN")
                })?,
            };
            Ok(Box::new(Pkcs11Sealer::open(
                module,
                &token,
                &pin,
                label,
                &args.key_id,
            )?))
        }
        #[cfg(not(unix))]
        (None, Some(_)) => bail!("PKCS#11 sealing is only built on unix targets"),
        (None, None) => bail!(
            "choose a sealing key: --key <seed file> (development) or \
             --hsm-module <pkcs11 .so> (production)"
        ),
        (Some(_), Some(_)) => unreachable!("clap: conflicts_with"),
    }
}

/// Reads a trusted-key file (`Vec<PublicKeyEntry>` JSON).
fn read_keys(path: &Path) -> Result<Vec<audit_core::checkpoint::PublicKeyEntry>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn origin_policy(args: &SealArgs) -> Result<ledger::OriginPolicy> {
    // v1: an ops-signed deployment bundle, require-origin on by default.
    if let Some(bundle_path) = &args.deployment_bundle {
        let raw = std::fs::read_to_string(bundle_path)
            .with_context(|| format!("reading {}", bundle_path.display()))?;
        let signed: audit_core::SignedDeploymentBundle = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", bundle_path.display()))?;

        let ops_path = args
            .trusted_keys
            .as_ref()
            .context("--deployment-bundle needs --trusted-keys: the ops key that signed it")?;
        let ops_keys = read_keys(ops_path)?;
        let ops_vk = ops_keys
            .iter()
            .find(|k| k.key_id == signed.key_id)
            .with_context(|| {
                format!(
                    "deployment bundle signed with ops key \"{}\", absent from {}",
                    signed.key_id,
                    ops_path.display()
                )
            })?
            .to_verifying_key()
            .context("unusable ops key")?;

        let require = !args.allow_unsigned_legacy_chains;
        if !require {
            eprintln!(
                "[ledger] --allow-unsigned-legacy-chains: unsigned records still \
                 seal (rollout tolerance under a deployment bundle)"
            );
        }
        let policy = ledger::OriginPolicy::from_bundle(&signed, &ops_vk, require)?;
        eprintln!(
            "[ledger] origin trust from deployment bundle (require-origin {})",
            if require { "on" } else { "off" }
        );
        return Ok(policy);
    }

    // v0 flat-file path, superseded.
    match &args.trusted_origin_keys {
        None => {
            eprintln!(
                "[ledger] WARNING: no --deployment-bundle or --trusted-origin-keys \
                 — sealing without checking who wrote the records"
            );
            Ok(ledger::OriginPolicy::permissive())
        }
        Some(path) => {
            let keys = read_keys(path)?;
            if !args.require_origin {
                eprintln!(
                    "[ledger] origin keys loaded (flat file), --require-origin off: \
                     unsigned records still seal (rollout mode)"
                );
            }
            Ok(ledger::OriginPolicy::new(&keys, args.require_origin)?)
        }
    }
}

fn one_pass(
    args: &SealArgs,
    sealer: &dyn Sealer,
    origin: &ledger::OriginPolicy,
) -> Result<bool, ledger::Error> {
    let records = wal::read(&args.wal, &args.store.chain_id)?;
    let mut store = Store::open(&args.store.store, &args.store.chain_id)?;

    match seal_pass(&records, &mut store, sealer, origin, now_ms(), args.min_new)? {
        Some(sc) => {
            let cp = &sc.checkpoint;
            eprintln!(
                "[ledger] sealed [{}..{}] — root {} — key {}",
                cp.from_seq, cp.to_seq, cp.root, cp.key_id
            );
            Ok(true)
        }
        None => {
            eprintln!(
                "[ledger] nothing to seal ({} record(s), sealed up to {})",
                records.len(),
                store
                    .last()
                    .map(|sc| sc.checkpoint.to_seq.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
            Ok(false)
        }
    }
}

fn run_loop(
    args: &SealArgs,
    sealer: &dyn Sealer,
    origin: &ledger::OriginPolicy,
    interval_secs: u64,
) -> Result<()> {
    loop {
        match one_pass(args, sealer, origin) {
            Ok(_) => {}
            // Divergence, truncation, store corruption and an
            // unauthenticated record never self-heal: looping over them
            // would turn an incident into a heartbeat. Exit non-zero so the
            // orchestrator alerts.
            Err(
                e @ (ledger::Error::DivergedLog { .. }
                | ledger::Error::TruncatedLog { .. }
                | ledger::Error::StoreBroken(_)
                | ledger::Error::KeyConflict(_)
                | ledger::Error::UnauthenticatedRecord { .. }),
            ) => return Err(e.into()),
            // Anything else (I/O blip, WAL mid-write) is worth retrying,
            // but never silently.
            Err(e) => eprintln!("[ledger] pass failed, will retry: {e}"),
        }
        std::thread::sleep(Duration::from_secs(interval_secs.max(1)));
    }
}

fn do_export(
    store_args: &StoreArgs,
    wal_dir: &Path,
    out: &Path,
    origin_keys: Option<&Path>,
    deployment_bundle: Option<&Path>,
) -> Result<()> {
    let records = wal::read(wal_dir, &store_args.chain_id).context("reading the log")?;
    let store =
        Store::open(&store_args.store, &store_args.chain_id).context("opening the store")?;

    let origin_keys = match origin_keys {
        None => Vec::new(),
        Some(p) => read_keys(p)?,
    };
    let deployment = match deployment_bundle {
        None => None,
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("reading {}", p.display()))?;
            Some(
                serde_json::from_str(&raw)
                    .with_context(|| format!("parsing {}", p.display()))?,
            )
        }
    };
    let ev = export(records, &store, &origin_keys, deployment);
    // The self-check runs with what the pack embeds — including the origin
    // keys and the deployment bundle, so a signed log exports as verified
    // rather than "unverifiable because the keys travel out of band".
    let trusted = ev.keys.clone();

    std::fs::write(out, serde_json::to_string_pretty(&ev)?)
        .with_context(|| format!("writing {}", out.display()))?;
    eprintln!(
        "[ledger] evidence pack: {} — {} record(s), {} checkpoint(s), {} anchor(s)",
        out.display(),
        ev.records.len(),
        ev.checkpoints.len(),
        ev.anchors.len()
    );

    // The pack is written either way — a failing export is exactly the one
    // you want on disk for the investigation — but the exit code must not
    // pretend everything is fine.
    let report = audit_core::evidence::verify(&ev, &trusted);
    if !report.is_valid() {
        for f in report.errors() {
            eprintln!("[ledger]   [{}] {}", f.code, f.message);
        }
        bail!("the exported pack does not verify — see findings above");
    }
    if report.self_referential {
        // No keys in the store: nothing signed, nothing to prove.
        eprintln!(
            "[ledger] verified: internally consistent, {} sealed record(s) — \
             no key in the store, authenticity not provable",
            report.records_sealed
        );
    } else {
        eprintln!(
            "[ledger] verified: chain intact, {} sealed record(s)",
            report.records_sealed
        );
    }
    Ok(())
}

fn anchor_request(
    store_args: &StoreArgs,
    checkpoint: Option<&str>,
    out: &Path,
) -> Result<()> {
    let store =
        Store::open(&store_args.store, &store_args.chain_id).context("opening the store")?;

    let hash = match checkpoint {
        Some(hex) => Hash::from_hex(hex).context("--checkpoint is not a valid hash")?,
        None => store
            .last_hash()
            .context("no checkpoint in the store: seal before anchoring")?,
    };
    let sc = store
        .find_checkpoint(&hash)
        .with_context(|| format!("checkpoint {hash} is not in the store"))?;

    std::fs::write(out, timestamp_request(&hash))
        .with_context(|| format!("writing {}", out.display()))?;
    eprintln!(
        "[ledger] timestamp request for checkpoint [{}..{}] ({hash}): {}",
        sc.checkpoint.from_seq,
        sc.checkpoint.to_seq,
        out.display()
    );
    eprintln!("[ledger] send it to your TSA, then: probant-ledger anchor attach --response <file.tsr>");
    Ok(())
}

fn anchor_attach(
    store_args: &StoreArgs,
    response: &Path,
    tsa: Option<String>,
) -> Result<()> {
    let mut store =
        Store::open(&store_args.store, &store_args.chain_id).context("opening the store")?;
    let der = std::fs::read(response)
        .with_context(|| format!("reading {}", response.display()))?;

    // The token names its own checkpoint: the imprint is the checkpoint
    // hash. No --checkpoint flag to get wrong.
    let imprint = parse_timestamp_response(&der)
        .context("unreadable TSA response")?
        .hashed_message;
    let arr: [u8; 32] = imprint
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("the token does not imprint a SHA-256 digest"))?;
    let hash = Hash(arr);

    let info = validate_response(&store, &hash, &der)
        .context("the response does not anchor a checkpoint of this store")?;

    store.append_anchor(Anchor {
        checkpoint_hash: hash,
        token_hex: hex::encode(&der),
        tsa,
    })?;
    eprintln!(
        "[ledger] anchor attached to checkpoint {hash}{}",
        info.gen_time
            .map(|t| format!(" — TSA time {t}"))
            .unwrap_or_default()
    );
    Ok(())
}
