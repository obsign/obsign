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
    export, seal_pass, timestamp_request, validate_response, FileSealer, Store,
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
    /// production implements the Sealer trait over a KMS/HSM so the key
    /// material never sits in a file at all.
    #[arg(long)]
    key: PathBuf,

    #[arg(long, default_value = "seal-ledger")]
    key_id: String,

    /// Do not produce a checkpoint for fewer than this many new records
    #[arg(long, default_value_t = 1)]
    min_new: usize,
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
            one_pass(&args).map_err(anyhow::Error::from)?;
            Ok(())
        }
        Command::Run {
            args,
            interval_secs,
        } => run_loop(&args, interval_secs),
        Command::Export { store, wal, out } => do_export(&store, &wal, &out),
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

fn one_pass(args: &SealArgs) -> Result<bool, ledger::Error> {
    let records = wal::read(&args.wal, &args.store.chain_id)?;
    let mut store = Store::open(&args.store.store, &args.store.chain_id)?;
    let sealer = FileSealer::from_seed_file(&args.key, &args.key_id)?;

    match seal_pass(&records, &mut store, &sealer, now_ms(), args.min_new)? {
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

fn run_loop(args: &SealArgs, interval_secs: u64) -> Result<()> {
    loop {
        match one_pass(args) {
            Ok(_) => {}
            // Divergence, truncation and store corruption never self-heal:
            // looping over them would turn an incident into a heartbeat.
            // Exit non-zero so the orchestrator alerts.
            Err(
                e @ (ledger::Error::DivergedLog { .. }
                | ledger::Error::TruncatedLog { .. }
                | ledger::Error::StoreBroken(_)
                | ledger::Error::KeyConflict(_)),
            ) => return Err(e.into()),
            // Anything else (I/O blip, WAL mid-write) is worth retrying,
            // but never silently.
            Err(e) => eprintln!("[ledger] pass failed, will retry: {e}"),
        }
        std::thread::sleep(Duration::from_secs(interval_secs.max(1)));
    }
}

fn do_export(store_args: &StoreArgs, wal_dir: &Path, out: &Path) -> Result<()> {
    let records = wal::read(wal_dir, &store_args.chain_id).context("reading the log")?;
    let store =
        Store::open(&store_args.store, &store_args.chain_id).context("opening the store")?;

    let ev = export(records, &store);
    let trusted = store.keys().to_vec();

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
    eprintln!("[ledger] verified: chain intact, {} sealed record(s)", report.records_sealed);
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
