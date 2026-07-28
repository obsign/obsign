//! Offline verifier for evidence packs.
//!
//! This binary is a commercial argument as much as a tool: the auditor does
//! not take our word for it, they check for themselves, on their own machine,
//! with no network. Hence three non-negotiable constraints:
//!
//! * no network access, ever;
//! * minimal dependencies, readable end to end;
//! * script-friendly exit codes (0 valid, 1 invalid, 2 execution error).

use anyhow::{Context, Result};
use audit_core::checkpoint::PublicKeyEntry;
use audit_core::evidence::{self, Evidence, Severity};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "probant",
    about = "Verifies the integrity of an agent-action evidence pack",
    long_about = "Checks offline that an evidence pack has not been tampered with.\n\
                  Makes no network connection and depends on no service."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify an evidence pack
    Verify {
        /// Evidence pack file (JSON)
        evidence: PathBuf,

        /// Trusted public keys, obtained outside the pack.
        /// Without this the verification stays self-referential.
        #[arg(long)]
        trusted_keys: Option<PathBuf>,

        /// JSON output instead of the human-readable report
        #[arg(long)]
        json: bool,

        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Verify {
            evidence: path,
            trusted_keys,
            json,
            strict,
        } => {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let ev: Evidence = serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?;

            let trusted: Vec<PublicKeyEntry> = match &trusted_keys {
                None => Vec::new(),
                Some(p) => {
                    let raw = std::fs::read_to_string(p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    serde_json::from_str(&raw)
                        .with_context(|| format!("parsing {}", p.display()))?
                }
            };

            let report = evidence::verify(&ev, &trusted);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }

            let has_warnings = report.warnings().next().is_some();
            Ok(report.is_valid() && !(strict && has_warnings))
        }
    }
}

fn print_report(r: &evidence::Report) {
    println!("Evidence pack — chain \"{}\"", r.chain_id);
    println!();

    let range = match (r.first_seq, r.last_seq) {
        (Some(a), Some(b)) => format!("{a}..{b}"),
        _ => "empty".to_string(),
    };
    println!("  records     : {} (seq {})", r.records_total, range);
    println!("  sealed      : {} / {}", r.records_sealed, r.records_total);
    println!(
        "  checkpoints : {} valid / {}",
        r.checkpoints_valid, r.checkpoints_total
    );
    println!();

    if r.findings.is_empty() {
        println!("  No findings.");
    } else {
        for f in &r.findings {
            let tag = match f.severity {
                Severity::Error => "ERROR  ",
                Severity::Warning => "WARNING",
            };
            println!("  [{tag}] {} — {}", f.code, f.message);
        }
    }

    println!();
    if r.is_valid() {
        println!("VERDICT: chain intact.");
        if r.records_sealed < r.records_total {
            println!(
                "         {} record(s) unsealed: consistent, but not proven.",
                r.records_total - r.records_sealed
            );
        }
    } else {
        println!("VERDICT: TAMPERING DETECTED — this pack is not enforceable.");
    }
}
