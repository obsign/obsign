//! Offline verifier for evidence packs.
//!
//! This binary is a commercial argument as much as a tool: the auditor does
//! not take our word for it, they check for themselves, on their own machine,
//! with no network. Hence three non-negotiable constraints:
//!
//! * no network access, ever;
//! * minimal dependencies, readable end to end;
//! * script-friendly exit codes (0 proven, 1 invalid, 2 execution error,
//!   3 consistent but unproven — self-referential verification).

use anyhow::{Context, Result};
use audit_core::checkpoint::PublicKeyEntry;
use audit_core::evidence::{self, Evidence, Severity};
use std::path::PathBuf;
use std::process::ExitCode;

// Argument parsing is written by hand: the auditor compiles this binary
// themselves, and `clap` alone added twelve crates to the tree they have
// to vet. The whole CLI is one subcommand and three flags.

const USAGE: &str = "\
Checks offline that an evidence pack has not been tampered with.
Makes no network connection and depends on no service.

Usage: probant verify [OPTIONS] <EVIDENCE>

Arguments:
  <EVIDENCE>  Evidence pack file (JSON)

Options:
      --trusted-keys <FILE>  Trusted public keys, obtained outside the pack.
                             Without this the verification stays self-referential
                             and cannot prove authenticity (exit 3 at best).
      --json                 JSON output instead of the human-readable report
      --strict               Treat warnings as errors
  -h, --help                 Print help

Exit codes: 0 proven, 1 invalid, 2 execution error,
            3 consistent but unproven (no trusted keys supplied).";

enum Cli {
    Verify(VerifyCmd),
    Help,
}

struct VerifyCmd {
    evidence: PathBuf,
    trusted_keys: Option<PathBuf>,
    json: bool,
    strict: bool,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Cli, String> {
    match args.next().as_deref() {
        None => return Err("missing command, expected `verify`".into()),
        Some("-h" | "--help") => return Ok(Cli::Help),
        Some("verify") => {}
        Some(other) => return Err(format!("unknown command `{other}`, expected `verify`")),
    }

    let mut evidence: Option<PathBuf> = None;
    let mut trusted_keys: Option<PathBuf> = None;
    let mut json = false;
    let mut strict = false;
    let mut options_done = false;

    let mut positional = |arg: String| -> Result<(), String> {
        if evidence.is_some() {
            return Err(format!("unexpected argument `{arg}`"));
        }
        evidence = Some(PathBuf::from(arg));
        Ok(())
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            _ if options_done => positional(arg)?,
            "--" => options_done = true,
            "-h" | "--help" => return Ok(Cli::Help),
            "--json" => json = true,
            "--strict" => strict = true,
            "--trusted-keys" => {
                let v = args
                    .next()
                    .ok_or("`--trusted-keys` expects a file path".to_string())?;
                trusted_keys = Some(PathBuf::from(v));
            }
            _ if arg.starts_with("--trusted-keys=") => {
                trusted_keys = Some(PathBuf::from(&arg["--trusted-keys=".len()..]));
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(format!("unknown option `{arg}`"));
            }
            _ => positional(arg)?,
        }
    }

    let evidence = evidence.ok_or("missing argument <EVIDENCE>".to_string())?;
    Ok(Cli::Verify(VerifyCmd {
        evidence,
        trusted_keys,
        json,
        strict,
    }))
}

fn main() -> ExitCode {
    let cmd = match parse_args(std::env::args().skip(1)) {
        Ok(Cli::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Verify(cmd)) => cmd,
        Err(msg) => {
            eprintln!("error: {msg}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cmd: VerifyCmd) -> Result<ExitCode> {
    let raw = std::fs::read_to_string(&cmd.evidence)
        .with_context(|| format!("reading {}", cmd.evidence.display()))?;
    let ev: Evidence = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", cmd.evidence.display()))?;

    let trusted: Vec<PublicKeyEntry> = match &cmd.trusted_keys {
        None => Vec::new(),
        Some(p) => {
            let raw =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
        }
    };

    let report = evidence::verify(&ev, &trusted);

    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    let has_warnings = report.warnings().next().is_some();
    if !report.is_valid() || (cmd.strict && has_warnings) {
        return Ok(ExitCode::from(1));
    }
    // A self-referential run must not exit 0: a fully forged pack, signed
    // with the attacker's key embedded in the pack itself, passes every
    // internal check. Exit 0 is reserved for verification against keys the
    // auditor obtained through another channel.
    if report.self_referential {
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
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
    if r.anchors_total > 0 {
        println!(
            "  anchors     : {} consistent / {} (RFC 3161)",
            r.anchors_ok, r.anchors_total
        );
    }
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
        if r.self_referential {
            println!("VERDICT: internally consistent — NOT PROVEN.");
            println!(
                "         Verified against the keys embedded in the pack itself: \
                 a forged"
            );
            println!(
                "         pack passes this check identically. Re-run with \
                 --trusted-keys."
            );
        } else {
            println!("VERDICT: chain intact.");
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    fn verify(args: &[&str]) -> VerifyCmd {
        match parse(args) {
            Ok(Cli::Verify(cmd)) => cmd,
            Ok(Cli::Help) => panic!("expected Verify, got Help"),
            Err(e) => panic!("expected Verify, got error: {e}"),
        }
    }

    #[test]
    fn minimal_invocation() {
        let cmd = verify(&["verify", "pack.json"]);
        assert_eq!(cmd.evidence, PathBuf::from("pack.json"));
        assert_eq!(cmd.trusted_keys, None);
        assert!(!cmd.json);
        assert!(!cmd.strict);
    }

    #[test]
    fn all_options() {
        let cmd = verify(&[
            "verify",
            "--json",
            "--strict",
            "--trusted-keys",
            "keys.json",
            "pack.json",
        ]);
        assert_eq!(cmd.evidence, PathBuf::from("pack.json"));
        assert_eq!(cmd.trusted_keys, Some(PathBuf::from("keys.json")));
        assert!(cmd.json);
        assert!(cmd.strict);
    }

    #[test]
    fn trusted_keys_equals_form() {
        let cmd = verify(&["verify", "--trusted-keys=keys.json", "pack.json"]);
        assert_eq!(cmd.trusted_keys, Some(PathBuf::from("keys.json")));
    }

    #[test]
    fn options_after_positional() {
        let cmd = verify(&["verify", "pack.json", "--strict"]);
        assert!(cmd.strict);
    }

    #[test]
    fn double_dash_ends_options() {
        let cmd = verify(&["verify", "--", "--strict"]);
        assert_eq!(cmd.evidence, PathBuf::from("--strict"));
        assert!(!cmd.strict);
    }

    #[test]
    fn help_flags() {
        assert!(matches!(parse(&["--help"]), Ok(Cli::Help)));
        assert!(matches!(parse(&["-h"]), Ok(Cli::Help)));
        assert!(matches!(parse(&["verify", "--help"]), Ok(Cli::Help)));
    }

    #[test]
    fn errors() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["frobnicate"]).is_err());
        assert!(parse(&["verify"]).is_err());
        assert!(parse(&["verify", "--bogus", "pack.json"]).is_err());
        assert!(parse(&["verify", "--trusted-keys"]).is_err());
        assert!(parse(&["verify", "a.json", "b.json"]).is_err());
    }
}
