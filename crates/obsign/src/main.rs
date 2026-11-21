//! Offline verifier for evidence packs.
//!
//! This binary is a commercial argument as much as a tool: the auditor does
//! not take our word for it, they check for themselves, on their own machine,
//! with no network. Hence three non-negotiable constraints:
//!
//! * no network access, ever;
//! * minimal dependencies, readable end to end;
//! * script-friendly exit codes (0 proven, 1 invalid, 2 execution error,
//!   3 consistent but unproven: self-referential verification, or records
//!   no valid checkpoint covers).
//!
//! A log carrying a payload type this build cannot read exits 1, not 3.
//! Nothing an unauthenticated field can trigger may soften the verdict: the
//! `kind` string is chosen by whoever wrote the record, so a softer exit
//! keyed on it would be a forger's switch. The report says what happened and
//! what to rebuild; the exit code stays on the accusing side.

use anyhow::{Context, Result};
use obsign_audit_core::checkpoint::PublicKeyEntry;
use obsign_audit_core::evidence::{self, Evidence, Severity, VerifyOptions};
use std::path::PathBuf;
use std::process::ExitCode;

// Argument parsing is written by hand: the auditor compiles this binary
// themselves, and `clap` alone added twelve crates to the tree they have
// to vet. The whole CLI is one subcommand and three flags.

const USAGE: &str = "\
Checks offline that an evidence pack has not been tampered with.
Makes no network connection and depends on no service.

Usage: obsign verify [OPTIONS] <EVIDENCE>

Arguments:
  <EVIDENCE>  Evidence pack file (JSON)

Options:
      --trusted-keys <FILE>  Trusted public keys, obtained outside the pack.
                             Without this the verification stays self-referential
                             and cannot prove authenticity (exit 3 at best).
      --deployment-bundle <FILE>
                             Ops-signed deployment bundle naming the gateway
                             origin keys, when the pack does not embed one.
      --allow-unsigned-legacy-chains
                             Tolerate records that carry no origin signature
                             (a warning, not an error). Origin authentication
                             is required by default; this is the explicit
                             opt-out for pre-origin logs. A signature under a
                             key absent from the trusted set stays an error.
      --require-attestation  Treat an enrolled identity key with no valid
                             remote attestation as an error, not a warning
                             (v3; the EK vendor-root check stays out of band).
      --json                 JSON output instead of the human-readable report
      --strict               Treat warnings as errors. Caveats are not
                             warnings: they name checks this tool cannot do
                             offline (TSA signature, TPM vendor root), which
                             the auditor still performs out of band.
  -h, --help                 Print help

Input files (pack, keys, bundle) over 1 GiB are refused (exit 2).

Exit codes: 0 proven, 1 invalid, 2 execution error,
            3 consistent but unproven (no trusted keys supplied, or
              records no valid checkpoint covers, or an empty pack).";

enum Cli {
    Verify(VerifyCmd),
    Help,
}

struct VerifyCmd {
    evidence: PathBuf,
    trusted_keys: Option<PathBuf>,
    deployment_bundle: Option<PathBuf>,
    json: bool,
    strict: bool,
    /// Origin authentication is required by default (the v1 posture);
    /// `--allow-unsigned-legacy-chains` is the explicit opt-out.
    require_origin: bool,
    /// Remote attestation is opt-in (v3): `--require-attestation` turns an
    /// unattested enrolled identity key from a warning into an error.
    require_attestation: bool,
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
    let mut deployment_bundle: Option<PathBuf> = None;
    let mut json = false;
    let mut strict = false;
    // The v1 default: origin is required unless the operator explicitly opts
    // out for a pre-origin log.
    let mut require_origin = true;
    let mut require_attestation = false;
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
            // Accepted and redundant: origin is required by default now.
            // Kept so v0 invocations do not break.
            "--require-origin" => require_origin = true,
            "--require-attestation" => require_attestation = true,
            "--allow-unsigned-legacy-chains" => require_origin = false,
            "--trusted-keys" => {
                let v = args
                    .next()
                    .ok_or("`--trusted-keys` expects a file path".to_string())?;
                trusted_keys = Some(PathBuf::from(v));
            }
            _ if arg.starts_with("--trusted-keys=") => {
                trusted_keys = Some(PathBuf::from(&arg["--trusted-keys=".len()..]));
            }
            "--deployment-bundle" => {
                let v = args
                    .next()
                    .ok_or("`--deployment-bundle` expects a file path".to_string())?;
                deployment_bundle = Some(PathBuf::from(v));
            }
            _ if arg.starts_with("--deployment-bundle=") => {
                deployment_bundle = Some(PathBuf::from(&arg["--deployment-bundle=".len()..]));
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
        deployment_bundle,
        json,
        strict,
        require_origin,
        require_attestation,
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

/// Largest input file `verify` reads: 1 GiB. Generous (a pack is a few
/// hundred bytes per record, so millions of records fit) and far below the
/// canonical encoder's 4 GiB field limit. Without it, a file the auditor is
/// handed decides how much memory the verifier takes.
const MAX_INPUT_BYTES: u64 = 1 << 30;

/// `read_to_string`, refusing a file over [`MAX_INPUT_BYTES`]. The size is
/// checked up front and the read bounded too, for a file that grows or is not
/// a regular file.
fn read_input(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let too_big = || {
        anyhow::anyhow!(
            "{} is larger than {MAX_INPUT_BYTES} bytes (1 GiB), the most `obsign verify` reads",
            path.display()
        )
    };
    if file.metadata().map(|m| m.len()).unwrap_or(0) > MAX_INPUT_BYTES {
        return Err(too_big());
    }
    let mut raw = String::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("reading {}", path.display()))?;
    if raw.len() as u64 > MAX_INPUT_BYTES {
        return Err(too_big());
    }
    Ok(raw)
}

fn run(cmd: VerifyCmd) -> Result<ExitCode> {
    let raw = read_input(&cmd.evidence)?;
    let mut ev: Evidence = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", cmd.evidence.display()))?;

    // A deployment bundle supplied out of band fills in when the pack does
    // not embed one; a pack that embeds its own is authoritative. That is
    // the bundle that was in force when it was sealed.
    if let Some(p) = &cmd.deployment_bundle {
        let raw = read_input(p)?;
        let supplied = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", p.display()))?;
        if ev.deployment.is_none() {
            ev.deployment = Some(supplied);
        } else {
            eprintln!(
                "note: the pack already embeds a deployment bundle; --deployment-bundle ignored"
            );
        }
    }

    let trusted: Vec<PublicKeyEntry> = match &cmd.trusted_keys {
        None => Vec::new(),
        Some(p) => {
            let raw = read_input(p)?;
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
        }
    };

    let report = evidence::verify_with(
        &ev,
        &trusted,
        &VerifyOptions {
            require_origin: cmd.require_origin,
            require_attestation: cmd.require_attestation,
        },
    );

    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    Ok(ExitCode::from(exit_code(&report, cmd.strict)))
}

fn exit_code(report: &evidence::Report, strict: bool) -> u8 {
    // Caveats do not count here, by design: see `Severity::Caveat`.
    let has_warnings = report.warnings().next().is_some();
    if !report.is_valid() || (strict && has_warnings) {
        return 1;
    }
    // A self-referential run must not exit 0: a fully forged pack, signed
    // with the attacker's key embedded in the pack itself, passes every
    // internal check. Exit 0 is reserved for verification against keys the
    // auditor obtained through another channel.
    if report.self_referential {
        return 3;
    }
    // Same reasoning one level down: a record covered by no valid
    // checkpoint is consistent with the chain but may have been appended
    // after the fact, and an empty pack proves nothing. Exit 0 says every
    // record in the pack is proven, so neither may reach it. Under
    // `--strict` the matching warning has already made this a 1.
    if !report.proves_every_record() {
        return 3;
    }
    0
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
        // The date is the point of an anchor: show each one, and say so
        // when it was not counted (the finding below says why).
        for a in &r.anchors {
            println!(
                "                {} genTime {}{}{}",
                a.checkpoint.as_deref().unwrap_or("[absent checkpoint]"),
                a.gen_time.as_deref().unwrap_or("unreadable"),
                a.tsa.as_deref().map(|t| format!(" ({t})")).unwrap_or_default(),
                if a.consistent { "" } else { " — not counted" }
            );
        }
    }
    // "0 signed" on a legacy pack is information, not noise, and under
    // --require-origin it is the headline.
    if r.records_total > 0 {
        println!(
            "  origin      : {} signed by the gateway / {}",
            r.records_origin_ok, r.records_total
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
                Severity::Caveat => "CAVEAT ",
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
        } else if r.records_total == 0 {
            println!("VERDICT: empty pack — nothing to prove.");
        } else if r.records_sealed < r.records_total {
            println!("VERDICT: chain consistent — NOT PROVEN.");
        } else {
            println!("VERDICT: chain intact.");
        }
        if r.records_sealed < r.records_total {
            println!(
                "         {} record(s) unsealed: consistent, but not proven.",
                r.records_total - r.records_sealed
            );
        }
        let caveats = r.caveats().count();
        if caveats > 0 {
            println!(
                "         {caveats} check(s) left to do out of band (CAVEAT above): \
                 this verdict does not cover them."
            );
        }
    } else {
        println!("VERDICT: TAMPERING DETECTED — this pack is not enforceable.");
        if r.records_unknown > 0 {
            // Said after the verdict, never instead of it. This build cannot
            // tell an honest log written by a newer gateway from a record
            // rewritten to look like one. The discriminator would be the
            // origin signature, which is exactly what it cannot check. So it
            // accuses, and names the one thing that would settle it.
            println!(
                "         {} record(s) carry a payload type this build cannot read, and",
                r.records_unknown
            );
            println!(
                "         the failures above may follow from that alone. Rebuild this"
            );
            println!(
                "         verifier from a revision that knows those types and re-run"
            );
            println!(
                "         before treating this as evidence of tampering."
            );
        }
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
        assert_eq!(cmd.deployment_bundle, None);
        assert!(!cmd.json);
        assert!(!cmd.strict);
        // v1 posture: origin is required unless the operator opts out.
        assert!(cmd.require_origin);
    }

    #[test]
    fn legacy_opt_out_relaxes_the_origin_requirement() {
        let cmd = verify(&["verify", "--allow-unsigned-legacy-chains", "pack.json"]);
        assert!(!cmd.require_origin);
    }

    #[test]
    fn all_options() {
        let cmd = verify(&[
            "verify",
            "--json",
            "--strict",
            "--require-origin",
            "--trusted-keys",
            "keys.json",
            "--deployment-bundle",
            "deployment.json",
            "pack.json",
        ]);
        assert_eq!(cmd.evidence, PathBuf::from("pack.json"));
        assert_eq!(cmd.trusted_keys, Some(PathBuf::from("keys.json")));
        assert_eq!(cmd.deployment_bundle, Some(PathBuf::from("deployment.json")));
        assert!(cmd.json);
        assert!(cmd.strict);
        assert!(cmd.require_origin);
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

    fn report(findings: Vec<evidence::Finding>, self_referential: bool) -> evidence::Report {
        evidence::Report {
            chain_id: "c".into(),
            records_total: 1,
            records_sealed: 1,
            checkpoints_total: 1,
            checkpoints_valid: 1,
            anchors_total: 0,
            anchors_ok: 0,
            anchors: Vec::new(),
            records_origin_ok: 1,
            records_unknown: 0,
            first_seq: Some(0),
            last_seq: Some(0),
            self_referential,
            findings,
        }
    }

    fn finding(severity: Severity, code: &str) -> evidence::Finding {
        evidence::Finding { severity, code: code.into(), message: String::new() }
    }

    #[test]
    fn strict_does_not_fail_a_pack_for_its_out_of_band_caveats() {
        // An anchored, attested pack: the most complete evidence there is.
        // `--strict` used to fail it, while the same pack stripped of its
        // anchor and attestation passed.
        let r = report(
            vec![
                finding(Severity::Caveat, "anchor_not_validated"),
                finding(Severity::Caveat, "attestation_not_rooted"),
            ],
            false,
        );
        assert_eq!(exit_code(&r, true), 0);
        assert_eq!(exit_code(&r, false), 0);
    }

    #[test]
    fn strict_still_fails_on_a_warning() {
        let r = report(vec![finding(Severity::Warning, "identity_not_attested")], false);
        assert_eq!(exit_code(&r, false), 0);
        assert_eq!(exit_code(&r, true), 1);
    }

    #[test]
    fn caveats_do_not_lift_a_self_referential_run_to_exit_0() {
        let r = report(vec![finding(Severity::Caveat, "anchor_not_validated")], true);
        assert_eq!(exit_code(&r, true), 3);
    }

    #[test]
    fn an_unsealed_record_keeps_an_anchored_run_off_exit_0() {
        // Records covered by no valid checkpoint: consistent, not proven.
        // Exit 0 used to say otherwise.
        let mut r = report(vec![finding(Severity::Warning, "unsealed_records")], false);
        r.records_total = 9;
        r.records_sealed = 0;
        assert_eq!(exit_code(&r, false), 3);
        assert_eq!(exit_code(&r, true), 1);
    }

    #[test]
    fn an_empty_pack_is_not_proven() {
        let mut r = report(vec![finding(Severity::Warning, "empty_pack")], false);
        r.records_total = 0;
        r.records_sealed = 0;
        assert_eq!(exit_code(&r, false), 3);
        assert_eq!(exit_code(&r, true), 1);
    }

    #[test]
    fn an_error_fails_regardless_of_mode() {
        let r = report(vec![finding(Severity::Error, "anchor_mismatch")], false);
        assert_eq!(exit_code(&r, false), 1);
        assert_eq!(exit_code(&r, true), 1);
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
