//! Control plane CLI: compile from git, publish atomically, export the audit
//! dossier, serve the read-only console.
//!
//! All output goes to stderr except data explicitly written to files.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use obsign_control_plane::source::{git_head, short_ref};
use obsign_control_plane::{
    compile, export_all, publish, worktree_divergence, Console, OpsKey, SourceTree,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "obsign-control",
    about = "Compiles signed bundles from a git checkout and distributes them",
    long_about = "The operator-side counterpart of the gateway: compiles a\n\
                  policy source tree into signed bundles (the version carries\n\
                  the commit sha), publishes immutable releases atomically,\n\
                  exports verified evidence dossiers, and serves a read-only\n\
                  console. Makes no network calls, like everything else."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct CompileArgs {
    /// Policy source tree (a git checkout; see the crate docs for the layout)
    #[arg(long)]
    source: PathBuf,

    /// Version label when the source is not in git. Defaults to the short
    /// commit sha of HEAD — in which case the working tree must match that
    /// commit: compile refuses to stamp a sha onto uncommitted bytes.
    #[arg(long)]
    label: Option<String>,

    /// Ops signing key seed, 32 bytes in hex. Development-grade by
    /// construction: production puts this key behind a KMS/HSM.
    #[arg(long)]
    key: PathBuf,

    #[arg(long, default_value = "ops-key")]
    key_id: String,
}

#[derive(Subcommand)]
enum Command {
    /// Compile and sign bundles into a directory, without publishing
    Compile {
        #[command(flatten)]
        args: CompileArgs,

        /// Output directory for the signed artifacts
        #[arg(long)]
        out: PathBuf,
    },

    /// Compile and publish an immutable release into a distribution directory
    Publish {
        #[command(flatten)]
        args: CompileArgs,

        /// Distribution directory the gateways watch
        #[arg(long)]
        dist: PathBuf,
    },

    /// Export every chain as a verified evidence pack plus a signed manifest
    Export {
        /// WAL directory written by the gateway. Read-only here.
        #[arg(long)]
        wal: PathBuf,

        /// Ledger store directory (checkpoints, anchors, sealing keys)
        #[arg(long)]
        store: PathBuf,

        /// Output directory for the dossier
        #[arg(long)]
        out: PathBuf,

        /// Ops signing key seed for the export manifest
        #[arg(long)]
        key: PathBuf,

        #[arg(long, default_value = "ops-key")]
        key_id: String,
    },

    /// Write the Cedar schema of the model these rules see
    ///
    /// A derived artifact: it comes from `tools.json` and from the engine's
    /// own model, needs no signing key, and belongs in the repository next to
    /// the rules. Committing it is what lets an editor type-check a rule
    /// while it is being written, with the same checks `compile` runs.
    Schema {
        /// Policy source tree
        #[arg(long)]
        source: PathBuf,

        /// Where to write it. Defaults to `<source>/policies/obsign.cedarschema`,
        /// beside the rules, where editors find it without configuration.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Write nothing; exit non-zero if the file on disk is out of date.
        /// For CI: a stale schema silently weakens every editor that reads it.
        #[arg(long)]
        check: bool,
    },

    /// Serve the read-only console
    Console {
        /// WAL directory to display
        #[arg(long)]
        wal: PathBuf,

        /// Ledger store directory, for sealing state
        #[arg(long)]
        store: Option<PathBuf>,

        /// Distribution directory, for the release page
        #[arg(long)]
        dist: Option<PathBuf>,

        /// Listen address. Localhost by default: the core console has no
        /// authentication, do not point it at a network you do not trust.
        #[arg(long, default_value = "127.0.0.1:9090")]
        listen: String,
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
        Command::Compile { args, out } => do_compile(&args, &out),
        Command::Publish { args, dist } => do_publish(&args, &dist),
        Command::Export {
            wal,
            store,
            out,
            key,
            key_id,
        } => do_export(&wal, &store, &out, &key, &key_id),
        Command::Schema { source, out, check } => do_schema(&source, out.as_deref(), check),
        Command::Console {
            wal,
            store,
            dist,
            listen,
        } => {
            let console = Console {
                wal_dir: wal,
                store_dir: store,
                dist_dir: dist,
            };
            console.serve(&listen).context("serving the console")?;
            Ok(())
        }
    }
}

fn load_and_compile(args: &CompileArgs) -> Result<(obsign_control_plane::Compiled, OpsKey)> {
    let ops = OpsKey::from_seed_file(&args.key, &args.key_id).context("loading the ops key")?;
    let tree = SourceTree::load(&args.source).context("loading the source tree")?;

    let source_ref = match &args.label {
        Some(l) => l.clone(),
        None => {
            let sha = git_head(&args.source)?;
            // The version will cite this sha. Refuse to sign bytes the
            // commit does not contain — an explicit --label is the way to
            // compile a tree that is not exactly a commit.
            let divergence = worktree_divergence(&args.source)?;
            if !divergence.is_empty() {
                let listed: Vec<String> = divergence.iter().map(|d| format!("  {d}")).collect();
                return Err(obsign_control_plane::Error::DirtyTree(listed.join("\n")).into());
            }
            short_ref(&sha).to_string()
        }
    };

    let compiled = compile(&tree, &source_ref, &ops).context("compiling")?;
    for w in &compiled.warnings {
        eprintln!("[control] warning: {w}");
    }
    eprintln!(
        "[control] compiled {} — {} rule file(s), {} tool(s), identity {}",
        compiled.policy.bundle.version,
        tree.cedar_files.len(),
        tree.tools.len(),
        match &compiled.identity {
            Some(i) => i.bundle.version.clone(),
            // Loud: a gateway without an identity bundle only starts in
            // declared mode, and someone should decide that on purpose.
            None => "ABSENT (declared mode only)".to_string(),
        }
    );
    Ok((compiled, ops))
}

fn do_compile(args: &CompileArgs, out: &std::path::Path) -> Result<()> {
    let (compiled, ops) = load_and_compile(args)?;
    std::fs::create_dir_all(out)?;

    let bundle_path = out.join("policy-bundle.json");
    std::fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&compiled.policy)?,
    )?;
    eprintln!("[control] signed policy bundle : {}", bundle_path.display());

    if let Some(idb) = &compiled.identity {
        let path = out.join("identity-bundle.json");
        std::fs::write(&path, serde_json::to_string_pretty(idb)?)?;
        eprintln!("[control] signed identity bundle : {}", path.display());
    }

    obsign_control_plane::record_trusted_key_file(&out.join("trusted-keys.json"), &ops)?;
    eprintln!(
        "[control] trusted keys : {}",
        out.join("trusted-keys.json").display()
    );
    Ok(())
}

fn do_publish(args: &CompileArgs, dist: &std::path::Path) -> Result<()> {
    let (compiled, ops) = load_and_compile(args)?;
    let published = publish(dist, &compiled, &ops, now_ms()).context("publishing")?;
    eprintln!(
        "[control] {} release {} -> {}",
        if published.reused {
            "re-pointed current at"
        } else {
            "published"
        },
        published.version,
        published.release_dir.display()
    );
    Ok(())
}

fn do_schema(source: &std::path::Path, out: Option<&std::path::Path>, check: bool) -> Result<()> {
    let tree = SourceTree::load(source).context("loading the source tree")?;
    let path = match out {
        Some(p) => p.to_path_buf(),
        None => obsign_control_plane::default_schema_path(source),
    };

    match obsign_control_plane::sync_schema(&tree, &path, check).context("deriving the schema")? {
        obsign_control_plane::SchemaSync::UpToDate => {
            eprintln!("[control] {} is up to date", path.display());
        }
        obsign_control_plane::SchemaSync::Stale => {
            // Echo the arguments the operator actually passed. Printing the
            // default invocation when they gave `--out` would send them to
            // regenerate a different file and leave this one stale.
            let mut fix = format!("obsign-control schema --source {}", source.display());
            if out.is_some() {
                fix.push_str(&format!(" --out {}", path.display()));
            }
            bail!(
                "{} is out of date with tools.json — regenerate it:\n\x20   {fix}",
                path.display()
            );
        }
        obsign_control_plane::SchemaSync::Written => {
            let declared: usize = tree.tools.iter().map(|t| t.policy_args.len()).sum();
            eprintln!(
                "[control] cedar schema : {} — {} tool(s), {} declared argument(s)",
                path.display(),
                tree.tools.len(),
                declared
            );
            eprintln!("[control] commit it: your editor type-checks rules against it");
        }
    }
    Ok(())
}

fn do_export(
    wal: &std::path::Path,
    store: &std::path::Path,
    out: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
) -> Result<()> {
    let ops = OpsKey::from_seed_file(key, key_id).context("loading the ops key")?;
    let (exports, all_valid) = export_all(wal, store, out, &ops, now_ms()).context("exporting")?;

    for e in &exports {
        eprintln!(
            "[control] {} — {} record(s), {}/{} sealed{}",
            e.file,
            e.report.records_total,
            e.report.records_sealed,
            e.report.records_total,
            if e.report.is_valid() {
                ""
            } else {
                " — INVALID"
            }
        );
        for f in e.report.errors() {
            eprintln!("[control]   [{}] {}", f.code, f.message);
        }
    }
    eprintln!(
        "[control] export manifest : {}",
        out.join("export-manifest.json").display()
    );

    // The dossier is written either way — a failing pack is exactly the one
    // you want on disk — but the exit code must not pretend it verified.
    if !all_valid {
        bail!("some packs do not verify — see findings above");
    }
    Ok(())
}
