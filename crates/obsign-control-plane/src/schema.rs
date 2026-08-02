//! The generated Cedar schema a policy repository commits.
//!
//! `obsign-control compile` derives the authorization model from
//! `tools.json` and type-checks every rule against it. This module writes
//! that same model out as a file, so an editor can run the check while the
//! rule is being written rather than at signing time.
//!
//! Two properties the rest of the module exists to hold:
//!
//! * **never write a schema for a catalogue `compile` would refuse.** An
//!   editor validating against a schema the control plane rejects is worse
//!   than no editor support: it green-lights rules that can never ship. So
//!   the catalogue goes through `Engine::load` — the same call `compile`
//!   makes — before anything reaches disk;
//! * **the file is derived, never authoritative.** `compile` regenerates the
//!   model and ignores whatever is on disk. A stale file misleads editors
//!   and nothing else, which is what `--check` is for.

use std::path::{Path, PathBuf};

use obsign_policy::bundle::Bundle;

use crate::compile::format_for;
use crate::source::SourceTree;
use crate::{write_atomic, Error};

/// Where the schema goes when the operator names no output.
///
/// Beside the rules it types, because that is where the Cedar VS Code
/// extension auto-detects a schema — a colleague who clones the repository
/// gets a working setup with nothing to configure.
pub fn default_schema_path(source_root: &Path) -> PathBuf {
    source_root
        .join("policies")
        .join(obsign_policy::SCHEMA_FILE)
}

/// What a `sync_schema` call did.
#[derive(Debug, PartialEq, Eq)]
pub enum SchemaSync {
    Written,
    UpToDate,
    /// `check` was set and the file on disk does not match the catalogue.
    Stale,
}

/// Derives the schema for `tree` and either writes it to `path` or, when
/// `check` is set, compares it against what is already there.
///
/// `check` never writes: it is meant for CI, where the useful outcome is a
/// red build and a diff, not a mutated working tree.
pub fn sync_schema(tree: &SourceTree, path: &Path, check: bool) -> Result<SchemaSync, Error> {
    // The catalogue's own validation — argument specs, JSON pointers,
    // defaults that coerce, Cedar syntax, mandatory `@id` — lives in
    // `Engine::load`. `SourceTree::load` does none of it, so without this
    // call a tree that `compile` refuses would still get a committed schema
    // and a "point your editor at it" instruction.
    //
    // Deliberately NOT `Engine::validate`: that type-checks the rules
    // *against the schema this function produces*, so requiring it here
    // would mean a broken rule blocks regeneration of the very file needed
    // to diagnose it.
    let bundle = Bundle {
        format: format_for(&tree.tools).to_string(),
        version: "schema-check".to_string(),
        cedar: tree.cedar.clone(),
        tools: tree.tools.clone(),
        fail_mode: tree.fail_mode.clone(),
    };
    obsign_policy::Engine::load(&bundle).map_err(|e| Error::Source(format!("policies: {e}")))?;

    let generated = obsign_policy::schema_source(&tree.tools)
        .map_err(|e| Error::Source(format!("tools.json: {e}")))?;

    if check {
        // An absent file is staleness, not an error — that is the first run.
        // Anything else (unreadable, not UTF-8) is reported as itself:
        // swallowing it into "out of date" would send the operator to
        // regenerate a file whose real problem is permissions.
        let current = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        return Ok(if current == generated {
            SchemaSync::UpToDate
        } else {
            SchemaSync::Stale
        });
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Atomic, like every other file this crate writes: a truncated schema is
    // one an editor would silently validate against.
    write_atomic(path, generated.as_bytes())?;
    Ok(SchemaSync::Written)
}
