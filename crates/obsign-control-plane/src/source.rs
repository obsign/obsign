//! The policy source tree — what a customer keeps in git.
//!
//! Layout, relative to the tree root:
//!
//! ```text
//! policies/*.cedar             rules, concatenated in file-name order
//! tools.json                   the signed catalogue's source (Vec<ToolDef>)
//! fail-mode.json               optional FailMode
//! identity/provider.json       { issuer, audience, claims? }
//! identity/jwks.json           the IdP's JWKS, checked into git like a rule
//! deployment/origin-keys.json  active gateway origin keys, reviewed like the JWKS
//! ```
//!
//! Everything here is *validated*, not merely parsed. The gateway refuses an
//! unsigned bundle; this module is the matching guarantee on the other side —
//! a bundle that would blow up at load time (Cedar syntax, missing `@id`,
//! unusable JWKS) or misbehave silently (duplicate tool, fail-mode override
//! for a tool that does not exist) is refused at compile time, in CI, where
//! the author of the pull request is still looking.

use obsign_audit_core::checkpoint::{KeyRole, PublicKeyEntry};
use obsign_identity::{ClaimMap, JwkSet};
use obsign_policy::bundle::{FailMode, ToolDef};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::Error;

/// A loaded, validated source tree.
#[derive(Debug)]
pub struct SourceTree {
    pub root: PathBuf,
    /// Cedar sources concatenated in lexicographic file-name order — the
    /// same tree always produces the same bytes, hence the same bundle hash.
    pub cedar: String,
    pub cedar_files: Vec<String>,
    pub tools: Vec<ToolDef>,
    pub fail_mode: FailMode,
    /// Absent when the tree has no `identity/` directory. A gateway without
    /// an identity bundle only starts in declared mode, and says so.
    pub identity: Option<IdentitySource>,
    /// Active gateway origin keys, absent when the tree has no `deployment/`
    /// directory. Absent means no gateway is enrolled yet — legitimate
    /// before the first one, and honestly distinct from an empty set.
    pub deployment: Option<Vec<PublicKeyEntry>>,
    /// Remote-attestation enrollments (v3), from `deployment/attestation.json`.
    /// Each is a TPM quote+certify an operator captured off their gateway's
    /// hardware and committed for review. Empty when the file is absent.
    pub attestations: Vec<obsign_audit_core::attestation::KeyAttestation>,
}

#[derive(Debug)]
pub struct IdentitySource {
    pub issuer: String,
    pub audience: String,
    pub claims: ClaimMap,
    pub jwks: JwkSet,
}

#[derive(Deserialize)]
struct ProviderFile {
    issuer: String,
    audience: String,
    #[serde(default)]
    claims: Option<ClaimMap>,
}

impl SourceTree {
    pub fn load(root: &Path) -> Result<Self, Error> {
        let (cedar, cedar_files) = read_cedar(&root.join("policies"))?;
        let tools = read_tools(&root.join("tools.json"))?;
        let fail_mode = read_fail_mode(&root.join("fail-mode.json"), &tools)?;
        let identity = read_identity(&root.join("identity"))?;
        let deployment = read_deployment(&root.join("deployment"))?;
        let attestations = read_attestations(&root.join("deployment"), deployment.as_deref())?;

        Ok(SourceTree {
            root: root.to_path_buf(),
            cedar,
            cedar_files,
            tools,
            fail_mode,
            identity,
            deployment,
            attestations,
        })
    }
}

fn read_cedar(dir: &Path) -> Result<(String, Vec<String>), Error> {
    if !dir.is_dir() {
        return Err(Error::Source(format!(
            "no policies/ directory in {}",
            dir.parent().unwrap_or(dir).display()
        )));
    }

    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".cedar") && entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(Error::Source(format!(
            "no .cedar file in {}: an empty policy set denies everything, \
             which deserves an explicit file saying so",
            dir.display()
        )));
    }
    // Lexicographic order: the concatenation must not depend on the
    // filesystem's enumeration order, or the same commit would produce two
    // different bundle hashes on two machines.
    names.sort();

    let mut cedar = String::new();
    for name in &names {
        let content = std::fs::read_to_string(dir.join(name))?;
        cedar.push_str(&format!("// ─── {name} ───\n{content}\n"));
    }
    Ok((cedar, names))
}

fn read_tools(path: &Path) -> Result<Vec<ToolDef>, Error> {
    if !path.is_file() {
        return Err(Error::Source(format!(
            "missing {}: the signed catalogue is authoritative, a bundle \
             without one refuses every tool",
            path.display()
        )));
    }
    let tools: Vec<ToolDef> = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| Error::Source(format!("{}: {e}", path.display())))?;

    let mut seen = HashSet::new();
    for t in &tools {
        if t.name.is_empty() {
            return Err(Error::Source(format!(
                "{}: a tool with an empty name",
                path.display()
            )));
        }
        if !seen.insert(t.name.as_str()) {
            // The engine indexes tools by name: a duplicate would silently
            // shadow one definition with the other, and which one wins would
            // depend on file order. Refused here, where it is a diff.
            return Err(Error::Source(format!(
                "{}: tool \"{}\" is declared twice",
                path.display(),
                t.name
            )));
        }
    }
    Ok(tools)
}

fn read_fail_mode(path: &Path, tools: &[ToolDef]) -> Result<FailMode, Error> {
    if !path.is_file() {
        return Ok(FailMode::default());
    }
    let fm: FailMode = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| Error::Source(format!("{}: {e}", path.display())))?;

    for name in fm.tools.keys() {
        if !tools.iter().any(|t| &t.name == name) {
            // A typo here does not fail, it silently applies the default
            // behaviour to the tool the author meant to override. That is
            // the worst kind of bug for a fail-open declaration.
            return Err(Error::Source(format!(
                "{}: fail-mode override for \"{name}\", which is not in the \
                 catalogue",
                path.display()
            )));
        }
    }
    Ok(fm)
}

fn read_identity(dir: &Path) -> Result<Option<IdentitySource>, Error> {
    if !dir.is_dir() {
        return Ok(None);
    }

    let provider_path = dir.join("provider.json");
    let jwks_path = dir.join("jwks.json");
    for p in [&provider_path, &jwks_path] {
        if !p.is_file() {
            return Err(Error::Source(format!(
                "identity/ exists but {} is missing: half an identity \
                 configuration verifies nothing",
                p.display()
            )));
        }
    }

    let provider: ProviderFile = serde_json::from_str(&std::fs::read_to_string(&provider_path)?)
        .map_err(|e| Error::Source(format!("{}: {e}", provider_path.display())))?;
    if provider.issuer.is_empty() || provider.audience.is_empty() {
        return Err(Error::Source(format!(
            "{}: issuer and audience must both be set — an empty audience \
             would accept tokens minted for any other service",
            provider_path.display()
        )));
    }

    let jwks: JwkSet = serde_json::from_str(&std::fs::read_to_string(&jwks_path)?)
        .map_err(|e| Error::Source(format!("{}: {e}", jwks_path.display())))?;
    // The same validation the gateway will run: empty set, duplicate kid,
    // malformed or forbidden key (HMAC in a JWKS) are compile errors.
    obsign_identity::KeyStore::from_set(&jwks)
        .map_err(|e| Error::Source(format!("{}: {e}", jwks_path.display())))?;

    Ok(Some(IdentitySource {
        issuer: provider.issuer,
        audience: provider.audience,
        claims: provider.claims.unwrap_or_default(),
        jwks,
    }))
}

/// Reads and validates the active gateway origin keys.
///
/// The same rigour `read_identity` applies to the JWKS, for the same reason:
/// the checks that would otherwise fail at the ledger — a seal key posing as
/// an origin key, a duplicate id, an unusable public key — are compile errors
/// here, where the pull-request author is looking. Enrolling a gateway is
/// committing its public entry to this file; revoking is removing it.
fn read_deployment(dir: &Path) -> Result<Option<Vec<PublicKeyEntry>>, Error> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let path = dir.join("origin-keys.json");
    if !path.is_file() {
        return Err(Error::Source(format!(
            "deployment/ exists but {} is missing: an empty deployment \
             directory enrolls no gateway, which deserves an explicit file",
            path.display()
        )));
    }

    let keys: Vec<PublicKeyEntry> = serde_json::from_str(&std::fs::read_to_string(&path)?)
        .map_err(|e| Error::Source(format!("{}: {e}", path.display())))?;

    let mut seen = HashSet::new();
    for k in &keys {
        if k.role != KeyRole::Origin {
            return Err(Error::Source(format!(
                "{}: key \"{}\" has role \"{}\" — the deployment bundle carries \
                 gateway origin keys only; a sealing key certifying its own \
                 writer is exactly the confusion the two roles prevent",
                path.display(),
                k.key_id,
                k.role.as_str()
            )));
        }
        if !seen.insert(k.key_id.as_str()) {
            return Err(Error::Source(format!(
                "{}: origin key id \"{}\" is declared twice",
                path.display(),
                k.key_id
            )));
        }
        k.to_verifying_key().map_err(|e| {
            Error::Source(format!("{}: key \"{}\" unusable: {e}", path.display(), k.key_id))
        })?;
    }
    Ok(Some(keys))
}

/// Reads the remote-attestation enrollments, if any, and checks each names an
/// enrolled origin key — an attestation for a key the bundle does not carry
/// is a copy-paste slip worth catching in review, not at the verifier.
fn read_attestations(
    dir: &Path,
    origin_keys: Option<&[PublicKeyEntry]>,
) -> Result<Vec<obsign_audit_core::attestation::KeyAttestation>, Error> {
    let path = dir.join("attestation.json");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let atts: Vec<obsign_audit_core::attestation::KeyAttestation> =
        serde_json::from_str(&std::fs::read_to_string(&path)?)
            .map_err(|e| Error::Source(format!("{}: {e}", path.display())))?;

    let enrolled: HashSet<&str> = origin_keys
        .unwrap_or(&[])
        .iter()
        .map(|k| k.key_id.as_str())
        .collect();
    for a in &atts {
        if !enrolled.contains(a.key_id.as_str()) {
            return Err(Error::Source(format!(
                "{}: attestation for \"{}\", which is not an enrolled origin key",
                path.display(),
                a.key_id
            )));
        }
    }
    Ok(atts)
}

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

/// Resolves the commit sha of HEAD for the repository containing `start`.
///
/// Read from the `.git` files directly rather than by shelling out: the
/// control plane must compile on a machine that has a checkout but not
/// necessarily a git binary (a build container, an air-gapped admin host).
/// Handles the three shapes that occur in practice: a `.git` directory, a
/// `.git` file pointing at a worktree gitdir, and refs packed into
/// `packed-refs`.
pub fn git_head(start: &Path) -> Result<String, Error> {
    let GitDirs { gitdir, common, .. } = find_git_dirs(start).ok_or_else(|| {
        Error::NoVersion(format!(
            "{} is not inside a git repository — pass --label to name the \
             version explicitly",
            start.display()
        ))
    })?;

    let mut target = std::fs::read_to_string(gitdir.join("HEAD"))?
        .trim()
        .to_string();

    // Symbolic refs can chain (HEAD -> ref -> ref); bounded, because a cycle
    // in hand-edited files must not hang a build.
    for _ in 0..5 {
        let Some(refname) = target.strip_prefix("ref:").map(str::trim) else {
            if target.len() >= 40 && target.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(target);
            }
            return Err(Error::NoVersion(format!(
                "unrecognised HEAD content: {target:?}"
            )));
        };

        // The refname is joined under the git directory and opened: without
        // this check, a hand-crafted `ref: ../../...` (or an absolute path)
        // in HEAD reads an arbitrary file on the compiling host. Git's own
        // refname rules already forbid these shapes; enforcing the subset
        // that decides path safety is enough here.
        if !is_safe_refname(refname) {
            return Err(Error::NoVersion(format!(
                "HEAD names a ref that escapes the repository: {refname:?}"
            )));
        }

        let loose = common.join(refname);
        if loose.is_file() {
            target = std::fs::read_to_string(&loose)?.trim().to_string();
            continue;
        }

        match packed_ref(&common.join("packed-refs"), refname)? {
            Some(sha) => target = sha,
            None => {
                return Err(Error::NoVersion(format!(
                    "ref {refname} not found (unborn branch?) — commit first, \
                     or pass --label"
                )))
            }
        }
    }
    Err(Error::NoVersion("symbolic ref chain too deep".to_string()))
}

/// Where a repository keeps its state, resolved from a path inside its
/// working tree.
pub(crate) struct GitDirs {
    /// The working-tree root: the directory that contains `.git`. Paths in
    /// the index are relative to it.
    pub root: PathBuf,
    /// Per-worktree state: HEAD, index.
    pub gitdir: PathBuf,
    /// Shared state: refs, packed-refs, config. The same directory as
    /// `gitdir` except in a linked worktree.
    pub common: PathBuf,
}

pub(crate) fn find_git_dirs(start: &Path) -> Option<GitDirs> {
    for dir in start.ancestors() {
        let dot = dir.join(".git");
        if dot.is_dir() {
            return Some(GitDirs {
                root: dir.to_path_buf(),
                gitdir: dot.clone(),
                common: dot,
            });
        }
        if dot.is_file() {
            // Worktree: `.git` is a file `gitdir: <path>`. HEAD lives in
            // that gitdir; refs and packed-refs live in the common dir.
            let content = std::fs::read_to_string(&dot).ok()?;
            let rel = content.strip_prefix("gitdir:")?.trim();
            let gitdir = dir.join(rel);
            let common = match std::fs::read_to_string(gitdir.join("commondir")) {
                Ok(c) => gitdir.join(c.trim()),
                Err(_) => gitdir.clone(),
            };
            return Some(GitDirs {
                root: dir.to_path_buf(),
                gitdir,
                common,
            });
        }
    }
    None
}

fn is_safe_refname(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn packed_ref(path: &Path, refname: &str) -> Result<Option<String>, Error> {
    if !path.is_file() {
        return Ok(None);
    }
    for line in std::fs::read_to_string(path)?.lines() {
        if line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        if let Some((sha, name)) = line.split_once(' ') {
            if name.trim() == refname {
                return Ok(Some(sha.trim().to_string()));
            }
        }
    }
    Ok(None)
}

/// The short form used in version identifiers (`policies@<short>`).
///
/// Twelve characters, like git's own default for large repositories:
/// collisions at that length would already be a problem for the customer's
/// git tooling, and the full sha remains one `git rev-parse` away.
pub fn short_ref(sha: &str) -> &str {
    if sha.len() > 12 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        &sha[..12]
    } else {
        sha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refnames_that_escape_the_git_directory_are_refused() {
        assert!(is_safe_refname("refs/heads/main"));
        assert!(is_safe_refname("refs/heads/feature/x-1.2"));
        assert!(!is_safe_refname(""));
        assert!(!is_safe_refname("/etc/passwd"));
        assert!(!is_safe_refname("refs/../../../etc/passwd"));
        assert!(!is_safe_refname(".."));
        assert!(!is_safe_refname("refs//heads"));
        assert!(!is_safe_refname("refs/./heads"));
        assert!(!is_safe_refname("refs\\heads\\main"));
    }

    #[test]
    fn a_traversal_symref_in_head_is_an_error_not_a_file_read() {
        let dir = std::env::temp_dir().join(format!("obsign-symref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        // A file outside the git directory whose content is a plausible sha:
        // without the refname check, git_head would happily return it.
        std::fs::write(dir.join("secret"), "a".repeat(40)).unwrap();
        std::fs::write(dir.join(".git").join("HEAD"), "ref: ../secret\n").unwrap();

        let err = git_head(&dir).unwrap_err();
        assert!(
            matches!(&err, Error::NoVersion(m) if m.contains("escapes")),
            "expected a refusal, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
