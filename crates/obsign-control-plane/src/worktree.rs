//! Clean-tree verification: the working tree must match the commit whose
//! sha the bundle version is about to cite.
//!
//! `compile` signs bytes read from disk and stamps them `policies@<sha>`,
//! where `<sha>` comes from `.git/HEAD`. Nothing ties the two together: an
//! edited-but-uncommitted rule would be signed under a commit that does not
//! contain it, and every decision in the log would cite a version that lies
//! to the auditor replaying it. This module is the missing tie. It runs on
//! the sha path only. An explicit `--label` names the build without citing a
//! commit, and skips it.
//!
//! Like [`git_head`](crate::source::git_head), it reads `.git` directly: the
//! control plane must compile where there is a checkout but no git binary.
//! Comparing against the *commit* itself would mean reading the object store
//! (zlib, packfiles, deltas); the index gives almost all of it without that:
//!
//! * every working file the compilation reads is content-hashed and compared
//!   to its index entry, so edits, deletions and untracked additions are
//!   caught exactly, whatever the stat data says (an rsync'ed checkout, with
//!   its fresh mtimes, hashes the same);
//! * an invalidated cache-tree entry in the index means `git add` ran with
//!   no commit after it; staged-but-uncommitted state is caught too.
//!
//! Accepted blind spots, for the record: a `git reset --soft` (index and
//! tree agree, HEAD points elsewhere) passes, because telling that apart
//! needs the object store; a mode-only change (chmod +x) passes, because the
//! compiled bytes do not depend on it; and a checkout using content filters
//! (autocrlf, clean/smudge) reads as diverged, because the blob and the
//! working file legitimately differ. `--label` is the escape hatch there.

use std::collections::HashSet;
use std::path::Path;

use crate::source::find_git_dirs;
use crate::Error;

/// Every way the working tree diverges from what the index (and, through the
/// cache tree, the last commit) holds for the files `compile` reads.
/// Empty means clean. Each entry names the path and the nature of the lie,
/// ready to be printed as a refusal.
pub fn worktree_divergence(source_root: &Path) -> Result<Vec<String>, Error> {
    let dirs = find_git_dirs(source_root).ok_or_else(|| {
        Error::NoVersion(format!(
            "{} is not inside a git repository — pass --label to name the \
             version explicitly",
            source_root.display()
        ))
    })?;

    let index_path = dirs.gitdir.join("index");
    let bytes = std::fs::read(&index_path).map_err(|e| {
        Error::Source(format!(
            "{}: {e} — a checkout without an index cannot be verified \
             against HEAD; pass --label",
            index_path.display()
        ))
    })?;
    let oid_len = object_id_len(&dirs.common);
    let index = parse_index(&bytes, oid_len)?;

    // Index paths are '/'-separated and relative to the working-tree root;
    // the source tree may sit in a subdirectory of the repository.
    let rel = source_root.strip_prefix(&dirs.root).unwrap_or(source_root);
    let mut prefix = String::new();
    for c in rel.components() {
        if let std::path::Component::Normal(s) = c {
            prefix.push_str(&s.to_string_lossy());
            prefix.push('/');
        }
    }
    // The generated Cedar schema lives beside the rules but is not one of
    // them: `read_cedar` takes only `*.cedar`, so its bytes provably never
    // reach the signed bundle. Refusing to stamp a sha because a *derived*
    // file is uncommitted would fail the documented sequence, regenerate
    // the schema after a catalogue change, then compile, over something the
    // compilation does not read. `compile` derives the model from
    // `tools.json` itself and never trusts this file.
    let generated_schema = format!("policies/{}", obsign_policy::SCHEMA_FILE);

    let in_scope = |p: &str| match p.strip_prefix(&prefix) {
        None => false,
        Some(rest) => {
            rest != generated_schema
                && (rest == "tools.json"
                    || rest == "fail-mode.json"
                    || rest.starts_with("policies/")
                    || rest.starts_with("identity/"))
        }
    };

    let mut divergence = Vec::new();

    // Index -> disk: every tracked file in scope must exist with exactly the
    // bytes the index holds. Tracked-but-unread files (a policies/README)
    // are checked too: `git describe --dirty` would call their modification
    // dirty, and so does the operator reading the refusal.
    let mut tracked: HashSet<&str> = HashSet::new();
    for e in &index.entries {
        if !in_scope(&e.path) {
            continue;
        }
        tracked.insert(e.path.as_str());
        if e.stage != 0 {
            divergence.push(format!("{}: unmerged (conflict in progress)", e.path));
            continue;
        }
        if e.intent_to_add {
            divergence.push(format!(
                "{}: added with --intent-to-add, never committed",
                e.path
            ));
            continue;
        }
        if e.mode >> 12 != 0o10 {
            // A symlink or a submodule where a policy file should be:
            // neither can be content-checked against its blob, and neither
            // is something `compile` should read through silently.
            divergence.push(format!("{}: not a regular file in the index", e.path));
            continue;
        }
        match std::fs::read(dirs.root.join(&e.path)) {
            Err(_) => divergence.push(format!(
                "{}: tracked but missing from the working tree",
                e.path
            )),
            Ok(content) => {
                if blob_oid(&content, oid_len)? != e.oid {
                    divergence.push(format!("{}: modified and not committed", e.path));
                }
            }
        }
    }

    // Disk -> index: every file the compilation reads must be tracked. A
    // stray file `compile` never reads (a .DS_Store in policies/) is not
    // divergence. The citation stays honest without it.
    for path in compiled_inputs(source_root, &prefix)? {
        if !tracked.contains(path.as_str()) {
            divergence.push(format!("{path}: read by compile but not tracked in git"));
        }
    }

    if index.cache_tree_stale {
        divergence
            .push("the index carries staged, uncommitted changes (stale cache tree)".to_string());
    }
    Ok(divergence)
}

/// The files `SourceTree::load` reads, as index-style paths. Deliberately
/// re-enumerated from disk rather than taken from a loaded `SourceTree`,
/// with the same scoping (`policies/*.cedar` at the top level, the two
/// catalogues, the identity pair): this is the read whose bytes are about to
/// be signed.
fn compiled_inputs(source_root: &Path, prefix: &str) -> Result<Vec<String>, Error> {
    let mut inputs = Vec::new();
    let policies = source_root.join("policies");
    if policies.is_dir() {
        for entry in std::fs::read_dir(&policies)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".cedar") && entry.file_type()?.is_file() {
                inputs.push(format!("{prefix}policies/{name}"));
            }
        }
    }
    for name in ["tools.json", "fail-mode.json"] {
        if source_root.join(name).is_file() {
            inputs.push(format!("{prefix}{name}"));
        }
    }
    for name in ["identity/provider.json", "identity/jwks.json"] {
        if source_root.join(name).is_file() {
            inputs.push(format!("{prefix}{name}"));
        }
    }
    inputs.sort();
    Ok(inputs)
}

// ---------------------------------------------------------------------------
// Object ids
// ---------------------------------------------------------------------------

/// The object id git would give `content` as a blob (`git hash-object`
/// without the git binary). `oid_len` selects the repository's object format:
/// 20 for SHA-1, 32 for SHA-256.
pub fn blob_oid(content: &[u8], oid_len: usize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(content.len() + 16);
    buf.extend_from_slice(format!("blob {}\0", content.len()).as_bytes());
    buf.extend_from_slice(content);
    match oid_len {
        20 => Ok(sha1(&buf).to_vec()),
        32 => {
            use sha2::{Digest, Sha256};
            Ok(Sha256::digest(&buf).to_vec())
        }
        n => Err(Error::Source(format!(
            ".git/index: unsupported object id length {n}"
        ))),
    }
}

/// 20 unless the repository config says `objectFormat = sha256`. The key is
/// only legal under `[extensions]`, so matching it alone is enough. A wrong
/// guess cannot accept a diverged tree, only mis-parse the index into a
/// refusal.
fn object_id_len(common: &Path) -> usize {
    let Ok(cfg) = std::fs::read_to_string(common.join("config")) else {
        return 20;
    };
    for line in cfg.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            if k.trim().eq_ignore_ascii_case("objectformat")
                && v.trim().eq_ignore_ascii_case("sha256")
            {
                return 32;
            }
        }
    }
    20
}

/// SHA-1, exactly RFC 3174. Hand-rolled because nothing else in the
/// workspace needs it and a dependency for forty lines is a poor trade.
/// It authenticates nothing: both the hash and the bytes come from the
/// operator's own disk, so collision resistance is not relied on; equality
/// with git's own arithmetic is.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Index file
// ---------------------------------------------------------------------------

struct IndexEntry {
    /// '/'-separated, relative to the working-tree root.
    path: String,
    oid: Vec<u8>,
    mode: u32,
    stage: u8,
    intent_to_add: bool,
}

struct Index {
    entries: Vec<IndexEntry>,
    cache_tree_stale: bool,
}

/// Parses `.git/index` versions 2 to 4, the shapes git writes today.
///
/// The trailing checksum is not verified: whoever can corrupt the index can
/// also recompute its checksum, so it proves nothing here, and a garbled
/// file fails the structural checks below instead.
fn parse_index(b: &[u8], oid_len: usize) -> Result<Index, Error> {
    let corrupt = |what: &str| Error::Source(format!(".git/index: {what}"));

    if b.len() < 12 + oid_len || &b[..4] != b"DIRC" {
        return Err(corrupt("not an index file"));
    }
    let version = u32::from_be_bytes(b[4..8].try_into().unwrap());
    if !(2..=4).contains(&version) {
        return Err(corrupt(&format!("unsupported index version {version}")));
    }
    let count = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
    let end = b.len() - oid_len; // trailing checksum

    let mut entries = Vec::with_capacity(count);
    let mut prev_path: Vec<u8> = Vec::new();
    let mut off = 12usize;
    for _ in 0..count {
        let start = off;
        let fixed = 40 + oid_len + 2;
        if off + fixed > end {
            return Err(corrupt("truncated entry"));
        }
        let mode = u32::from_be_bytes(b[off + 24..off + 28].try_into().unwrap());
        let oid = b[off + 40..off + 40 + oid_len].to_vec();
        let flags = u16::from_be_bytes(
            b[off + 40 + oid_len..off + 42 + oid_len]
                .try_into()
                .unwrap(),
        );
        off += fixed;

        let stage = ((flags >> 12) & 0x3) as u8;
        let mut intent_to_add = false;
        if flags & 0x4000 != 0 {
            // Extended entry: one more u16 of flags. Skip-worktree (sparse
            // checkout) needs no special case. If the file is absent, the
            // content check reports it, which is the honest verdict for a
            // file the compilation would fail to read anyway.
            if version < 3 {
                return Err(corrupt("extended entry in a v2 index"));
            }
            if off + 2 > end {
                return Err(corrupt("truncated entry"));
            }
            intent_to_add = u16::from_be_bytes(b[off..off + 2].try_into().unwrap()) & 0x2000 != 0;
            off += 2;
        }

        let path: Vec<u8> = if version == 4 {
            // Prefix-compressed: strip N bytes off the previous path, append
            // a NUL-terminated suffix. No padding.
            let (strip, next) = read_varint(&b[..end], off).ok_or_else(|| corrupt("bad varint"))?;
            off = next;
            let nul = b[off..end]
                .iter()
                .position(|&c| c == 0)
                .ok_or_else(|| corrupt("unterminated path"))?;
            let keep = prev_path
                .len()
                .checked_sub(strip as usize)
                .ok_or_else(|| corrupt("bad prefix length"))?;
            let mut p = prev_path[..keep].to_vec();
            p.extend_from_slice(&b[off..off + nul]);
            off += nul + 1;
            p
        } else {
            let nul = b[off..end]
                .iter()
                .position(|&c| c == 0)
                .ok_or_else(|| corrupt("unterminated path"))?;
            let p = b[off..off + nul].to_vec();
            // NUL-terminated, then NUL-padded to a multiple of eight bytes
            // from the start of the entry, git's ce_size formula.
            off = start + ((off - start + nul + 8) & !7);
            if off > end {
                return Err(corrupt("truncated entry"));
            }
            p
        };

        entries.push(IndexEntry {
            path: String::from_utf8_lossy(&path).into_owned(),
            oid,
            mode,
            stage,
            intent_to_add,
        });
        prev_path = path;
    }

    let mut cache_tree_stale = false;
    while off < end {
        if off + 8 > end {
            return Err(corrupt("truncated extension"));
        }
        let name = &b[off..off + 4];
        let size = u32::from_be_bytes(b[off + 4..off + 8].try_into().unwrap()) as usize;
        off += 8;
        if off + size > end {
            return Err(corrupt("truncated extension"));
        }
        let data = &b[off..off + size];
        off += size;
        match name {
            b"TREE" => cache_tree_stale = cache_tree_has_invalidated_entry(data, oid_len)?,
            // An extension whose name starts with a capital letter may be
            // ignored, says the format. A lowercase one changes the meaning
            // of what precedes it (split index, sparse directories): the
            // entry list just read may not be the whole truth, and half an
            // index must not certify a clean tree.
            _ if name[0].is_ascii_uppercase() => {}
            _ => {
                return Err(Error::Source(format!(
                    ".git/index: mandatory extension \"{}\" is not supported \
                     — this index cannot be verified against the working \
                     tree; disable the feature writing it (core.splitIndex, \
                     index.sparse) or pass --label",
                    String::from_utf8_lossy(name)
                )))
            }
        }
    }

    Ok(Index {
        entries,
        cache_tree_stale,
    })
}

/// A cache-tree entry with a negative count was invalidated by `git add` or
/// `git rm` and no commit re-validated it: the index carries staged state
/// HEAD does not have. `git describe --dirty` calls this dirty for the same
/// reason, anywhere in the repository. Attribution to a path is not possible
/// without the object store, so neither is attempted.
fn cache_tree_has_invalidated_entry(data: &[u8], oid_len: usize) -> Result<bool, Error> {
    let corrupt = || Error::Source(".git/index: corrupt TREE extension".to_string());
    let mut i = 0usize;
    while i < data.len() {
        let nul = data[i..].iter().position(|&c| c == 0).ok_or_else(corrupt)?;
        i += nul + 1;
        let sp = data[i..]
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(corrupt)?;
        let count: i64 = std::str::from_utf8(&data[i..i + sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(corrupt)?;
        i += sp + 1;
        let nl = data[i..]
            .iter()
            .position(|&c| c == b'\n')
            .ok_or_else(corrupt)?;
        i += nl + 1;
        if count < 0 {
            return Ok(true);
        }
        i += oid_len;
        if i > data.len() {
            return Err(corrupt());
        }
    }
    Ok(false)
}

/// Git's variable-length integer (varint.c): seven bits per byte, high bit
/// continues, each continuation adds one before shifting.
fn read_varint(b: &[u8], mut off: usize) -> Option<(u64, usize)> {
    let mut c = *b.get(off)?;
    off += 1;
    let mut v = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if v >= 1 << 25 {
            return None; // no path is that long; a loop of 0x80s must not spin
        }
        c = *b.get(off)?;
        off += 1;
        v = ((v + 1) << 7) | (c & 0x7f) as u64;
    }
    Some((v, off))
}
