//! Read-only console: what the log looks like to the operator.
//!
//! Server-rendered HTML on `std::net`, no JavaScript, no template engine —
//! three pages assembled by hand. Same reasoning as the gateway's HTTP
//! transport: the subset needed here (GET, three routes) is smaller than any
//! framework's dependency tree, and that tree is part of the product.
//!
//! Read-only **by construction**: the only accepted method is GET and no
//! handler writes anything. The console can therefore never become a second
//! write path around git — rules change through a reviewed commit and
//! `probant-control publish`, or not at all.
//!
//! Everything is re-read from disk on every request. No cache to invalidate,
//! and what the console shows is what the files say *now* — the same property
//! the gateway's hot reload relies on. These are admin pages over directory
//! listings; if serving them ever needs a cache, something else went wrong.
//!
//! Authentication is deliberately absent from the core console: bind it to
//! localhost (the default) or an admin network. SSO/RBAC belongs to the
//! commercial layer.

use audit_core::checkpoint::PublicKeyEntry;
use audit_core::record::{Payload, Record};
use ledger::Store;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::export::list_chains;
use crate::release::SignedManifest;
use crate::Error;

/// Ceiling on request head bytes. Above this, nobody is browsing.
const MAX_HEAD_BYTES: u64 = 8 * 1024;

/// Deadline on every socket read and write. One thread per connection is
/// fine for an admin page, but only if a client that stops mid-request
/// releases its thread instead of holding it forever.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Records shown on a chain page. Not a silent cap: the page says when it
/// truncates and points at `export` for the full log.
const MAX_ROWS: usize = 500;

pub struct Console {
    pub wal_dir: PathBuf,
    /// Ledger store. Without it the console still lists chains and records,
    /// but shows no sealing state.
    pub store_dir: Option<PathBuf>,
    /// Distribution directory, for the release page.
    pub dist_dir: Option<PathBuf>,
}

impl Console {
    pub fn serve(self, addr: &str) -> Result<(), Error> {
        let listener = TcpListener::bind(addr)?;
        eprintln!(
            "[control] console on http://{}/ — read-only",
            listener.local_addr()?
        );
        self.serve_on(listener)
    }

    /// Serves on an already-bound listener (tests bind port 0 themselves).
    pub fn serve_on(self, listener: TcpListener) -> Result<(), Error> {
        let console = Arc::new(self);
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let console = Arc::clone(&console);
            std::thread::spawn(move || {
                let _ = handle(&console, stream);
            });
        }
        Ok(())
    }
}

/// One request per connection. Keep-alive buys nothing on an admin page and
/// the close is what makes the hand-written test client trivial.
fn handle(console: &Console, stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    // The cap sits under the reader, so it bounds the request line too:
    // `read_line` otherwise buffers a newline-less line without limit, and an
    // unbounded allocation driven by the peer is a one-connection DoS.
    let mut reader = BufReader::new(stream.try_clone()?.take(MAX_HEAD_BYTES));
    let mut stream = stream;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.ends_with('\n') {
        // The cap was hit mid-line, or the client hung up before finishing
        // its request line. Neither is a request to serve.
        return respond(&mut stream, 431, "Request Header Fields Too Large", "text/plain", b"");
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return respond(&mut stream, 400, "Bad Request", "text/plain", b"malformed request");
    };
    let method = method.to_string();
    let path = target.split('?').next().unwrap_or(target).to_string();

    // Drain headers; their content is irrelevant to a GET-only server. EOF
    // before the blank line means the head was truncated by the cap above.
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            return respond(&mut stream, 431, "Request Header Fields Too Large", "text/plain", b"");
        }
        if h.trim_end().is_empty() {
            break;
        }
    }

    if method != "GET" {
        return respond(&mut stream, 405, "Method Not Allowed", "text/plain", b"read-only console: GET only");
    }

    let page = match path.as_str() {
        "/" => overview(console),
        "/release" => release_page(console),
        p => match p.strip_prefix("/chain/") {
            Some(id) if is_safe_chain_id(id) => chain_page(console, id),
            // The id feeds a file-name join: anything outside this alphabet
            // is a traversal attempt, not a chain.
            _ => None,
        },
    };

    match page {
        Some(html) => respond(&mut stream, 200, "OK", "text/html; charset=utf-8", html.as_bytes()),
        None => respond(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}

fn is_safe_chain_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.contains("..")
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// Per-chain state assembled for display. Every failure mode becomes a
/// visible status string: a console that hides a broken store behind a blank
/// cell defeats its purpose.
struct ChainRow {
    id: String,
    records: usize,
    last_seq: Option<u64>,
    sealed_to: Option<u64>,
    checkpoints: usize,
    anchors: usize,
    status: String,
    ok: bool,
}

fn chain_row(console: &Console, id: &str) -> ChainRow {
    let records = match wal::read(&console.wal_dir, id) {
        Ok(r) => r,
        Err(e) => {
            return ChainRow {
                id: id.to_string(),
                records: 0,
                last_seq: None,
                sealed_to: None,
                checkpoints: 0,
                anchors: 0,
                status: format!("log unreadable: {e}"),
                ok: false,
            }
        }
    };
    let last_seq = records.last().map(|r| r.seq);

    let store = match &console.store_dir {
        Some(dir) if dir.is_dir() => match Store::open(dir, id) {
            Ok(s) => Some(s),
            Err(e) => {
                return ChainRow {
                    id: id.to_string(),
                    records: records.len(),
                    last_seq,
                    sealed_to: None,
                    checkpoints: 0,
                    anchors: 0,
                    status: format!("store broken: {e}"),
                    ok: false,
                }
            }
        },
        _ => None,
    };

    match store {
        None => ChainRow {
            id: id.to_string(),
            records: records.len(),
            last_seq,
            sealed_to: None,
            checkpoints: 0,
            anchors: 0,
            status: "no store configured".to_string(),
            ok: true,
        },
        Some(store) => {
            let trusted = store.keys().to_vec();
            let sealed_to = store.last().map(|sc| sc.checkpoint.to_seq);
            let checkpoints = store.checkpoints().len();
            let anchors = store.anchors().len();
            let evidence = ledger::export(records, &store);
            let report = audit_core::evidence::verify(&evidence, &trusted);
            let ok = report.is_valid();
            let status = if ok {
                format!("intact — {}/{} sealed", report.records_sealed, report.records_total)
            } else {
                let first = report
                    .errors()
                    .next()
                    .map(|f| f.code.clone())
                    .unwrap_or_default();
                format!("INVALID: {first}")
            };
            ChainRow {
                id: id.to_string(),
                records: report.records_total,
                last_seq,
                sealed_to,
                checkpoints,
                anchors,
                status,
                ok,
            }
        }
    }
}

fn overview(console: &Console) -> Option<String> {
    let mut body = String::new();

    body.push_str("<h2>Release</h2>");
    match &console.dist_dir {
        None => body.push_str("<p class=\"mut\">no distribution directory configured</p>"),
        Some(dist) => body.push_str(&release_summary(dist)),
    }

    body.push_str("<h2>Chains</h2>");
    match list_chains(&console.wal_dir) {
        Err(e) => {
            let _ = write!(body, "<p class=\"bad\">{}</p>", esc(&e.to_string()));
        }
        Ok(chains) if chains.is_empty() => {
            body.push_str("<p class=\"mut\">no chain in the log directory</p>");
        }
        Ok(chains) => {
            body.push_str(
                "<table><tr><th>chain</th><th>records</th><th>last seq</th>\
                 <th>sealed to</th><th>checkpoints</th><th>anchors</th>\
                 <th>status</th></tr>",
            );
            for id in chains {
                let row = chain_row(console, &id);
                let _ = write!(
                    body,
                    "<tr><td><a href=\"/chain/{id}\">{id}</a></td><td>{}</td>\
                     <td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                     <td class=\"{}\">{}</td></tr>",
                    row.records,
                    opt(row.last_seq),
                    opt(row.sealed_to),
                    row.checkpoints,
                    row.anchors,
                    if row.ok { "ok" } else { "bad" },
                    esc(&row.status),
                    id = esc(&row.id),
                );
            }
            body.push_str("</table>");
        }
    }

    Some(page("Probant — control plane", &body))
}

fn release_summary(dist: &Path) -> String {
    let manifest_path = dist.join("manifest.json");
    if !manifest_path.is_file() {
        return "<p class=\"mut\">nothing published yet</p>".to_string();
    }
    let parsed: Result<SignedManifest, _> = std::fs::read_to_string(&manifest_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()));
    let signed = match parsed {
        Ok(s) => s,
        Err(e) => return format!("<p class=\"bad\">manifest unreadable: {}</p>", esc(&e)),
    };

    // Verified against the published trusted keys — and the outcome is shown
    // either way. An unverifiable current release is front-page news.
    let verdict = match load_keys(&dist.join("trusted-keys.json"))
        .iter()
        .find(|k| k.key_id == signed.key_id)
    {
        None => format!(
            "<span class=\"bad\">signed with unknown key \"{}\"</span>",
            esc(&signed.key_id)
        ),
        Some(entry) => match entry
            .to_verifying_key()
            .map_err(Error::from)
            .and_then(|vk| signed.verify(&vk).map(|_| ()))
        {
            Ok(()) => format!(
                "<span class=\"ok\">signature valid (key {})</span>",
                esc(&signed.key_id)
            ),
            Err(e) => format!("<span class=\"bad\">signature INVALID: {}</span>", esc(&e.to_string())),
        },
    };

    let m = &signed.manifest;
    let mut out = format!(
        "<p>version <code>{}</code> — published {} — {} — \
         <a href=\"/release\">details</a></p><table>\
         <tr><th>artifact</th><th>sha256</th></tr>",
        esc(&m.version),
        fmt_utc(m.ts_ms),
        verdict
    );
    for a in &m.artifacts {
        let _ = write!(
            out,
            "<tr><td>{}</td><td><code>{}</code></td></tr>",
            esc(&a.name),
            a.sha256
        );
    }
    out.push_str("</table>");
    out
}

fn load_keys(path: &Path) -> Vec<PublicKeyEntry> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn release_page(console: &Console) -> Option<String> {
    let dist = console.dist_dir.as_ref()?;
    let mut body = release_summary(dist);

    let bundle_path = dist.join("policy-bundle.json");
    if let Ok(raw) = std::fs::read_to_string(&bundle_path) {
        match serde_json::from_str::<policy::SignedBundle>(&raw) {
            Err(e) => {
                let _ = write!(
                    body,
                    "<h2>Policy bundle</h2><p class=\"bad\">unreadable: {}</p>",
                    esc(&e.to_string())
                );
            }
            Ok(signed) => {
                let b = &signed.bundle;
                let _ = write!(
                    body,
                    "<h2>Policy bundle <code>{}</code></h2>\
                     <h3>Tool catalogue</h3><table>\
                     <tr><th>tool</th><th>server</th><th>destructive</th>\
                     <th>required scope</th><th>on failure</th></tr>",
                    esc(&b.version)
                );
                for t in &b.tools {
                    let _ = write!(
                        body,
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td></tr>",
                        esc(&t.name),
                        esc(&t.server),
                        if t.destructive { "yes" } else { "no" },
                        esc(t.required_scope.as_deref().unwrap_or("—")),
                        b.fail_mode.for_tool(&t.name),
                    );
                }
                let _ = write!(
                    body,
                    "</table><h3>Rules (Cedar, verbatim)</h3><pre>{}</pre>",
                    esc(&b.cedar)
                );
            }
        }
    }

    if let Ok(raw) = std::fs::read_to_string(dist.join("identity-bundle.json")) {
        if let Ok(signed) = serde_json::from_str::<identity::SignedIdentityBundle>(&raw) {
            let b = &signed.bundle;
            let kids: Vec<String> = b.jwks.keys.iter().map(|k| esc(&k.kid)).collect();
            let _ = write!(
                body,
                "<h2>Identity bundle <code>{}</code></h2>\
                 <p>issuer <code>{}</code> — audience <code>{}</code> — \
                 {} key(s): {}</p>",
                esc(&b.version),
                esc(&b.issuer),
                esc(&b.audience),
                b.jwks.keys.len(),
                kids.join(", ")
            );
        }
    }

    Some(page("Release", &body))
}

fn chain_page(console: &Console, id: &str) -> Option<String> {
    let records = wal::read(&console.wal_dir, id).ok()?;
    if records.is_empty() && !console.wal_dir.join(format!("{id}.jsonl")).exists() {
        return None;
    }

    let row = chain_row(console, id);
    let mut body = format!(
        "<p><a href=\"/\">&larr; overview</a></p>\
         <p>{} record(s) — sealed to {} — {} checkpoint(s), {} anchor(s) — \
         <span class=\"{}\">{}</span></p>",
        row.records,
        opt(row.sealed_to),
        row.checkpoints,
        row.anchors,
        if row.ok { "ok" } else { "bad" },
        esc(&row.status)
    );

    let shown = if records.len() > MAX_ROWS {
        let _ = write!(
            body,
            "<p class=\"mut\">showing the last {MAX_ROWS} of {} records — \
             run <code>probant-control export</code> for the full log</p>",
            records.len()
        );
        &records[records.len() - MAX_ROWS..]
    } else {
        &records[..]
    };

    body.push_str(
        "<table><tr><th>seq</th><th>time (UTC)</th><th>id</th>\
         <th>kind</th><th>summary</th></tr>",
    );
    for rec in shown {
        let _ = write!(
            body,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            rec.seq,
            fmt_utc(rec.ts_ms),
            esc(&rec.id),
            kind(rec),
            summary(rec),
        );
    }
    body.push_str("</table>");

    Some(page(&format!("Chain {id}"), &body))
}

fn kind(rec: &Record) -> &'static str {
    match rec.payload {
        Payload::Delegation(_) => "delegation",
        Payload::Actor(_) => "actor",
        Payload::AgentSession(_) => "agent_session",
        Payload::LlmTurn(_) => "llm_turn",
        Payload::ToolCall(_) => "tool_call",
        Payload::Decision(_) => "decision",
        Payload::Effect(_) => "effect",
        Payload::ConfigReload(_) => "config_reload",
    }
}

fn summary(rec: &Record) -> String {
    match &rec.payload {
        Payload::Delegation(d) => format!(
            "{} iss={} — expires {}",
            esc(&d.principal_sub),
            esc(&d.principal_issuer),
            fmt_utc(d.expires_at_ms)
        ),
        Payload::Actor(a) => format!(
            "{} [{}]",
            esc(&a.chain.join(" → ")),
            a.principal_kind.as_str()
        ),
        Payload::AgentSession(a) => esc(&a.agent_id),
        Payload::LlmTurn(t) => format!("{} / {}", esc(&t.provider), esc(&t.model)),
        Payload::ToolCall(c) => format!("{} @ {}", esc(&c.tool), esc(&c.server)),
        Payload::Decision(d) => {
            let mut s = format!("<b>{}</b>", d.outcome.as_str().to_uppercase());
            if let Some(p) = &d.policy_id {
                let _ = write!(s, " &lt;{}&gt;", esc(p));
            }
            if let Some(r) = &d.reason {
                let _ = write!(s, " — {}", esc(r));
            }
            s
        }
        Payload::Effect(x) => format!("{} ({} ms)", x.status.as_str(), x.latency_ms),
        Payload::ConfigReload(c) => {
            let mut s = format!(
                "<b>{}</b> {} — in force: {}",
                match c.status {
                    audit_core::record::ReloadStatus::Applied => "applied",
                    audit_core::record::ReloadStatus::Rejected => "REJECTED",
                },
                c.config_kind.as_str(),
                esc(&c.bundle_version),
            );
            if let Some(r) = &c.reason {
                let _ = write!(s, " — {}", esc(r));
            }
            s
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn opt(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "—".to_string())
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>{t}</title><style>\
         body{{font:14px/1.5 -apple-system,system-ui,sans-serif;margin:2rem auto;\
         max-width:72rem;padding:0 1rem;color:#1a1a1a}}\
         table{{border-collapse:collapse;width:100%;margin:.5rem 0}}\
         th,td{{border:1px solid #ddd;padding:.3rem .6rem;text-align:left;\
         vertical-align:top}}th{{background:#f5f5f5}}\
         code,pre{{font:12px/1.5 ui-monospace,monospace;background:#f5f5f5}}\
         pre{{padding:.8rem;overflow:auto}}\
         .ok{{color:#166534}}.bad{{color:#b91c1c;font-weight:600}}\
         .mut{{color:#777}}a{{color:#1d4ed8}}\
         </style></head><body><h1>{t}</h1>{body}\
         <p class=\"mut\">read-only console — rules change through git and \
         <code>probant-control publish</code>, not here</p></body></html>",
        t = esc(title),
    )
}

/// Epoch milliseconds to `YYYY-MM-DD HH:MM:SSZ`, by hand.
///
/// Fifteen lines of civil-calendar arithmetic (Howard Hinnant's
/// `civil_from_days`) instead of a chrono dependency nobody audits for a
/// timestamp column.
fn fmt_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);

    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting_matches_known_dates() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00Z");
        // 2026-07-29 00:00:00 UTC
        assert_eq!(fmt_utc(1_785_283_200_000), "2026-07-29 00:00:00Z");
        // Leap day.
        assert_eq!(fmt_utc(1_709_164_800_000), "2024-02-29 00:00:00Z");
    }

    #[test]
    fn chain_ids_that_escape_the_wal_directory_are_refused() {
        assert!(is_safe_chain_id("demo-abc123"));
        assert!(!is_safe_chain_id("../etc/passwd"));
        assert!(!is_safe_chain_id("a/b"));
        assert!(!is_safe_chain_id(""));
        assert!(!is_safe_chain_id("a..b"));
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(esc("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#39;");
    }
}
