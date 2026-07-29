//! Local write-ahead log, durable before forwarding.
//!
//! The gateway's central trade-off: in high-assurance mode no act may execute
//! without a durable record. But a network round trip to the ledger before
//! every tool call is unacceptable.
//!
//! Hence this WAL: we write and `fsync` locally (tens of microseconds on
//! NVMe) *before* forwarding the call, then ship to the ledger asynchronously
//! in batches. We get durability at the price of an fsync, not an RTT.

use audit_core::{ChainWriter, Hash, Record, GENESIS};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("unreadable record at line {line}: {source}")]
    Corrupt {
        line: usize,
        source: serde_json::Error,
    },

    #[error("inconsistent chain on replay: {0}")]
    BrokenChain(String),
}

/// Append-only log, one JSON record per line.
///
/// JSONL rather than a binary format: during an incident you want to read the
/// log with `tail` on a production machine where you will not be installing a
/// tool. Integrity does not rest on the file format anyway, but on the hash
/// chain carried by the records themselves.
#[derive(Debug)]
pub struct Wal {
    file: File,
    path: PathBuf,
}

impl Wal {
    /// Opens (or creates) the log and replays its contents to rebuild the
    /// chain state.
    ///
    /// Returns the positioned `ChainWriter`: this is the only correct way to
    /// resume after a restart.
    pub fn open(dir: &Path, chain_id: &str) -> Result<(Self, ChainWriter), Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{chain_id}.jsonl"));

        // Whether we are about to create the file dictates whether the
        // directory entry needs to be made durable below.
        let is_new = !path.exists();

        let (records, good_len) = replay(&path)?;

        // A truncated final line means the process died mid-write. The record
        // was never acknowledged to the caller, so the act did not happen: we
        // trim the file rather than carry an invalid line forever.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        if file.metadata()?.len() != good_len {
            file.set_len(good_len)?;
            file.seek(SeekFrom::End(0))?;
        }

        // `append` fsyncs the file's *contents*, but the directory entry that
        // names a freshly created file is a separate piece of metadata: a power
        // cut after the first record is fdatasync'd could still lose the whole
        // file, and with it a record we durably wrote before forwarding the
        // act. With the HTTP transport every session is a new chain file, so
        // this is the first audited call of every session, not a corner case.
        // Persist the new entry once, here, before any record is written.
        if is_new {
            sync_dir(dir)?;
        }

        let writer = match records.last() {
            None => ChainWriter::new(chain_id),
            Some(last) => {
                // Sealing state is not replayed here: on restart everything
                // unsealed is treated as pending and will be sealed on the
                // next pass. A record sealed twice is not a problem, a record
                // never sealed is.
                ChainWriter::resume(chain_id, last.seq + 1, last.hash(), None)
            }
        };

        Ok((Wal { file, path }, writer))
    }

    /// Writes a record and makes it durable.
    ///
    /// The `sync_data` is not negotiable: without it the content stays in the
    /// page cache, and a power cut erases the trace of an act that did happen.
    pub fn append(&mut self, rec: &Record) -> Result<(), Error> {
        let line = serde_json::to_string(rec).expect("serializing a record");
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-reads the whole log (export, verification).
    pub fn read_all(&self) -> Result<Vec<Record>, Error> {
        Ok(replay(&self.path)?.0)
    }
}

/// Read-only replay, for a process that does not own the log (the ledger,
/// an exporter).
///
/// Unlike `Wal::open`, this neither opens the file for append nor trims a
/// truncated tail: a reader must not mutate another process's log. A
/// truncated final line is simply not returned — the gateway never
/// acknowledged that record, so the act it would describe did not happen.
pub fn read(dir: &Path, chain_id: &str) -> Result<Vec<Record>, Error> {
    Ok(replay(&dir.join(format!("{chain_id}.jsonl")))?.0)
}

/// fsync a directory so a newly created entry inside it survives a crash.
///
/// On Unix, fsync of the file only guarantees the file's data; the link that
/// names it in its parent directory is durable only once the directory itself
/// is fsync'd. Opening a directory read-only and syncing it is the portable way
/// to do that.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Re-reads the log and returns the valid records plus the length of the
/// healthy prefix of the file.
fn replay(path: &Path) -> Result<(Vec<Record>, u64), Error> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }

    let total = std::fs::metadata(path)?.len();
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut records: Vec<Record> = Vec::new();
    let mut good_len: u64 = 0;
    let mut expected_prev: Hash = GENESIS;
    let mut expected_seq: Option<u64> = None;

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let raw_len = line.len() as u64 + 1; // +1 for the \n

        let rec: Record = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                // Truncated last line: a normal end of file after a crash.
                // Any other position is genuine corruption.
                if good_len + raw_len >= total {
                    break;
                }
                return Err(Error::Corrupt {
                    line: i + 1,
                    source: e,
                });
            }
        };

        if let Some(exp) = expected_seq {
            if rec.seq != exp {
                return Err(Error::BrokenChain(format!(
                    "expected seq {}, found {} at line {}",
                    exp,
                    rec.seq,
                    i + 1
                )));
            }
        }
        if rec.prev_hash != expected_prev {
            return Err(Error::BrokenChain(format!(
                "broken link at line {} (seq {})",
                i + 1,
                rec.seq
            )));
        }

        expected_prev = rec.hash();
        expected_seq = Some(rec.seq + 1);
        good_len += raw_len;
        records.push(rec);
    }

    Ok((records, good_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use audit_core::record::{Effect, EffectStatus, Payload};

    fn payload(n: u64) -> Payload {
        Payload::Effect(Effect {
            status: EffectStatus::Ok,
            result_hash: None,
            latency_ms: n,
        })
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wal-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn replay_resumes_the_chain_at_the_right_place() {
        let dir = tmpdir("resume");
        let (mut wal, mut chain) = Wal::open(&dir, "c1").unwrap();
        for i in 0..3 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
            wal.append(&r).unwrap();
        }
        let head = chain.head();
        drop(wal);

        // Restart.
        let (wal2, chain2) = Wal::open(&dir, "c1").unwrap();
        assert_eq!(chain2.next_seq(), 3, "the sequence must continue");
        assert_eq!(chain2.head(), head, "the head must be recovered");
        assert_eq!(wal2.read_all().unwrap().len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_chain_file_is_named_in_its_directory_at_open() {
        // The durability fix: opening a fresh chain creates the file and syncs
        // its directory entry before any record is written, so the first
        // audited call of a session cannot be lost to an unsynced dirent. We
        // cannot observe the fsync, but we can pin that the entry exists at
        // open time and that both the new-file and reopen paths stay sound.
        let dir = tmpdir("newfile");
        {
            let (_wal, _chain) = Wal::open(&dir, "fresh").unwrap();
            assert!(
                dir.join("fresh.jsonl").exists(),
                "the chain file must be created and named at open"
            );
        }
        // Reopen: the existing-file path must not error either.
        let (_wal, chain) = Wal::open(&dir, "fresh").unwrap();
        assert_eq!(chain.next_seq(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_final_line_is_trimmed() {
        // Simulates a power cut mid-write.
        let dir = tmpdir("truncated");
        let (mut wal, mut chain) = Wal::open(&dir, "c1").unwrap();
        for i in 0..2 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
            wal.append(&r).unwrap();
        }
        let path = wal.path().to_path_buf();
        drop(wal);

        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":2,\"ts_ms\":0,\"prev_ha").unwrap();
        drop(f);

        let (wal2, chain2) = Wal::open(&dir, "c1").unwrap();
        assert_eq!(chain2.next_seq(), 2, "the partial write is ignored");
        assert_eq!(wal2.read_all().unwrap().len(), 2);

        // And the file really was trimmed: writing can resume without leaving
        // an invalid line in the middle of the log.
        let mut wal2 = wal2;
        let mut chain2 = chain2;
        let r = chain2.append(9, "r2", None, "s", payload(9));
        wal2.append(&r).unwrap();
        assert_eq!(wal2.read_all().unwrap().len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_only_access_sees_the_log_without_touching_it() {
        let dir = tmpdir("readonly");
        let (mut wal, mut chain) = Wal::open(&dir, "c1").unwrap();
        for i in 0..2 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
            wal.append(&r).unwrap();
        }
        let path = wal.path().to_path_buf();
        drop(wal);

        // Simulated crash mid-write by the owning process.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":2,\"ts_m").unwrap();
        drop(f);
        let len_before = std::fs::metadata(&path).unwrap().len();

        let records = read(&dir, "c1").unwrap();
        assert_eq!(records.len(), 2, "the unacknowledged tail is not returned");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len_before,
            "a reader must not trim a log it does not own"
        );

        // And a missing chain reads as empty, without creating the file.
        assert!(read(&dir, "absent").unwrap().is_empty());
        assert!(!dir.join("absent.jsonl").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_tampering_is_detected_on_replay() {
        let dir = tmpdir("tamper");
        let (mut wal, mut chain) = Wal::open(&dir, "c1").unwrap();
        for i in 0..3 {
            let r = chain.append(i as i64, format!("r{i}"), None, "s", payload(i));
            wal.append(&r).unwrap();
        }
        let path = wal.path().to_path_buf();
        drop(wal);

        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines[1] = lines[1].replace("\"latency_ms\":1", "\"latency_ms\":999");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = Wal::open(&dir, "c1").unwrap_err();
        assert!(
            matches!(err, Error::BrokenChain(_)),
            "expected BrokenChain, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
