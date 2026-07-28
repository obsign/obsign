use crate::sealer::{sign_checkpoint, Sealer};
use crate::store::Store;
use crate::Error;
use audit_core::checkpoint::{seal_interval, SignedCheckpoint};
use audit_core::evidence::{Evidence, FORMAT};
use audit_core::record::Record;

/// One sealing pass: seal everything the log holds beyond sealed history.
///
/// `records` comes from `wal::read`, which already validated the chain's
/// internal consistency. What it cannot validate — and what this function
/// exists to catch — is consistency with *sealed history*: a compromised
/// gateway host can rewrite the WAL and recompute every hash, producing a
/// perfectly self-consistent log that is no longer the one the checkpoints
/// certify. The boundary record is therefore re-hashed and compared to the
/// sealed head before anything new is sealed.
///
/// `min_new` batches sealing (a checkpoint per record would bloat the store);
/// it is a floor, not a trigger — call this from `run` or cron.
///
/// Returns `Ok(None)` when there is nothing (or not yet enough) to seal.
pub fn seal_pass(
    records: &[Record],
    store: &mut Store,
    sealer: &dyn Sealer,
    now_ms: i64,
    min_new: usize,
) -> Result<Option<SignedCheckpoint>, Error> {
    let unsealed: &[Record] = match store.last() {
        None => records,
        Some(last) => {
            let sealed_to = last.checkpoint.to_seq;
            let Ok(idx) = records.binary_search_by_key(&sealed_to, |r| r.seq) else {
                return Err(Error::TruncatedLog {
                    log_last: records.last().map(|r| r.seq),
                    sealed_to,
                });
            };
            if records[idx].hash() != last.checkpoint.head_hash {
                return Err(Error::DivergedLog { seq: sealed_to });
            }
            &records[idx + 1..]
        }
    };

    if unsealed.len() < min_new.max(1) {
        return Ok(None);
    }

    let cp = seal_interval(
        store.chain_id(),
        unsealed,
        store.last_hash(),
        now_ms,
        sealer.key_id(),
    )?;
    let signed = sign_checkpoint(cp, sealer)?;
    store.append_checkpoint(signed.clone(), &sealer.public_key())?;
    Ok(Some(signed))
}

/// Assembles the evidence pack an auditor receives.
///
/// Assembly, not judgement: the pack is handed to `probant verify` (or run
/// through `audit_core::evidence::verify` by the caller) for that. An export
/// that filtered or repaired on the way out would be doing exactly what the
/// product exists to make impossible.
pub fn export(records: Vec<Record>, store: &Store) -> Evidence {
    Evidence {
        format: FORMAT.to_string(),
        chain_id: store.chain_id().to_string(),
        records,
        checkpoints: store.checkpoints().to_vec(),
        keys: store.keys().to_vec(),
        anchors: store.anchors().to_vec(),
    }
}
