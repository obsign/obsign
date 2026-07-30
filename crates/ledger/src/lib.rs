//! Sealing service, separate from the gateway.
//!
//! The reason this crate exists: as long as sealing happens inside the
//! gateway, the signing key and the log cohabit on the same host. Whoever
//! compromises that host can rewrite the log *and* re-seal it — the
//! checkpoints then certify the attacker's version of history, which defeats
//! exactly what they are for.
//!
//! The ledger runs elsewhere (another process, another machine, a cron on an
//! admin host). It reads the WAL the gateway produced, never writes to it,
//! and seals with a key the gateway never sees. The division of trust:
//!
//! * the **gateway** guarantees durability (fsync before forwarding) and can
//!   at worst fail to write — never rewrite sealed history unnoticed;
//! * the **ledger** guarantees that what was sealed stays sealed: any
//!   divergence between the WAL and sealed history is detected at the next
//!   pass, before a single new seal is produced.
//!
//! Signing goes through the [`Sealer`] trait. [`FileSealer`] (a seed on disk)
//! is the development implementation; `Pkcs11Sealer` is the production one,
//! holding the key in an HSM behind the vendor's PKCS#11 module, so the key
//! material never enters this process's memory either.
//!
//! The ledger makes no network calls, like every other component. RFC 3161
//! anchoring works by files — a request artifact carried to the TSA, a
//! response artifact carried back — because the deployments this product
//! targets are air-gapped first.

mod anchor;
mod pass;
#[cfg(unix)]
mod pkcs11;
mod sealer;
mod store;

pub use anchor::{timestamp_request, validate_response};
pub use pass::{export, seal_pass, OriginPolicy};
#[cfg(unix)]
pub use pkcs11::{Pkcs11Sealer, TokenSelector};
pub use sealer::{sign_checkpoint, FileSealer, Sealer};
pub use store::Store;

use audit_core::Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Core(#[from] audit_core::Error),

    #[error("log: {0}")]
    Wal(#[from] wal::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The WAL no longer reaches the last sealed record. Records that were
    /// sealed have disappeared: that is not a state to seal over, it is an
    /// incident to surface.
    #[error(
        "the log ends at seq {log_last:?} but sealed history reaches seq \
         {sealed_to}: sealed records have disappeared from the WAL"
    )]
    TruncatedLog {
        log_last: Option<u64>,
        sealed_to: u64,
    },

    /// The record at the sealed boundary no longer hashes to what was sealed.
    /// The chain may be internally consistent — a rewriter recomputes every
    /// hash — but it is no longer the history the checkpoints certify.
    #[error(
        "the log diverges from sealed history at seq {seq}: the record no \
         longer matches the sealed head. The WAL was rewritten after sealing."
    )]
    DivergedLog { seq: u64 },

    /// A record past the sealed head that no trusted origin key vouches
    /// for. Raised *after* the authentic prefix (if any) was sealed: honest
    /// records keep their path to proof, the forgery keeps none, and the
    /// error is the alarm — someone wrote to the WAL who is not the gateway.
    #[error(
        "record seq {seq} is not authenticated by any trusted origin key \
         ({reason}). {}; nothing at or past seq {seq} was sealed — the WAL \
         holds records the gateway did not sign",
        match .prefix_sealed_to {
            Some(to) => format!("the authentic prefix was sealed up to seq {to}"),
            None => "no authentic prefix preceded it".to_string(),
        }
    )]
    UnauthenticatedRecord {
        seq: u64,
        reason: String,
        prefix_sealed_to: Option<u64>,
    },

    #[error("checkpoint store: {0}")]
    StoreBroken(String),

    #[error(
        "key id \"{0}\" already recorded with different key material: a \
         rotated key must take a new id, or old seals become unverifiable"
    )]
    KeyConflict(String),

    #[error("checkpoint {0} is not in the store")]
    UnknownCheckpoint(Hash),

    #[error("the timestamp token imprints different bytes than checkpoint {0}")]
    AnchorMismatch(Hash),

    #[error("invalid signing seed: {0}")]
    BadSeed(String),

    /// Anything the HSM side refuses or garbles, vendor return code included.
    /// One variant, not a taxonomy: the operator's next step is the same
    /// (read the message, check the token), and `run` treats every sealer
    /// construction failure as fatal anyway — retrying PINs against an HSM
    /// walks it toward lock-out.
    #[error("pkcs#11: {0}")]
    Pkcs11(String),
}
