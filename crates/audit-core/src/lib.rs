//! Audit log core: record format, hash chain, sealing and verification.
//!
//! **This crate is the single implementation of the proof.** The gateway, the
//! ledger, the control plane and the offline verifier all depend on it. No
//! other component may recompute a hash or revalidate a chain on its own:
//! divergence between two implementations is precisely what would make the
//! export say "valid" while the verifier says "tampered".
//!
//! Rules held here, and to be held over time:
//!
//! * minimal dependency tree, readable end to end by an auditor;
//! * no async, no web framework, no ORM;
//! * the canonical encoding and the discriminants are frozen: changing them
//!   invalidates already-sealed logs.

pub mod attestation;
pub mod canonical;
pub mod checkpoint;
pub mod deployment;
pub mod error;
pub mod evidence;
pub mod hash;
pub mod merkle;
pub mod origin;
pub mod p256;
pub mod record;
pub mod rfc3161;

pub use deployment::{DeploymentBundle, SignedDeploymentBundle};
pub use error::Error;
pub use hash::{Hash, GENESIS};
pub use origin::{
    key_id_for, origin_signing_bytes, session_cert_signing_bytes, verify_session_cert, SignedRecord,
};
pub use record::{
    Actor, AgentSession, ApprovalMode, Decision, Delegation, Effect, EffectStatus, LlmTurn,
    Outcome, Payload, PrincipalKind, Record, SealedRef, ToolCall,
};

use checkpoint::Checkpoint;
use merkle::merkle_root;

/// Write-side state of a chain.
///
/// Encapsulates the two invariants that are easy to break by hand: `seq`
/// strictly increasing with no gaps, and `prev_hash` correctly propagated.
/// The gateway and the ledger must go through it.
#[derive(Debug, Clone)]
pub struct ChainWriter {
    chain_id: String,
    next_seq: u64,
    head: Hash,
    /// Hashes accumulated since the last seal.
    pending: Vec<Hash>,
    pending_from: u64,
    last_checkpoint: Option<Hash>,
}

impl ChainWriter {
    /// New chain, anchored on genesis.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            next_seq: 0,
            head: GENESIS,
            pending: Vec::new(),
            pending_from: 0,
            last_checkpoint: None,
        }
    }

    /// Resume an existing chain (ledger restart).
    pub fn resume(
        chain_id: impl Into<String>,
        next_seq: u64,
        head: Hash,
        last_checkpoint: Option<Hash>,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            next_seq,
            head,
            pending: Vec::new(),
            pending_from: next_seq,
            last_checkpoint,
        }
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn head(&self) -> Hash {
        self.head
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Appends a record and returns its final form (`seq` and `prev_hash` are
    /// set here, never by the caller).
    pub fn append(
        &mut self,
        ts_ms: i64,
        id: impl Into<String>,
        parent_id: Option<String>,
        session_id: impl Into<String>,
        payload: Payload,
    ) -> Record {
        let rec = Record {
            seq: self.next_seq,
            ts_ms,
            prev_hash: self.head,
            id: id.into(),
            parent_id,
            session_id: session_id.into(),
            payload,
        };
        let h = rec.hash();
        if self.pending.is_empty() {
            self.pending_from = rec.seq;
        }
        self.pending.push(h);
        self.head = h;
        self.next_seq += 1;
        rec
    }

    /// Seals everything appended since the last call.
    ///
    /// Returns `None` when nothing is pending: an empty seal has no probative
    /// value and must not be manufactured.
    pub fn seal(&mut self, ts_ms: i64, key_id: impl Into<String>) -> Option<Checkpoint> {
        let root = merkle_root(&self.pending)?;
        let cp = Checkpoint {
            chain_id: self.chain_id.clone(),
            from_seq: self.pending_from,
            to_seq: self.next_seq - 1,
            root,
            head_hash: self.head,
            prev_checkpoint_hash: self.last_checkpoint,
            ts_ms,
            key_id: key_id.into(),
        };
        self.last_checkpoint = Some(cp.hash());
        self.pending.clear();
        self.pending_from = self.next_seq;
        Some(cp)
    }
}

/// Hash of application content (prompt, arguments, result).
///
/// Used to prove *what* without retaining the content itself.
pub fn content_hash(bytes: &[u8]) -> Hash {
    // Domain distinct from records: application content must never be
    // confusable with a link of the chain.
    hash::digest(hash::domain::CONTENT, bytes)
}
