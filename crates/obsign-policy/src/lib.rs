//! Signed policy bundles and Cedar evaluation.
//!
//! Two principles carry everything:
//!
//! * **rules come from git, signed** — the control plane compiles a
//!   repository into a signed bundle, the gateway verifies it before loading.
//!   A policy file dropped on disk changes nothing: without a valid signature
//!   it is rejected;
//! * **the catalogue is authoritative** — a tool the bundle does not describe
//!   is refused, even if the MCP server advertises it.

pub mod bundle;
pub mod engine;
pub mod schema;

pub use bundle::{
    ArgKind, ArgSpec, Bundle, FailBehaviour, FailMode, SignedBundle, ToolDef, FORMAT, FORMAT_V2,
};
pub use engine::{Capability, Engine, ToolRequest, Verdict, WRAPPED_SERVER};
pub use schema::{schema_source, SCHEMA_FILE};

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid bundle signature")]
    BadSignature,

    #[error("unknown bundle format: {0}")]
    UnknownFormat(String),

    #[error("bundle: {0}")]
    Bundle(String),

    #[error("cedar: {0}")]
    Cedar(String),

    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}
