//! OIDC token verification and delegation extraction.
//!
//! Without this crate, the log records a *declared* identity: someone typed a
//! name on a command line. With it, it records a *proven* identity: an
//! identity provider signed a time-bounded assertion that the gateway
//! verified.
//!
//! The whole attribution chain rests on that distinction. An audit log that
//! traces back to "marie.dupont" without being able to substantiate it was
//! really her proves nothing at all.
//!
//! Two design choices:
//!
//! * **no network calls** — the JWKS comes from a signed bundle distributed by
//!   the control plane, like the policy bundle. The gateway stays deployable
//!   air-gapped and adds no outbound surface. Key rotation happens by
//!   reloading that file, not by querying the IdP;
//! * **expiry is re-evaluated on every act**, not only when the session
//!   opens. An agent session outlives a token.

pub mod bundle;
pub mod claims;
pub mod jwks;
pub mod source;
pub mod verifier;

pub use bundle::{IdentityBundle, SignedIdentityBundle};
pub use claims::{ClaimMap, MachineMarkers, MarkerMatch};
pub use jwks::{Jwk, JwkSet, KeyStore};
pub use source::{BundleSource, ReloadOutcome};
pub use verifier::{Delegation, Verifier};

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("empty jwks: no verification key")]
    EmptyJwks,

    #[error("incomplete key \"{0}\"")]
    MalformedJwk(String),

    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("unsupported or forbidden algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("kid \"{0}\" appears more than once in the jwks")]
    DuplicateKid(String),

    #[error("token has no kid: cannot designate a verification key")]
    MissingKid,

    #[error("kid \"{0}\" unknown to the jwks")]
    UnknownKid(String),

    #[error("delegation expired {0} s ago")]
    Expired(i64),

    #[error("the token carries no scope: the delegation would be empty, \
             check the claim mapping")]
    NoScopes,

    #[error("the token carries no subject at the configured path")]
    MissingSubject,

    #[error("the token carries no exp claim")]
    MissingExpiry,

    #[error("invalid identity bundle signature")]
    BadBundleSignature,

    #[error("unknown identity bundle format: {0}")]
    UnknownBundleFormat(String),

    #[error("a obsign-identity/1 bundle carries machine markers its signature \
             does not cover: recompile it as obsign-identity/3")]
    UnsignedMachineMarkers,

    #[error("this bundle carries display-label paths its signature does not \
             cover: recompile it as obsign-identity/3")]
    UnsignedLabelPaths,

    #[error("identity bundle signed with key \"{0}\", absent from the trusted keys")]
    UnknownBundleKey(String),
}
