use audit_core::canonical::Encoder;
use audit_core::hash::{digest, domain, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;

pub const FORMAT: &str = "obsign-policy/1";

/// What the gateway loads in order to decide.
///
/// The bundle is produced from a git repository, not from a UI: the version
/// carries the commit sha, so every decision recorded in the log can be
/// replayed identically months later. It is also what an auditor wants to
/// see — a modified rule is a dated, reviewed pull request, not a click.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bundle {
    pub format: String,
    /// Version identifier, typically `policies@<git sha>`.
    pub version: String,
    /// Cedar source, verbatim.
    pub cedar: String,
    /// Catalogue of known tools. A tool absent from this catalogue is
    /// refused: we do not let through what we have not described.
    pub tools: Vec<ToolDef>,
    #[serde(default)]
    pub fail_mode: FailMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDef {
    pub name: String,
    pub server: String,
    /// A tool whose effect cannot be undone (deletion, transfer, external
    /// send). Exposed to Cedar as an attribute.
    #[serde(default)]
    pub destructive: bool,
    /// Delegation scope required to call it.
    #[serde(default)]
    pub required_scope: Option<String>,
}

/// Behaviour when the engine cannot decide (unreadable bundle, evaluation
/// error).
///
/// There is no universally good default: blocking a read-only tool breaks
/// production for nothing, letting a deletion through is indefensible. The
/// choice therefore belongs to the customer, tool by tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailMode {
    pub default: FailBehaviour,
    /// Per-tool overrides.
    #[serde(default)]
    pub tools: std::collections::BTreeMap<String, FailBehaviour>,
}

impl Default for FailMode {
    fn default() -> Self {
        // Cautious default: refuse. A customer who wants fail-open declares it
        // explicitly, and it shows up in the pull request review.
        FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailBehaviour {
    /// Refuse when in doubt.
    Closed,
    /// Let through, but record it as a degradation.
    Open,
}

impl FailMode {
    pub fn for_tool(&self, tool: &str) -> FailBehaviour {
        self.tools.get(tool).copied().unwrap_or(self.default)
    }
}

impl Bundle {
    /// Bytes that are signed. Explicit canonical encoding, never the JSON:
    /// two JSON serializers can produce two different hashes for the same
    /// bundle, which would invalidate otherwise valid signatures.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.str(&self.format).str(&self.version).str(&self.cedar);

        e.u64(self.tools.len() as u64);
        for t in &self.tools {
            e.str(&t.name)
                .str(&t.server)
                .u8(t.destructive as u8)
                .opt_str(t.required_scope.as_deref());
        }

        e.str(match self.fail_mode.default {
            FailBehaviour::Closed => "closed",
            FailBehaviour::Open => "open",
        });
        // BTreeMap: deterministic iteration order, essential here.
        e.u64(self.fail_mode.tools.len() as u64);
        for (k, v) in &self.fail_mode.tools {
            e.str(k).str(match v {
                FailBehaviour::Closed => "closed",
                FailBehaviour::Open => "open",
            });
        }

        digest(domain::POLICY_BUNDLE, e.finish())
            .as_bytes()
            .to_vec()
    }

    pub fn hash(&self) -> Hash {
        let b = self.signing_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        Hash(a)
    }

    pub fn sign(self, key_id: impl Into<String>, key: &SigningKey) -> SignedBundle {
        let sig = key.sign(&self.signing_bytes());
        SignedBundle {
            bundle: self,
            key_id: key_id.into(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedBundle {
    pub bundle: Bundle,
    pub key_id: String,
    pub signature: String,
}

impl SignedBundle {
    /// Verifies the signature before any use.
    ///
    /// A gateway that loads an unverified bundle is a gateway whose rules can
    /// be changed by writing a file. That is the difference between a policy
    /// and a suggestion.
    pub fn verify(&self, key: &VerifyingKey) -> Result<&Bundle, Error> {
        let raw = hex::decode(&self.signature).map_err(|_| Error::BadSignature)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadSignature)?;
        key.verify(&self.bundle.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadSignature)?;
        if self.bundle.format != FORMAT {
            return Err(Error::UnknownFormat(self.bundle.format.clone()));
        }
        Ok(&self.bundle)
    }
}
