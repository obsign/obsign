use obsign_audit_core::canonical::Encoder;
use obsign_audit_core::hash::{digest, domain, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;

pub const FORMAT: &str = "obsign-policy/1";
/// Same bundle plus per-tool `policy_args` declarations. A v1 bundle that
/// carries `policy_args` is refused outright: v1 signing bytes do not cover
/// the declarations, and an unsigned declaration is unsigned authority.
pub const FORMAT_V2: &str = "obsign-policy/2";

/// What the gateway loads in order to decide.
///
/// The bundle is produced from a git repository, not from a UI: the version
/// carries the commit sha, so every decision recorded in the log can be
/// replayed identically months later. It is also what an auditor wants to
/// see, because a modified rule is a dated, reviewed pull request.
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
    /// Arguments the policy may see, exposed to Cedar as `context.args`.
    /// The allowlist is the privacy boundary: anything not declared here
    /// never reaches the engine. Requires `obsign-policy/2`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_args: Vec<ArgSpec>,
}

/// One argument of one tool, as the policy is allowed to see it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArgSpec {
    /// Name under `context.args` in Cedar.
    pub name: String,
    /// Where to read the value in the call's `arguments` object: a JSON
    /// pointer (RFC 6901). Defaults to `/<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    pub kind: ArgKind,
    /// Injected when the call omits the argument. An arg with no default is
    /// required-if-declared: its absence refuses the call before Cedar runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

impl ArgSpec {
    /// JSON pointer this spec reads from. When derived from the name, the
    /// name is escaped per RFC 6901 (`~` becomes `~0`, `/` becomes `~1`) so
    /// that a name containing those characters resolves to the literal
    /// argument key instead of being read as a nesting path. An arg named
    /// `path/glob` must match the key `path/glob` itself, never
    /// `args["path"]["glob"]`. The order matters: `~` first, then `/`.
    pub fn pointer(&self) -> String {
        match &self.at {
            Some(p) => p.clone(),
            None => format!("/{}", self.name.replace('~', "~0").replace('/', "~1")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArgKind {
    String,
    /// Integral only, `i64` range. Floats are refused; an amount check
    /// that rounds is an amount check with a hole. Monetary rules declare
    /// minor units (cents).
    Long,
    Bool,
    /// A JSON array of strings; Cedar receives a set.
    StringSet,
}

impl ArgKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArgKind::String => "string",
            ArgKind::Long => "long",
            ArgKind::Bool => "bool",
            ArgKind::StringSet => "string_set",
        }
    }
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

        // Which optional segments this format's canonical encoding carries,
        // decided ONCE (the choice is a property of the bundle, not the
        // tool). The v1 encoding is frozen: it omits the declarations so
        // existing signatures keep verifying. Everything from v2 onward
        // appends them unconditionally (an empty list encodes as length 0)
        //: a canonical encoding with optional segments is how two bundles
        // end up sharing bytes, and the format string opens the encoding,
        // so the layouts cannot collide.
        //
        // Fail-safe against a future bump: only v1 omits the segment; any
        // newer format includes it. `signing_bytes` must never emit *fewer*
        // segments than a bundle carries, or a new field would fall outside
        // the signed bytes (the v1-with-policy_args injection, one version
        // later). verify()/Engine::load remain the format allowlist; this
        // default is the backstop if one is added there but missed here.
        let encode_policy_args = self.format != FORMAT;

        e.u64(self.tools.len() as u64);
        for t in &self.tools {
            e.str(&t.name)
                .str(&t.server)
                .u8(t.destructive as u8)
                .opt_str(t.required_scope.as_deref());
            if encode_policy_args {
                e.u64(t.policy_args.len() as u64);
                for a in &t.policy_args {
                    e.str(&a.name)
                        .opt_str(a.at.as_deref())
                        .str(a.kind.as_str())
                        .opt_str(a.default.as_ref().map(|d| d.to_string()).as_deref());
                }
            }
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
        // Format first, signature second. `signing_bytes` is format-shaped
        // (v2 appends the policy_args segment), so a peer that computed bytes
        // for the wrong format would otherwise fail with BadSignature, a
        // misdiagnosis indistinguishable from tampering. Checking the format
        // up front lets a version this build does not know report
        // UnknownFormat cleanly (both encodings open with the format string,
        // so an unknown format never masquerades as a known one). Rejection
        // is identical either way; only the diagnosis improves.
        if self.bundle.format != FORMAT && self.bundle.format != FORMAT_V2 {
            return Err(Error::UnknownFormat(self.bundle.format.clone()));
        }
        let raw = hex::decode(&self.signature).map_err(|_| Error::BadSignature)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::BadSignature)?;
        key.verify(&self.bundle.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| Error::BadSignature)?;
        // v1 signing bytes do not cover `policy_args`: an attacker could
        // inject declarations into a signed v1 bundle without breaking its
        // signature. Declarations are only authority under v2.
        if self.bundle.format == FORMAT
            && self.bundle.tools.iter().any(|t| !t.policy_args.is_empty())
        {
            return Err(Error::Bundle(
                "policy_args requires obsign-policy/2".to_string(),
            ));
        }
        Ok(&self.bundle)
    }
}
