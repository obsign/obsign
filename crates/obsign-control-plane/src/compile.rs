//! Compilation: a validated source tree becomes signed bundles.
//!
//! Compilation is deterministic. The same tree, ref and key always produce
//! byte-identical artifacts (Ed25519 is deterministic per RFC 8032, and the
//! source tree is read in a fixed order). This is what makes `publish`
//! idempotent and releases comparable by hash.

use obsign_audit_core::deployment::{DeploymentBundle, SignedDeploymentBundle, FORMAT as DEPLOYMENT_FORMAT};
use obsign_identity::bundle::{IdentityBundle, SignedIdentityBundle};
use obsign_policy::bundle::{Bundle, SignedBundle};

use crate::source::SourceTree;
use crate::{Error, OpsKey};

/// The artifacts a compilation produces, already signed and self-verified.
#[derive(Debug)]
pub struct Compiled {
    /// Short commit sha, or the explicit label. This is the release version.
    pub source_ref: String,
    pub policy: SignedBundle,
    pub identity: Option<SignedIdentityBundle>,
    pub deployment: Option<SignedDeploymentBundle>,
    /// Cedar validator warnings, such as a rule that can never fire or an
    /// identifier built from confusable characters. Worth showing the author,
    /// not worth refusing to sign over: none of them makes a decision wrong,
    /// and a warning that blocks a release is a warning people learn to route
    /// around.
    pub warnings: Vec<String>,
}

/// The bundle format a catalogue requires.
///
/// v2 only when some tool declares argument policy: a fleet that never uses
/// the feature keeps emitting v1, which pre-upgrade gateways still load. The
/// cutover is self-serve, per repository. Shared with `schema`, which must
/// load a catalogue exactly the way `compile` will.
pub(crate) fn format_for(tools: &[obsign_policy::ToolDef]) -> &'static str {
    if tools.iter().any(|t| !t.policy_args.is_empty()) {
        obsign_policy::FORMAT_V2
    } else {
        obsign_policy::FORMAT
    }
}

/// Compiles and signs. Loading the result through the same code paths the
/// gateway uses (`Engine::load`, `KeyStore::from_set`) is the point: what
/// passes here cannot fail there, because it *is* there.
pub fn compile(tree: &SourceTree, source_ref: &str, ops: &OpsKey) -> Result<Compiled, Error> {
    let bundle = Bundle {
        format: format_for(&tree.tools).to_string(),
        version: format!("policies@{source_ref}"),
        cedar: tree.cedar.clone(),
        tools: tree.tools.clone(),
        fail_mode: tree.fail_mode.clone(),
    };
    // Cedar syntax, mandatory @id on every rule, unique ids, argument
    // declarations — exactly the checks the gateway runs at startup, moved
    // to compile time.
    let engine = obsign_policy::Engine::load(&bundle)
        .map_err(|e| Error::Source(format!("policies: {e}")))?;
    // Type-check every rule against the model the gateway exposes, derived
    // from this bundle's own catalogue. `load` only proves the rules parse;
    // this proves they can *evaluate* — a rule reading `principal.roles` or
    // `context.enviroment` raises an evaluation error at runtime and falls to
    // the fail mode, which on a fail-open tool means the rule meant to stop a
    // call quietly stops stopping it.
    //
    // This replaced a per-tool "smoke evaluation" that ran the real policies
    // against synthetic zero-valued arguments. That check existed to catch a
    // typo'd `context.args.<name>`, which the type checker now catches
    // outright — whatever guards the rule carries, rather than only when a
    // zero-valued context happened to reach it. What the smoke evaluation
    // alone still caught was an expression that raises *at zero* (an i64
    // overflow, say); it missed the same defect at realistic values, and for
    // a tool that declares arguments an evaluation error already denies
    // rather than fail-opens, so that class was loud and immediate at
    // runtime, not silent. Not worth a second compile-time pass that had to
    // be taught to ignore every rule the type checker deliberately accepts.
    let warnings = engine
        .validate()
        .map_err(|e| Error::Source(format!("policies: {e}")))?;
    let vk = ops.signing_key().verifying_key();

    // Sign, then re-verify with the public half before anything is written.
    // Same rationale as the ledger's sign_checkpoint: with a remote signer, a
    // misconfigured key slot answers with a valid signature from the wrong
    // key. That must fail here, not at gateway startup across the fleet.
    let policy_signed = bundle.sign(ops.key_id(), ops.signing_key());
    policy_signed.verify(&vk)?;

    let identity_signed = match &tree.identity {
        None => None,
        Some(src) => {
            let ib = IdentityBundle {
                format: obsign_identity::bundle::FORMAT.to_string(),
                version: format!("identity@{source_ref}"),
                issuer: src.issuer.clone(),
                audience: src.audience.clone(),
                jwks: src.jwks.clone(),
                claims: src.claims.clone(),
            };
            let signed = ib.sign(ops.key_id(), ops.signing_key());
            signed.verify(&vk)?;
            Some(signed)
        }
    };

    let deployment_signed = match &tree.deployment {
        None => None,
        Some(origin_keys) => {
            let db = DeploymentBundle {
                format: DEPLOYMENT_FORMAT.to_string(),
                version: format!("deployment@{source_ref}"),
                origin_keys: origin_keys.clone(),
                attestations: tree.attestations.clone(),
            };
            // The same validation the ledger will run, at compile time: a
            // seal-role key, a duplicate id or an unusable key must fail here,
            // in CI, not at the sealing host across the fleet.
            db.active_origin_keys()?;
            let signed = db.sign(ops.key_id(), ops.signing_key());
            signed.verify(&vk)?;
            Some(signed)
        }
    };

    Ok(Compiled {
        source_ref: source_ref.to_string(),
        policy: policy_signed,
        identity: identity_signed,
        deployment: deployment_signed,
        warnings,
    })
}
