//! Compilation: a validated source tree becomes signed bundles.
//!
//! Compilation is deterministic — the same tree, ref and key always produce
//! byte-identical artifacts (Ed25519 is deterministic per RFC 8032, and the
//! source tree is read in a fixed order). This is what makes `publish`
//! idempotent and releases comparable by hash.

use audit_core::deployment::{DeploymentBundle, SignedDeploymentBundle, FORMAT as DEPLOYMENT_FORMAT};
use identity::bundle::{IdentityBundle, SignedIdentityBundle};
use policy::bundle::{Bundle, SignedBundle};

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
}

/// Compiles and signs. Loading the result through the same code paths the
/// gateway uses (`Engine::load`, `KeyStore::from_set`) is the point: what
/// passes here cannot fail there, because it *is* there.
pub fn compile(tree: &SourceTree, source_ref: &str, ops: &OpsKey) -> Result<Compiled, Error> {
    let bundle = Bundle {
        format: policy::FORMAT.to_string(),
        version: format!("policies@{source_ref}"),
        cedar: tree.cedar.clone(),
        tools: tree.tools.clone(),
        fail_mode: tree.fail_mode.clone(),
    };
    // Cedar syntax, mandatory @id on every rule, unique ids — exactly the
    // checks the gateway runs at startup, moved to compile time.
    policy::Engine::load(&bundle)
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
                format: identity::bundle::FORMAT.to_string(),
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
    })
}
