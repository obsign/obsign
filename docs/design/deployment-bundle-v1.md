# Deployment bundle — v1 design

Status: **implemented** (2026-07-30, branch `wal-origin-auth-design`, 204
tests). Implements §7.2 and §7.4 of [wal-origin-auth.md](wal-origin-auth.md):
origin-key distribution is now the same control-plane-signed-artifact story
as policy and identity, with rotation/revocation and the default posture
flipped to require origin. Sections 3–7 are as built. The three open
decisions in §10 were resolved as follows:

- **(1) chose option (b):** the gateway loads the deployment bundle,
  accepts any *currently-active* origin key on resume (closing the
  rotation-mid-chain gap v0 §3.5 left open), and records
  `ConfigKind::DeploymentBundle` at the top of every chain. `Wal::open_\
  authenticated` now takes the active key *set*, not one key.
- **(3) done:** the ops-signed bundle is embedded in the evidence pack
  (`Evidence.deployment`, `#[serde(default)]`), so the auditor verifies the
  whole origin chain of trust from the ops key alone.
- **(2) deferred:** the `obsign-identity/2` claims machine-marker fix is a
  separable HIGH (the deployment bundle is a *new* artifact, not an identity
  format rev, so it does not force the identity change). Left as its own
  next increment.

Live-attack verified on the built binaries: a fabricated record with a
correctly recomputed hash chain, appended after the sealed head, yields
`obsign-ledger seal --deployment-bundle` exit 1 and a gateway restart that
refuses to resume; the default `obsign verify` (require-origin now on)
fails a legacy unsigned pack, and `--allow-unsigned-legacy-chains` restores
the warning-only verdict.

## 1. What v0 left, and why it is not enough

v0 raised the bar from "write the WAL directory" to "hold the gateway's
origin key". But it distributes trust in origin keys through a **flat file an
operator hand-maintains** on the ledger host (`--trusted-origin-keys`) and on
the auditor's machine. That file is exactly the hole the identity and policy
bundles were built to close: whoever writes it mints origin authority. It has
no rotation story (edit the file), no revocation story (edit the file, hope
every copy is edited), and no audit trail (a text file has no history).

Two operational facts make this urgent, not cosmetic:

- A deployment has **many gateways**, each with its own origin key. The flat
  file is assembled by copy-pasting the public entry each gateway prints at
  startup — error-prone, and unverifiable after the fact.
- Keys get compromised and gateways get decommissioned. "Stop trusting this
  key everywhere, provably, dated" is a control-plane operation, not a
  `sed`.

## 2. Decision

**A new control-plane-signed artifact, `obsign-deployment/1`, listing the
active gateway origin keys. It rides the existing `compile → publish`
pipeline and the existing ops-key trust root. The ledger and the offline
verifier resolve origin trust through it instead of through a hand-kept file.
Origin is required by default; the unsigned-legacy path becomes an explicit,
ugly opt-out.**

Nothing about the v0 record path, envelope, per-record signature, or pack
format changes. This is a distribution-and-trust-root change only — the
property §7 exists to protect.

### Why this shape

The control plane already solves exactly this problem three times over
(policy bundle, identity bundle, release manifest): a reviewed file in the
git source tree, compiled deterministically, signed with the ops key,
published immutably under `releases/<sha>/`, with the current copy swapped
atomically for watching gateways. The origin key set is one more reviewed
file compiled into one more signed artifact. Enrolling a gateway is a pull
request; revoking one is a pull request; the audit trail is the git history
plus the immutable release directories — the same properties a rule change
already has.

**Rejected — a bespoke enrollment protocol** (gateways POST their public key
to the control plane). It would be the first network-writing path in a
system whose whole console is GET-only by construction (lib.rs), and it would
make key enrollment a runtime event instead of a reviewed change. Copy the
public entry into git; that is the reviewable step.

**Rejected — leaving the ledger's trust as a flat file, signed.** Signing the
flat file is most of the work of a real artifact without the version, the
immutable history, or the reuse of the publish pipeline. Do it once,
properly.

## 3. The artifact

```rust
pub const FORMAT: &str = "obsign-deployment/1";

/// The set of gateway origin keys a deployment currently trusts.
///
/// Signed by the ops key, the same root that signs policy and identity
/// bundles. A key absent from the active set is not trusted to have written
/// any record a fresh seal will bless — that is what revocation is: remove
/// and republish.
#[derive(Serialize, Deserialize)]
pub struct DeploymentBundle {
    pub format: String,
    /// `deployment@<sha>`, the source ref, like `policies@<sha>`.
    pub version: String,
    /// Active origin keys, sorted by key_id (the order is part of the
    /// signature). Every entry has role `origin`; a seal role here is a
    /// compile error.
    pub origin_keys: Vec<PublicKeyEntry>,
}
```

- New domain byte `DEPLOYMENT_BUNDLE = 0x0B` in `audit_core::hash::domain`
  (0x0A is `ORIGIN_RECORD`, 0x09 stays reserved for `SignedChainHead`).
- `signing_bytes` follows the identity bundle exactly: format, version, then
  the key entries in `key_id` order (each `key_id`, `algo`, `public_key`,
  `role.as_str()`), domain-separated. `SignedDeploymentBundle { bundle,
  key_id, signature }`, verified under the ops verifying key — a byte-for-byte
  clone of `SignedIdentityBundle`, deliberately.
- Lives in `identity` crate next to `IdentityBundle`? **No** — it lives in a
  small new home so `identity` (which is about *humans*/IdP) does not gain a
  concept about *gateways*. Proposed: `audit_core::deployment` (audit-core
  already owns `PublicKeyEntry` and `KeyRole`, and both the ledger and the
  verifier depend on it, which is where the resolution logic must sit — the
  single-implementation-of-the-proof rule).

### Revocation semantics, stated precisely

Removing a key from the active set and republishing stops it from
authenticating any record a **future** seal will accept. It does **not**
invalidate already-sealed history, and it must not: the checkpoint attests
the records were origin-verified at seal time, the anchor attests when. An
auditor re-verifying an *old* pack uses the origin keys **embedded in that
pack** (v0 already embeds them) or the historical bundle from
`releases/<sha>/`, not the current active set. So:

- current bundle = what the ledger will seal under, and what the verifier
  trusts for a *fresh* pack;
- `releases/<sha>/deployment-bundle.json` = the immutable lineage, the answer
  to "was this key trusted on 2026-06-01?";
- a compromised key that signed records *before* revocation which then got
  sealed cannot be un-sealed — that is key compromise, which no revocation
  scheme repairs. Revocation bounds the future, and the git history dates the
  boundary.

## 4. Source tree and compile

One new optional file, reviewed like the JWKS:

```text
deployment/origin-keys.json    Vec<PublicKeyEntry>, each role "origin"
```

`SourceTree::load` gains `deployment: Option<Vec<PublicKeyEntry>>`.
`compile` validates it with the same rigour it applies to the JWKS — the
checks that would otherwise blow up at the ledger, moved to CI where the PR
author is looking:

- every entry has role `origin` (a seal key here is the writer-certifier
  confusion, refused);
- `key_id`s are unique, and each `public_key` is a usable 32-byte ed25519 key
  (`to_verifying_key` succeeds);
- an empty or absent file is allowed and means "no gateway trusted yet" —
  legitimate before the first gateway is enrolled, and honest rather than a
  silent empty set (the ledger under default-require will then refuse to seal
  anything, which is correct: no trusted writer, no proof).

`Compiled` gains `deployment: Option<SignedDeploymentBundle>`; `publish`
writes `deployment-bundle.json` as a third artifact, sorted into the
manifest, copied to the immutable release dir and swapped atomically like the
others. Zero new machinery in `release.rs` — it already iterates an artifact
list.

## 5. The ledger resolves trust through the bundle

`obsign-ledger seal`/`run`/`export` learn `--deployment-bundle <file>`. The
ledger already needs the ops public key to trust it, so:

- `--deployment-bundle <ops-signed file>` and the ops key supplied the way
  the gateway already receives it (`--trusted-keys`, reused here to verify
  the bundle signature). The bundle is verified under the ops key, then its
  `origin_keys` become the `OriginPolicy` active set. `OriginPolicy::new`
  (v0) stays; a new `OriginPolicy::from_bundle(&SignedDeploymentBundle,
  &ops_keys, require)` is the v1 entry point.
- `--trusted-origin-keys` (the v0 flat file) stays supported for one
  transition, documented as superseded. Passing both is an error: one source
  of origin truth.

The `UnauthenticatedRecord` prefix-seal-then-alarm behaviour from v0 §3.4 is
unchanged — only where the trusted set *comes from* changes.

## 6. The verifier gets one root of trust

Today the auditor hand-assembles origin keys into `--trusted-keys`. v1 gives
them one artifact and one chain of trust:

```
ops key  ─signs→  deployment bundle  ─lists→  origin keys  ─verify→  records
seal key ──────────────────────────────────────sign→  checkpoints
```

`obsign verify --deployment-bundle <ops-signed file> --trusted-keys
<ops+seal keys>`:

- verify the deployment bundle under the ops key from `--trusted-keys`;
- its `origin_keys` join the origin trust set used by the v0 origin pass;
- new findings: `deployment_bundle_invalid` (**error**: bad signature, or
  signed by a key absent from / not matching the ops key in `--trusted-keys`),
  `deployment_bundle_unverified` (**warning**: a bundle is present but no ops
  key was supplied to anchor it — self-referential, the `keys_not_anchored`
  precedent).

`verify_with` grows an optional `deployment: Option<&SignedDeploymentBundle>`
input (or the bundle travels embedded in the pack — see open decision 3). The
v0 `VerifyOptions`/`records_origin_ok` machinery is untouched; origin keys
now have two possible provenances (explicit `--trusted-keys` entries, or the
verified bundle), unioned before the origin pass.

## 7. Default posture flips (§7.4)

Auditors and operators run defaults. As long as unsigned records are tolerated
by default, the headline claim carries an asterisk only experts read. v1
inverts it, carefully, because legacy unsigned chains genuinely exist:

- **Ledger**: with a `--deployment-bundle` present, `require` defaults to
  **on**. `--allow-unsigned-legacy-chains` is the explicit, deliberately
  unlovely opt-out that restores v0 rollout tolerance. Without any origin
  configuration at all (neither bundle nor flat file), behaviour is
  unchanged — pre-origin deployments are not force-upgraded by a version
  bump.
- **Verifier**: `--require-origin` becomes the default. `--allow-unsigned-\
  legacy-chains` downgrades `origin_unverified` back to a warning. The person
  accepting the asterisk types the flag; everyone else gets the strict
  verdict. `--strict` already fails on warnings, so nothing regresses for
  callers who were strict.

The flip is a behaviour change, not a format change: old packs still parse,
they just no longer pass the *default* verdict without the opt-out. That is
the intended, visible consequence.

## 8. What v1 deliberately does not do

- **Per-key validity windows / anchored-time key checks.** The bundle is a
  membership set, not a schedule. Time-bounded keys belong with v2's session
  certificates, which already carry `not_before`/`not_after` and are the
  natural place to verify against anchored RFC 3161 time. A membership set
  plus the dated git history covers v1's revocation need.
- **Hardware custody / two-tier keys.** Still v2 (§7.1). The gateway holds a
  file seed; the bundle distributes the *public* halves. The custody boundary
  (`OriginSigner`) does not move.
- **Automatic enrollment.** Enrollment is a reviewed commit, by design (§2).

## 9. Implementation plan

Each step green on its own, same discipline as v0:

1. **audit-core**: `domain::DEPLOYMENT_BUNDLE`, `deployment.rs`
   (`DeploymentBundle`, `SignedDeploymentBundle`, `signing_bytes`, verify).
   Tests: signature round-trip, foreign-key refusal, role-confusion refusal,
   frozen signing-bytes vector.
2. **control-plane**: `deployment/origin-keys.json` in `SourceTree`, compile
   validation, third artifact in `publish`. Tests: enroll/revoke as
   compile+publish, immutable-history reuse, seal-key-in-origin-file refused.
3. **ledger**: `OriginPolicy::from_bundle`, `--deployment-bundle`,
   default-on `require` with `--allow-unsigned-legacy-chains`. Tests: sealing
   trust resolved from a signed bundle; a key revoked (removed + republished)
   no longer seals; both-sources error.
4. **obsign verify**: `--deployment-bundle`, the two new findings, the
   ops→bundle→origin chain, default `--require-origin` +
   `--allow-unsigned-legacy-chains`. Tests: forged bundle rejected; the
   one-root-of-trust happy path; legacy pack under the new default.
5. **Docs**: operator runbook — enroll, rotate, revoke, and *when to flip*
   (the last unlovely-flag removal is per-deployment, stays in prose).

The mechanical surface is again small (one artifact, one trust resolution);
the tests are the bulk.

## 10. Open decisions (need a call before implementation)

1. **ConfigKind::DeploymentBundle + who logs the reload.** §7.2 wanted bundle
   reloads recorded in-chain. But the *ledger* consumes the bundle for
   sealing and never writes the chain; the *gateway* writes the chain but
   does not need the bundle to sign its own records. The honest options:
   - **(a) Defer it.** The audit trail already exists out-of-chain: git
     history + immutable `releases/<sha>/` + the origin keys embedded in each
     pack. "Which keys were trusted when this was sealed" is answerable
     without a chain record. *Recommended for v1* — it keeps the gateway free
     of a concept it does not otherwise use.
   - **(b) Give the gateway the bundle for rotation-on-resume.** Point the
     gateway at `--deployment-bundle` so `Wal::open_authenticated` accepts a
     tail signed by any *currently-active* origin key, not only its own
     current one — which is exactly how v0 §3.5 said rotation mid-chain
     should eventually work. Then logging `ConfigKind::DeploymentBundle`
     reloads has a real consumer and a real meaning. More surface; solves the
     rotation-mid-chain gap v0 left open. Adding the `ConfigKind` variant is
     additive and cheap regardless (string-encoded), so it can land now and
     be populated later.
   My recommendation: ship (a) for v1, add the `ConfigKind` variant now as a
   reserved additive extension, and schedule (b) with the rotation work.

2. **Bundle the deferred `obsign-identity/2` claims fix into this train.**
   The review's HIGH on `claims.rs` machine detection (`sub == client_id`
   misfires on Keycloak/Entra) was deferred because the real fix —
   configurable machine markers — needs a signed-bundle format rev, which we
   are now doing anyway. Folding it in here means one format-rev wave instead
   of two. *Recommended*, but it widens v1's scope; call it.

3. **Does the deployment bundle travel embedded in the evidence pack?**
   Embedding it makes the pack self-describing (verify with only the ops key
   out of band) and preserves the exact keys used at seal time. Not embedding
   it keeps the pack smaller and the bundle a separate out-of-band input.
   *Recommended: embed it* (optional field, `#[serde(default)]`, the
   `anchors` precedent) — it is the same self-containment argument that made
   v0 embed origin keys, and it makes the verifier's one-root story work with
   nothing but the ops key.
