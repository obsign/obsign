# Session certificates & hardware identity keys — v2 design

Status: **implemented** (2026-07-30, branch `wal-origin-auth-design`, 212
tests incl. a real SoftHSM token). Implements §7.1 of
[wal-origin-auth.md](wal-origin-auth.md): the gateway's *identity* is
separated from its *signing throughput* — the per-record key is generated in
memory and never touches disk, the long-lived identity key never touches the
hot path. Sections 3–7 are as built; the four §10 decisions were resolved on
their recommended defaults:

- **(1) in-chain, tag 9:** `Payload::SessionCert` is the chain's first
  record, sealed and unstrippable.
- **(2) dev custody = file seed;** production = PKCS#11 (`Pkcs11IdentitySigner`),
  verified against a real SoftHSM token.
- **(3) shared `obsign-pkcs11` crate:** the ledger's hand-rolled bindings were
  lifted into a new `obsign-pkcs11` crate; `Pkcs11Sealer` (sealing role) and
  `Pkcs11IdentitySigner` (identity role) are thin wrappers over the one
  audited `Pkcs11Signer` — with an internal sign-lock and `unsafe impl
  Send+Sync` so the identity signer is shareable across HTTP session threads.
- **(4) session-bounded lifetime:** `--session-lifetime-secs` (default 1h);
  the window is carried but enforced only against anchored time (informational
  otherwise — see §6).

Live-verified through the built binaries: a two-tier gateway writes a session
cert at the chain top signed by a memory session key, the identity key never
signs a record directly, the pack verifies under `require-origin` from the
ops+seal roots alone (the session key is never supplied out of band), and a
fabricated record is refused both at seal and at gateway resume. The HSM path
certifies a memory session key off a real SoftHSM Ed25519 key.

## 1. What v0/v1 left, and why it is not enough

v0 gave each gateway a file-seed origin key and signed every record with it.
v1 distributed those keys' public halves through a signed bundle. Both share
one residual, stated plainly in v0 §3.3: **the origin key material lives on
disk, on the host we assume the attacker can write to.** A disk attacker who
can also *read* the seed forges signatures. The bar is "read the gateway's
key file" — real, but not the bar we want long-term.

The naive fix — "put the key in a TPM and sign every record with it" — is
wrong on the hot path. Hardware signing is millisecond-class and serialized;
the per-record budget is set by an fsync in the tens of microseconds. Three
records per tool call through a TPM multiplies gateway latency by ~50. The
key must be in hardware; the signing must not go through hardware per record.

## 2. Decision

**Two-tier keys. A long-lived gateway *identity key* in hardware
(PKCS#11/TPM/Secure Enclave, file-seed in dev) signs a short *session
certificate* over an ephemeral *session key* generated in memory at session
open. Records are signed by the session key — same ~20 µs as today, same
code path, different key provenance. The session key never touches disk; the
identity key never signs on the hot path.**

The chain of trust becomes:

```
control-plane root ─signs→ deployment bundle ─enrolls→ identity key
   ─certifies→ session cert ─authorizes→ session key ─signs→ records
```

Nothing about the record envelope or the per-record signature *mechanism*
changes — a record still carries `origin_sig` + `origin_key_id`, verified
with an Ed25519 public key. What changes is where that public key comes from:
no longer a bundle entry directly, but a session certificate the bundle's
identity key vouches for.

### What this buys, in threat-model terms

- **No signing key material on disk, ever.** The v0/v1 residual disappears
  rather than being mitigated: the identity key is non-exportable hardware,
  the session key is memory-only and discarded at session close.
- **Compromise window = one session.** A leaked session key (a memory
  scrape) forges records only until its `not_after`, and only for its one
  chain. Minting a *new* session certificate needs the hardware identity key,
  which cannot leave the device.
- **Whole-chain forgery dies at the certificate.** The certificate binds the
  session key to a specific `chain_id` and `gateway_id`. A fabricated chain
  cannot obtain a certificate for its chain id without the hardware key —
  closing the post-session-append attack's big brother, not just the
  per-record case.

## 3. The session certificate

A new **payload type**, `Payload::SessionCert` (tag 9 — the next free
integer, the sanctioned extension mechanism that added `Actor` (7) and
`ConfigReload` (8) without moving any existing hash). It is the first record
of every chain, sealed like any other, so it cannot be stripped.

```rust
pub struct SessionCert {
    /// The ephemeral session public key (32-byte ed25519, hex) that signs
    /// every record of this chain in the envelope.
    pub session_pubkey: String,
    /// The hardware identity key that certified it — resolved in the
    /// deployment bundle's active set.
    pub identity_key_id: String,
    /// Gateway identity, bound so a certificate cannot be replayed by a
    /// different gateway holding a leaked session key.
    pub gateway_id: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    /// Ed25519 signature by the identity key over the canonical encoding of
    /// the fields above plus the chain_id.
    pub identity_sig: String,
}
```

The signed message (new domain byte `SESSION_CERT = 0x0C`):

```
digest(SESSION_CERT,
       chain_id || session_pubkey || identity_key_id
                || gateway_id || not_before_ms || not_after_ms)
```

- `chain_id` binds the certificate to one chain — the same
  transplant-prevention argument as the per-record signature (v0 §3.1).
- `session_pubkey` is what the record signatures resolve to: the verifier
  reads the cert, validates `identity_sig` under the identity key, then uses
  `session_pubkey` to check every record's `origin_sig`.

The `SessionCert` record itself is origin-signed in the envelope by the
session key, like every record. That is not circular: the envelope signature
proves the session key wrote the record; the `identity_sig` *inside* proves
the identity key blessed that session key. The verifier validates the inner
`identity_sig` first, then trusts `session_pubkey` for the envelope.

## 4. The signers

Two signer traits, mirroring the existing `Sealer`/`OriginSigner` split:

```rust
/// Long-lived, in hardware. Signs session certificates, never records.
pub trait IdentitySigner {
    fn key_id(&self) -> &str;
    fn public_key(&self) -> PublicKeyEntry;      // role: origin (enrolled in the bundle)
    fn certify(&self, msg: &[u8]) -> Result<[u8; 64]>;
}
```

- **`FileIdentitySigner`** (dev): a 32-byte seed, same custody class as
  `FileSealer` — acceptable for development and first design partners.
- **`Pkcs11IdentitySigner`** (prod): reuses the hand-rolled PKCS#11 bindings
  already shipped for the ledger's `Pkcs11Sealer` — same `dlopen`, same
  `C_Sign`, same "the host can sign now but cannot exfiltrate and sign later"
  guarantee. This is the payoff of having built the HSM path once: the
  identity signer is another consumer of it.

The **session key** needs no trait — it is an in-memory `SigningKey`
generated at session open (`getrandom`, already in the tree) and dropped at
session close. It is the existing `OriginSigner` role, now backed by a
freshly-generated key per session instead of a file seed. The
`OriginSigner` trait and the whole record-signing path are unchanged.

## 5. The gateway at session open

1. Generate a session `SigningKey` in memory.
2. Ask the `IdentitySigner` to `certify` it (one hardware operation per
   session, off the hot path).
3. Write the `SessionCert` record as the chain's first record (after the
   deployment reload, before the delegation), origin-signed by the session
   key.
4. Sign every subsequent record with the session key, exactly as today.

The identity signer is presented once, at startup (the `Pkcs11Sealer`
precedent: credentials presented once, never re-presented in a loop that
could lock the token). Over HTTP, each session generates its own session key
and certificate — a natural fit for the one-chain-per-session model, and the
reason the certificate is per-session rather than per-gateway.

Resume (`Wal::open_authenticated`) changes: the trusted set is no longer the
gateway's own key but the session key named by the chain's `SessionCert`,
which the gateway validates against its identity key (or the bundle's active
identity set, for rotation) before adopting the tail. A tail whose
`SessionCert` the identity key did not sign is foreign.

## 6. The verifier

The origin pass gains a preceding step: resolve session keys from the
certificates.

- For each `SessionCert` record: resolve `identity_key_id` in the origin key
  set (the deployment bundle's active identity keys, v1), validate
  `identity_sig`. On success, `session_pubkey` becomes a trusted origin key
  *for this chain only*, added to the origin map under its own id.
- Every record's `origin_sig` then resolves to the session key as today.

New findings:

- `session_cert_invalid` (**error**): a certificate whose `identity_sig` does
  not verify under a trusted identity key, or whose `chain_id`/`gateway_id`
  binding is wrong. Only tampering produces these.
- `session_cert_unverified` (**warning**, error under `require_origin`): a
  certificate whose `identity_key_id` resolves to no trusted key — the
  self-referential / unenrolled case, same logic as
  `deployment_bundle_unverified`.
- Records whose session key has no valid certificate fall to
  `origin_unverified`, exactly as an unsigned record does today.

### Validity window and time

A certificate's `not_before`/`not_after` can only be *enforced* against
trusted time. The pack already carries RFC 3161 anchors over checkpoints:

- when an anchor covers the checkpoint sealing the `SessionCert`, the window
  is checked against the anchored time (the certificate was valid *when the
  TSA saw it*) — enforceable against a third party;
- without an anchor, the window is **informational**: the binding
  (identity key → session key → chain) still holds, but "was it in date?"
  cannot be answered offline against a clock the verifier does not trust, and
  the report says so rather than checking against its own wall clock (which
  an evidence pack read years later would fail spuriously).

## 7. Rotation and revocation

- **Session keys** rotate every session, automatically and invisibly. There
  is no session-key rotation *operation* — expiry is the default.
- **Identity keys** rotate through the v1 deployment bundle: enroll the new
  identity key, keep the old one during the overlap, republish; retire the
  old one in a later republish. The bundle already carries the active set and
  the resume path already accepts any active key (v1's 1b), so a chain
  certified by a predecessor identity key still resumes during the overlap.
- **Revocation** of an identity key is bundle-removal + republish (v1
  semantics, unchanged): it bounds the future; sealed history stays valid
  because the checkpoint attests the certificate verified at seal time.

## 8. What v2 deliberately does not do

- **Remote attestation** (§7.5): binding the identity key to a measured boot
  and a measured gateway binary via a TPM quote. That strengthens the claim
  from "an origin signed this" to "an origin running *this software* signed
  this", and is the v3 horizon — pulled by a regulator's question, not
  pushed. The v2 enrollment record is deliberately one signed field away from
  carrying a quote.
- **Post-quantum signatures**: still just the `algo`/`key_id` agility already
  present (v0 §7.3). Do not build it now.

## 9. Implementation plan

Each step green on its own, the established discipline:

1. **obsign-audit-core**: `domain::SESSION_CERT` (0x0C), `Payload::SessionCert`
   (tag 9) + its encoding, `session_cert_signing_bytes`, a
   `SessionCert::verify(identity_vk)` helper. The frozen-format reference
   vector in `tamper.rs` gains a `session_cert` case and every existing hash
   must stay put — the tripwire that proves tag 9 touched nothing.
2. **obsign-audit-core evidence**: resolve session certs before the origin pass, the
   two findings, anchored-time window check. Tamper tests: forged cert,
   cert for the wrong chain, unenrolled identity key, a record signed by a
   session key with no cert.
3. **identity/signer crate**: `IdentitySigner` trait, `FileIdentitySigner`,
   and `Pkcs11IdentitySigner` behind the existing PKCS#11 module (reused, not
   rewritten). Where these live: a new `origin-signer` home, or extend the
   ledger's PKCS#11 module into a shared crate — see open decision 3.
4. **obsign-proxy**: generate the session key, certify at session open,
   write the `SessionCert` record, resume against the certified session key.
   `--identity-key` (file seed) / `--identity-hsm-*` (PKCS#11), replacing
   `--origin-key`. The `OriginSigner` backed by the ephemeral key.
5. **obsign verify**: report the certificate chain, the window verdict.
6. **control-plane / docs**: the enrolled key is now an *identity* key; the
   `deployment/origin-keys.json` semantics and the runbook updated.

The new surface is the certificate and the identity-signer trait; the record
path, envelope, bundle, and seal are untouched. Tests are the bulk, as ever.

## 10. Open decisions (need a call before implementation)

1. **`SessionCert` in-chain (tag 9) vs. pack envelope field.** *Recommended:
   in-chain*, as above — it is sealed (unstrippable), reads naturally at the
   chain top beside the delegation/deployment records, and uses the blessed
   new-tag extension. The objection to *per-record* in-chain attestation
   (v0's rejected option — coverage windows, log pollution) does not apply:
   this is one record per session, part of the chain's provenance story the
   delegation records already tell. The alternative (an envelope/pack field)
   is unsealed unless separately anchored, for no benefit.
2. **Dev identity custody: file seed vs. OS keychain.** *Recommended: file
   seed*, matching `FileSealer`, because the *point* of v2 is that production
   uses hardware (PKCS#11) — the dev seed is a stand-in exercising the
   `IdentitySigner` boundary, and the session key (the one that used to be a
   file) is memory-only in dev already. The seed file that "dies" in §7.6 is
   the per-record one; the identity seed is dev-only scaffolding for the
   hardware path.
3. **Where the identity signer + shared PKCS#11 lives.** The PKCS#11 bindings
   are currently private to the `obsign-ledger` crate (`Pkcs11Sealer`). v2 needs
   them for the *gateway's* identity signer too. Options: (a) lift the
   PKCS#11 module into a small shared crate both depend on; (b) duplicate the
   bindings in the proxy (the tamper-test precedent for deliberately not
   sharing forgery helpers — but this is infrastructure, not a forgery
   helper). *Recommended: (a)*, a `obsign-pkcs11` support crate — the bindings are
   audited infrastructure, and two hand-rolled copies drifting is the exact
   single-implementation-of-the-proof risk obsign-audit-core exists to avoid.
4. **Certificate lifetime default.** How long is `not_after - not_before`?
   *Recommended: bounded to the session, with a generous ceiling* (e.g. the
   session's expected max lifetime, hours not days) — the whole value is that
   a leaked session key expires soon. A concrete default belongs in the
   runbook, not hardcoded; the gateway sets it, the verifier enforces it only
   against anchored time (§6).
