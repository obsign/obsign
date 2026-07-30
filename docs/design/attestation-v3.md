# Remote attestation — v3 design

Status: **verification layer implemented** (2026-07-30, branch
`wal-origin-auth-design`, 221 tests) — option **(a)** of §10.4. Implements
§7.5 of [wal-origin-auth.md](wal-origin-auth.md), the horizon v2 §8 did not
commit to. Decisions 1–3 landed on their recommended defaults; decision 4 was
**(a)**: the auditor-facing verification layer is built and fully tested with
a `#[cfg(test)]` quote synthesizer (the RFC 3161 pattern), and the real-TPM
enrollment signer is deferred — **there is no TPM/`swtpm` on this machine, so
the hardware enroll/quote path is not exercised here.** What is built and
tested:

- **audit-core**: `KeyAttestation` + `PcrExpectation`, a bounds-checked
  `TPMS_ATTEST` parser (quote + certify, no recursion — the `rfc3161`
  discipline), `verify_attestation` doing the offline structural checks, and
  the `#[cfg(test)]` synthesizer. The attestation rides `DeploymentBundle`
  (a `#[serde(default)]` `Vec<KeyAttestation>`, **not** a field on
  `PublicKeyEntry` — enrollment concept, and no churn on every key literal),
  covered by the ops signature via `signing_bytes` (appended only when
  present, so v1 bundles stay byte-identical and keep verifying).
- **evidence**: `resolve_attestations` after the bundle resolution; findings
  `attestation_invalid` (error), `identity_not_attested`
  (warning → error under `require_attestation`), `attestation_not_rooted`
  (the standing out-of-band caveat, the `anchor_not_validated` shape).
  `VerifyOptions.require_attestation`.
- **control-plane**: `deployment/attestation.json` read and validated
  (each attestation must name an enrolled key), embedded at compile.
- **probant verify**: `--require-attestation`.

Live through the built binary: a bundle with an enrolled but **unattested**
identity key verifies with an `identity_not_attested` warning by default and
**fails under `--require-attestation`**. The forged/tampered/wrong-PCR/
wrong-key/truncated cases are covered by unit tests against the synthesizer;
a real TPM would replace the synthesizer, nothing above it.

**Deferred (needs a TPM/`swtpm`, unverified here):** the gateway-side
enrollment signer that produces the AK, the `TPM2_Certify` and the
`TPM2_Quote`. Interop caveat: the parser and synthesizer both encode *this
implementation's* reading of the TCG wire format; only real-hardware output
can confirm it, and the identity Name is bound as `alg || H(raw pubkey)`
rather than `alg || H(TPMT_PUBLIC)` — both are the flagged real-TPM interop
points.

---

*Original design follows.* Decision 4's testability caveat: **there is no
TPM or `swtpm` on this machine, so — unlike SoftHSM for v2 — the real-hardware
path cannot be end-to-end verified here.** That shaped the recommendation,
and option (a) above is what was built.

## 1. The hard limit v2 leaves

v2 removed signing-key material from disk: a leaked *session* key forges one
session, and minting new session certificates needs the hardware identity
key. But origin authentication's floor, stated since v0 §3.3, still stands:
**it cannot defend against a compromised gateway *process*.** The origin
signs whatever the origin says. An attacker who owns the running gateway
binary — a swapped executable, an injected library, a debugger — makes the
hardware identity key certify session keys for records that describe acts the
real software would have refused. Every signature verifies. The proof says
"an origin signed this"; it cannot say "an origin running the software you
reviewed signed this".

That gap is the one a regulator eventually names: *how do you know the
gateway enforcing the policy was the gateway you shipped?*

## 2. Decision

**Bind the identity key to a measured boot and a measured gateway binary via
a TPM quote, and enroll that attestation alongside the identity key in the
deployment bundle. The offline verifier checks the attestation structurally —
the quote binds *this* identity key, the measurements match the policy the
ops key signed — and defers the TPM-vendor certificate chain to an
out-of-band step, exactly as it already defers the RFC 3161 CMS signature.**

The claim then strengthens, provably and offline for the structural part,
from *an origin signed this* to *an origin whose boot state and binary match
the enrolled measurements signed this*.

Nothing in the chain, the record envelope, the session certificate, or the
seal changes. v3 is an **enrollment-time** strengthening of what a deployment
bundle's identity key *means* — the most additive place the whole ladder
could put it.

## 3. The TPM shape (why three keys, not one)

A TPM Attestation Key (AK) is *restricted*: it will only sign TPM-internal
structures (`TPMS_ATTEST`), never arbitrary external bytes. So the identity
key that signs session certificates (v2) cannot itself be the AK. The three
keys, and how they relate:

- **EK** (Endorsement Key) — burned in by the TPM vendor, its certificate
  chains to the vendor root. Proves "a genuine TPM".
- **AK** (Attestation Key) — created under the EK, restricted. Signs quotes
  and certifies other TPM keys. Its credential is bound to the EK via the
  standard `TPM2_MakeCredential`/`ActivateCredential` handshake at
  enrollment.
- **Identity key** — an ordinary (non-restricted) TPM signing key, TPM-
  resident, non-exportable. This is the v2 identity key, unchanged in role:
  it signs session certificates on the hot-path-adjacent per-session step.

Two TPM operations tie them together at enrollment:

- `TPM2_Certify(identity_key, AK)` → a signed statement that the identity key
  is TPM-resident with fixed, non-exportable properties. This is what binds
  *this* identity key (the one in the deployment bundle) to the attested TPM.
- `TPM2_Quote(AK, PCRs)` → a signed statement of the platform's PCR values:
  measured boot (firmware → bootloader → kernel) plus the **gateway binary
  hash**, extended into a PCR by the launch wrapper.

## 4. The enrollment attestation

The deployment bundle's identity-key entry grows an optional attestation.
`PublicKeyEntry` gains one `#[serde(default)]` field (the `anchors`
precedent — old bundles parse unchanged, and an absent attestation is an
absent proof, not a format break):

```rust
pub struct KeyAttestation {
    /// TPM AK public (the key that signed the quote and the certify).
    pub ak_pub: String,
    /// EK certificate (DER, hex): chains to the TPM vendor root. Validated
    /// out of band, like the RFC 3161 CMS signature.
    pub ek_cert: String,
    /// TPM2_Certify output binding the identity key to the AK (opaque
    /// TPMS_ATTEST + signature, hex).
    pub certify: String,
    /// TPM2_Quote over the PCRs (opaque TPMS_ATTEST + signature, hex).
    pub quote: String,
    /// The PCR selection and expected digests this quote must match —
    /// declared here so "the quote matches what was enrolled" is checkable,
    /// and covered by the ops signature over the bundle.
    pub expected_pcrs: Vec<PcrExpectation>,
}
```

Because it lives inside the bundle, the **ops key already signs it** (the
bundle `signing_bytes` covers every entry). So the attestation a verifier
reads is the attestation the control plane blessed at publish time — no new
probant-level signature, no new domain byte. The AK's own signatures over the
quote and certify are TPM-native (the TPM defines those bytes), carried
opaquely as the RFC 3161 token is.

### The gateway binary measurement closes on the release manifest

The expected gateway-binary PCR is the hash of the binary the **control
plane built and signed** — the same artifact the release manifest
(`RELEASE_MANIFEST`, domain 0x07) already covers. So the loop closes: the
control plane releases a gateway binary, records its hash, and enrolls that
hash as the expected PCR; a running gateway proves via the quote that it *is*
that binary. "Which software was enforcing the policy?" is answered by a
measurement chained to a signed release.

## 5. What the verifier checks — offline vs out of band

Modelled exactly on the anchor pass (`anchor_not_validated`): structural
consistency is proven offline; the cryptographic root is an out-of-band step
the report names, never silently skipped.

**Offline (in `evidence::verify`, when resolving the bundle's identity keys):**

- the AK signature over the `quote` and over the `certify` verifies under
  `ak_pub`;
- the `certify` binds the identity key present in the bundle entry (not some
  other key);
- the quote's PCR digests equal the `expected_pcrs` the ops key signed;
- findings: `attestation_invalid` (**error** — a signature or binding that
  does not hold; only tampering produces it), `identity_not_attested`
  (**warning**, error under a new `--require-attestation` — an identity key
  with no attestation, the self-referential/legacy case).

**Out of band (named, not performed offline):**

- the EK certificate chains to the TPM vendor root, and the AK is bound to
  that EK. This needs the vendor root CA and revocation state, which have no
  place in an air-gapped offline verifier by default. Finding
  `attestation_not_rooted` (**warning**): "the quote is structurally
  consistent and matches the enrolled measurements; this tool does not
  validate the EK certificate against a TPM vendor root — do so with
  `tpm2_checkquote` / the vendor chain." The exact shape of
  `anchor_not_validated`.

Why this split is the honest one: the offline check proves *this identity key
is bound to a TPM reporting these measurements*; the vendor-root check proves
*that TPM is genuine silicon, not a software fake*. Collapsing the second
into the offline verifier would either drag a vendor PKI into an air-gapped
tool or, worse, imply a guarantee it cannot make. The anchor pass already
taught auditors to read this exact caveat.

## 6. Rotation, revocation, and PCR churn

- **Binary updates** are the common case: every gateway release changes the
  expected binary PCR. That is already a control-plane operation — the new
  release carries the new expected PCR into a republished deployment bundle,
  the same enroll-by-commit flow v1 built. A gateway running the old binary
  then fails `attestation_invalid` against the new bundle, which is correct:
  it is not the shipped software.
- **AK/identity-key rotation and revocation** ride the v1 bundle mechanism
  unchanged (enroll new, overlap, retire; revoke = remove + republish).
- **Sealed history stays valid** on any of these: the checkpoint attests the
  attestation verified at seal time; revoking or re-measuring bounds the
  future, the release lineage dates the boundary.

## 7. What v3 deliberately does not do

- **Continuous / runtime attestation.** This is enrollment-time (and
  bundle-republish-time) attestation: it proves the gateway *booted* the
  measured binary, not that nothing was injected into the live process
  afterwards. Runtime integrity (IMA, periodic re-quote into the chain) is a
  further horizon; it would be the first thing to put *in* the chain (a new
  payload tag) rather than the bundle. Out of scope here, noted as the next
  pull.
- **A specific TPM vendor.** The quote and certify are standard `TPMS_ATTEST`;
  the parser is vendor-neutral like the PKCS#11 bindings. `swtpm` in
  test/CI, real silicon in production — the standard is the point.

## 8. Implementation shape

The verification layer is testable **without a TPM** and is where the
security logic lives; the signing/enrollment path needs a TPM (or `swtpm`)
and, on this machine, cannot be exercised (§10.4). Split accordingly:

1. **audit-core**: `KeyAttestation` on `PublicKeyEntry` (serde-default),
   `TPMS_ATTEST` parsing (bounds-checked, no-recursion, the RFC 3161 DER
   discipline), the offline checks in `evidence::verify`, the three findings,
   `--require-attestation` plumbed through `VerifyOptions`. **Tests: a
   `#[cfg(test)]` quote synthesizer** — an AK signing a hand-built
   `TPMS_ATTEST`, exactly as `rfc3161::testutil::granted_response` forges TSA
   responses — proving: valid attestation resolves, forged quote rejected,
   wrong-PCR rejected, certify bound to the wrong key rejected, absent
   attestation warns/errs under the flag. This exercises every line of the
   security logic with no hardware.
2. **control-plane**: read the expected PCR policy from the source tree
   (`deployment/attestation.json`, reviewed like the JWKS), carry the
   release binary hash into the expected-binary PCR, embed the enrollment
   attestation in the bundle.
3. **A TPM signer** (gateway enrollment side): produce the AK, the certify
   and the quote. This is the piece that needs real hardware; wrap `swtpm`
   for CI the way SoftHSM backs the PKCS#11 test, **gated on a provisioned
   TPM and skipped-vacuously without one** — and, here, unverified until a
   TPM/`swtpm` exists.
4. **probant verify**: `--require-attestation`, report the attestation
   verdict and the out-of-band caveat.

## 9. Rejected alternatives

- **Attestation in the chain, per session.** Puts platform state where the
  business log is, re-quotes on the hot-path-adjacent step, and answers a
  question (what booted) that does not change per session. Enrollment is its
  natural cadence. (Runtime re-quote *would* go in the chain — §7 — but that
  is a different, later thing.)
- **A probant-defined signature over the quote.** The TPM already signs
  `TPMS_ATTEST` with the AK; re-wrapping it in our own signature adds a key
  to trust and proves nothing more. Carry the TPM's bytes opaquely, verify
  them as the TPM defines — the RFC 3161 stance.
- **Full EK-chain validation offline.** Drags a vendor PKI into the
  air-gapped verifier and implies a genuineness guarantee an offline tool
  cannot honestly make. Out-of-band, named, like the TSA CMS check.

## 10. Open decisions (need a call before implementation)

1. **AK certifies the identity key vs. the identity key is the AK.**
   *Recommended: AK certifies a separate identity key* (§3) — TPM AKs are
   restricted and cannot sign session certificates, so the separation is
   forced by the standard, not a preference.
2. **Where the expected-PCR policy lives.** *Recommended: in the deployment
   bundle*, ops-signed, with the gateway-binary PCR chained to the release
   manifest (§4) — so "which software" is answered by a measurement tied to a
   signed release, and the enrollment attestation is covered by the ops
   signature for free.
3. **Offline structural + out-of-band vendor root.** *Recommended: yes*, the
   `anchor_not_validated` precedent (§5) — it is the only honest split for an
   air-gapped verifier, and auditors already read this caveat for timestamps.
4. **Scope now, given no local TPM/`swtpm` (the call the other rungs did not
   need).** Unlike SoftHSM for v2, this machine has no TPM, so the
   real-hardware enroll/quote path cannot be end-to-end verified here. Three
   ways:
   - **(a) Build the verification layer + synthesizer tests now, defer the
     real-TPM signer.** The security logic (parse + check quotes, the
     findings, `--require-attestation`) is fully testable with the
     `#[cfg(test)]` synthesizer, exactly as the RFC 3161 verifier was tested
     without a TSA. The gateway-side TPM signer lands gated-and-unverified,
     flagged for a machine that has a TPM. *Recommended* — it delivers and
     proves the part an auditor runs, and matches how the anchor verifier
     shipped ahead of any real TSA integration.
   - **(b) Install `swtpm` first** (`brew install swtpm` + `tpm2-tools`) so
     the enroll/quote path is exercised against a software TPM the way
     SoftHSM backs PKCS#11 — then build the full path verified. Heavier setup;
     turns (a)'s deferred piece into a tested one.
   - **(c) Design-only for now.** Stop at this document until a regulator or
     design partner actually pulls v3 (its §7.5 framing: pulled, not pushed),
     and spend the effort on the deferred `probant-identity/2` claims HIGH or
     the open mediums instead.

   My recommendation: **(a)** if v3 is wanted in code now — it lands the
   auditor-facing security logic with full test coverage and honestly gates
   the one piece this environment cannot verify; **(c)** is the right call if
   v3 is still horizon rather than a current requirement, because unlike
   v0–v2 there is no way to close the loop end-to-end here today.
