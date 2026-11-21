# Remote attestation — v4: credential activation, freshness, PCR-gated key

Status: **implemented, exercised end to end against swtpm and cross-checked
against go-tpm** (2026-11-22). Supersedes the claims of
[attestation-v3.md](attestation-v3.md), whose §3 and §5 described more than
the code proved. The v3 verification layer stays (an attestation in its
form still verifies, and is now reported for what it lacks).

## 1. What v3 actually proved, and what it did not

A review of the v3 code against its design found four gaps:

| v3 design said | v3 code did |
|---|---|
| The AK "is bound to the EK via `MakeCredential`/`ActivateCredential` at enrollment" | No activation anywhere. The AK was a `CreatePrimary` under the endorsement hierarchy; `ek_cert` rode beside it unbound, so a genuine EK certificate could be paired with an AK from a software TPM. |
| The quote is the platform's current state | `qualifyingData` was empty in both `TPM2_Quote` and `TPM2_Certify`, and the verifier skipped `extraData`: any earlier quote replayed. |
| The identity key is "TPM-resident, non-exportable" and bound to the measurements | Its `objectAttributes` were never checked, its `authPolicy` was empty and its password empty: any local process could sign with it whatever the PCRs held. The AK's `restricted` bit was assumed. |
| The quote proves "a running gateway *is* that binary" | `binary_hash` was an operator-supplied value the enroller extended into PCR 16 itself. |

v4 closes the first three in code and states the fourth precisely (§5).

## 2. The exchange

Four steps, two sides, files in between: the gateway host keeps its
no-network invariant, and the ops side needs no TPM.

```
gateway host                                   ops side (no TPM)
------------                                   -----------------
measure   PCR16 <- extend(H(gateway binary))   (launch wrapper)
request   EK (TCG template L-1), AK  ───────▶  challenge
                                               · EK: RSA-2048, restricted decrypt,
                                                 fixedTPM, TCG EK policy; EK cert
                                                 (if any) certifies its modulus
                                               · AK: restricted sign, fixedTPM,
                                                 fixedParent, sensitiveDataOrigin
                                               · nonce N, credential S (random)
                                               · MakeCredential(EK, Name(AK), S)
                                                 in software
respond   ◀───────────────────────────────────  challenge.json   (S kept: ops-state)
          · ActivateCredential(AK, EK) -> S
            (EK under a PolicySecret(endorsement) session)
          · q = SHA-256("obsign-tpm-activation/1\0" || N || S)
          · identity key: userWithAuth clear,
            authPolicy = PolicyPCR(PCR16 = value read now)
          · Certify(identity, AK, q), Quote(AK, PCR16, q)
          response.json  ─────────────────────▶  finish
                                               · same EK, AK, N as challenged
                                               · records S
                                               · --binary: PCR16 == H(0^32 || H(bin))
                                               · verify_attestation must pass
                                               attestation.json → deployment/
```

Why each piece:

- **Credential activation.** `TPM2_ActivateCredential` releases `S` only to
  a TPM that holds the EK the seed was encrypted to *and* a loaded object
  whose Name the integrity HMAC was keyed on. The AK's Name covers its
  attributes, so it names a `fixedTPM` key: one the TPM generated and will
  not export. A software AK cannot be loaded with those attributes. Knowing
  `S` therefore proves the AK lives in the TPM that owns the EK. Tested
  against swtpm: a credential made for TPM B's AK fails `TPM_RC_INTEGRITY`
  on TPM A, and one encrypted to TPM A's EK fails `TPM_RC_VALUE` on TPM B.
- **The qualifier.** Certify and quote carry `q` as `extraData`. It needs
  `S`, so only the activated AK's TPM could have produced statements that
  carry it, and it needs `N`, so they answer *this* challenge.
- **The PCR policy.** The identity key's `authPolicy` is the `PolicyPCR`
  digest over the enrolled PCR value, and `userWithAuth` is clear, so its
  empty password does not open it for signing. `TPM2_Sign` succeeds only in
  a policy session whose `PolicyPCR` saw the enrolled values. Tested
  against swtpm: one more extension of PCR 16 and `TPM2_Sign` fails
  `TPM_RC_POLICY_FAIL`. (`adminWithPolicy` stays clear: the ADMIN role,
  which `TPM2_Certify` needs, cannot sign or change the policy.)

`S` is recorded in the attestation once the exchange closes. It has done
its job by then, and recording it lets any verifier recompute `q`.

## 3. What the offline verifier checks

`obsign_audit_core::attestation::verify_attestation`, when the attestation
carries an `activation` (`ek_pub`, `ak_public`, `nonce`, `secret`):

1. everything v3 checked: AK signatures, the certify naming
   `alg || H(identity TPMT_PUBLIC)`, the raw key inside it equal to the
   bundle entry, the quote's PCR selection and digest equal to the ops-signed
   expectations;
2. `ak_public` holds `ak_pub`, and has `fixedTPM`, `fixedParent`,
   `sensitiveDataOrigin`, `restricted`, `sign`, and not `decrypt`;
3. `ek_pub` has the template L-1 shape: RSA-2048, SHA-256 names,
   AES-128-CFB, `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`,
   `adminWithPolicy`, `restricted`, `decrypt`, neither `sign` nor
   `userWithAuth`, and the published `PolicySecret(TPM_RH_ENDORSEMENT)`
   policy `837197…69aa` (computed and pinned by a test);
4. when `ek_cert` is present: its SubjectPublicKeyInfo is that EK's modulus,
   exponent 65537 (the certificate's own signature and chain stay out of
   band);
5. the identity key has `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`,
   `sign`, and none of `userWithAuth`, `restricted`, `decrypt`, and its
   `authPolicy` equals the `PolicyPCR` digest recomputed from the enrolled
   PCR values;
6. both statements' `extraData` equals `SHA-256(domain || nonce || secret)`.

The PCR selection bytes are built once, in `sha256_pcr_selection`, and used
both by the enroller (`TPM2_Quote`, `TPM2_PolicyPCR`) and by the policy
digest the verifier recomputes, so the two cannot drift apart.

An attestation without `activation` still verifies as before. `evidence`
then adds **`attestation_unbound`**: a warning by default, an error under
`--require-attestation`, naming what that form does not prove.

## 4. Format

The activation sits in `KeyAttestation`, which the deployment bundle signs.
Following the signed-bundle rule ([design notes](../design-notes.md#format-compatibility)):

- **`obsign-deployment/2`** appends each attestation's activation to the
  signing bytes, presence-tagged;
- **`obsign-deployment/1`** signing bytes are unchanged, pinned by a test
  against the value computed before this change; a `/1` bundle carrying an
  activation is refused as `UnsignedAttestationActivation` (its signature
  never covered it);
- the control plane emits `/2` **only when an attestation carries an
  activation** (`deployment::format_for`), the `obsign-policy/2` rule: a
  fleet that never enrolls this way never has to upgrade verifiers first.
  A fleet that does must upgrade ledgers and verifiers before publishing.

No record format and no frozen hash moves: the bundle is not a record.

## 5. What is proven, and what is not

With a v4 attestation in an ops-signed bundle, an auditor can establish
offline:

- the identity key is TPM-generated, cannot leave its TPM, and signs only
  while the enrolled PCRs hold the enrolled values;
- the AK that certified it and quoted those PCRs lives in the same TPM as
  the recorded EK, and the EK certificate, when carried, is for that EK;
- the statements were produced for this enrollment's challenge.

What it does **not** prove:

1. **That the EK is genuine silicon.** The certificate's chain to a vendor
   root is not checked; `attestation_not_rooted` keeps saying so. Without a
   certificate, a software TPM passes every check above, its own EK and all.
2. **That ops kept `S` secret until `finish`.** Whoever held `S` before the
   exchange closed could qualify statements from any AK. The ops state is
   written owner-only and the bundle's ops signature vouches for the
   enrollment; nothing in the attestation can.
3. **That the gateway runs the measured binary.** PCR 16 holding
   `H(0^32 || H(binary))` proves that *something* extended that PCR once
   with that hash since its last reset, and nothing else since. The
   measurement is made by software (`obsign-tpm-enroll measure`, the launch
   wrapper), not by a measured-boot chain, and PCR 16 is the debug PCR,
   resettable from locality 0: anyone with access to the TPM can reset it,
   extend the expected hash, and then use the identity key. What `finish
   --binary` adds is that ops compares the enrolled value with the release
   it knows, instead of taking the gateway host's word. Production needs a
   PCR that locality 0 cannot reset and that a measured-boot or IMA
   component extends, plus the boot PCRs in the expectations; the verifier
   and the policy digest handle several PCRs, the enroller's CLI takes one.
4. **Anything at runtime.** As in v3 §7: the PCR gate is checked at each
   signature, but nothing stops an attacker who already controls the
   running process from asking the key to sign while the PCR is right.
5. **That the gateway signs with this key.** The gateway's identity signer
   is PKCS#11 and ed25519 (`obsign-proxy/src/origin.rs`). swtpm implements
   no EdDSA and real TPMs rarely do, so the TPM identity key is P-256 in
   practice, and the bundle accepts only ed25519 origin keys.
   `obsign_tpm_enroll::sign` (CLI `sign`) is the policy-session signing
   path such a key must take, and it is tested, but no gateway code calls
   it yet. Until P-256 origin keys or EdDSA hardware exist, a v4
   attestation proves the properties above about a key that does not yet
   sign session certificates.
6. **Hierarchy authorization.** Enrollment assumes empty endorsement and
   owner hierarchy auth, as v3 did.

## 6. Choices and rejected alternatives

- **RSA EK, not ECC.** The credential needs public-key encryption to the
  EK. With an RSA EK that is one RSA public-exponent operation; an ECC EK
  needs ECDH with an ephemeral *secret* scalar, which the verification-only
  P-256 in audit-core deliberately does not implement. The RSA-2048 EK
  (template L-1) is also the one TPM 2.0 manufacturers ship a certificate
  for. An ECC EK is refused.
- **MakeCredential hand-rolled in the enroller**, not a crypto stack (no
  `aes`, `rsa` or `hmac` crate in the tree), pinned by FIPS-197, SP 800-38A
  and RFC 4231 vectors, and cross-checked twice: swtpm activates its output,
  and our activation path recovers a credential made by go-tpm's
  `credactivation`. It lives in `obsign-tpm-enroll`, not audit-core: it is
  not verification, and the auditor never runs it.
- **The verifier does not re-run MakeCredential.** Recording the seed and
  the OAEP randomness would let it recompute the blob, but it would still
  rest on ops having kept `S` secret, so it would prove nothing beyond (2).
  It recomputes the qualifier instead.
- **AK and identity key as primaries**, regenerated from the hierarchy seed
  and template at every step (and at signing time), so nothing is persisted
  on the host between `request`, `respond` and `sign`. The AK is a primary
  of the endorsement hierarchy rather than a child of the EK. Activation
  binds them all the same: it needs both loaded in one TPM.
- **The quote and certify share one qualifier**, rather than two nonces:
  both must answer the same challenge, and the verifier checks both.
