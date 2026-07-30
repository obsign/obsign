# WAL origin authentication — design

Status: **v0 implemented** (2026-07-30, branch `wal-origin-auth-design`,
188 tests). Closes exit-0 gap #2 from the 2026-07-29 adversarial review.
Sections 3–5 are as built; §7 is the agreed long-term target. Two points
were adjusted on contact with the code, both noted inline and marked
*(implementation note)*:

- A signature whose key is simply *absent from the trusted set* counts as
  **unverified** (warning, upgraded by `require`), not as the hard
  `origin_invalid` error §3.6 first proposed. Adversarially it is
  indistinguishable from an absent signature — an attacker gains nothing by
  attaching an unresolvable one — and a hard error would break every export
  in the rollout window where gateways sign before ledgers are configured.
  The hard error is reserved for what only tampering can produce: a bad
  signature under a *trusted* key, a role-confused key, half a
  signature/key-id pair.
- `obsign-ledger export` (and `seal`/`run`) takes `--trusted-origin-keys`;
  export embeds those entries in the pack beside the sealing keys, so a
  signed log self-describes. The gateway prints its public entry on stderr
  at startup — the operator's copy-paste path into that file.

## 1. The gap

Records carry only the SHA-256 hash chain. Every input to a record's hash is
public: an attacker with write access to the WAL directory — and nothing
else, no key — can fabricate a perfectly well-formed record and append it
after the sealed head. The honest ledger, on its next pass, finds a
consistent chain extension and **seals the forgery with the real key**.
`obsign verify --strict --trusted-keys` exits 0 over an act that never
happened.

The hash chain proves *internal consistency*; the checkpoint proves *who
sealed*. Nothing proves *who wrote*. That is the missing link: the sealer
certifies whatever the disk says, because the disk is its only source.

Two concrete attack windows today:

1. **Post-session append.** With the HTTP transport each session is its own
   chain file. Once the session closes, nothing will ever contradict a
   fabricated tail: the gateway that held the in-memory head is gone, and the
   ledger seals what it reads.
2. **Resume adoption.** `Wal::open` rebuilds the `ChainWriter` from the disk
   tail. A record fabricated while the gateway was down is silently *adopted*
   as the new head at restart — the honest gateway then chains its own
   authentic records on top of the forgery, laundering it.

(The mid-session window is already closed by accident: the gateway's
in-memory head does not move when the file does, so its next append writes a
conflicting `seq` and replay fails loudly with `BrokenChain`.)

## 2. Decision

**Per-record Ed25519 signature by the gateway, carried in the WAL/pack
envelope (never in the hashed record), verified at three points: ledger
before sealing, gateway at resume, verifier offline.**

The signature is *origin authentication*, deliberately layered outside the
frozen proof object:

- `Record` and `Record::hash()` are untouched. The frozen-format invariant
  holds: no field is added to the canonical encoding, no tag is renumbered.
- The signature travels as sibling fields in the serde envelope (WAL line and
  evidence pack). Old logs and old packs, which never had the fields, keep
  parsing; an absent signature is an absent proof, not a format break — the
  same rule the pack already applies to `anchors`.

### Why this shape and not the alternatives

**Rejected — HMAC with a ledger-shared secret.** Cheaper per record, but a
shared secret makes the ledger able to forge gateway records, destroying
non-repudiation between the two components — and the entire point of the
ledger split is that neither host has to be trusted with the other's
authority. Ed25519 is already in the dependency tree; signing costs ~20 µs
next to an fsync we already pay (~tens of µs on NVMe). Three records per tool
call means <100 µs added to an operation that includes a network round trip
to the tool. Asymmetric wins.

**Rejected — a new field in `Record`.** Changes the canonical encoding,
invalidates every sealed log. Forbidden by the invariant, and also
circular: a signature over a hash cannot be an input to that hash.

**Rejected — in-chain attestation records (new payload tag 9, gateway signs
the head every K records).** Attractive because the signature would sit
*inside* the sealed chain, unstrippable forever. But: (a) coverage gaps —
records after the last attestation are exactly the post-session-append
window, so the sealer must refuse to seal past the last attested seq, which
couples seal cadence to gateway attestation cadence for no benefit;
(b) it does not close the resume-adoption path (the gateway would adopt a
forged tail before noticing its next attestation disagrees); (c) it pollutes
the business log with crypto bookkeeping the investigator scrolls past.
A per-record envelope signature covers every record with no window, no new
tag, and simpler verification. If a future need arises to make origin proofs
survive *inside* the sealed object, an attestation tag can be added then —
tags are the sanctioned extension mechanism and the two designs compose.

## 3. Detailed design

### 3.1 The signed message

```
sig = Ed25519-sign(origin_key,
                   digest(domain::ORIGIN_RECORD, chain_id || record.hash()))
```

- New domain byte `ORIGIN_RECORD = 0x0A` in `obsign_audit_core::hash::domain`
  (0x09 is taken by `SignedChainHead` on the high-water-mark branch).
- `chain_id` is length-prefixed through the canonical `Encoder`, then the
  record hash: `e.str(chain_id).hash(&record.hash())`. The record hash
  already binds `seq`, `prev_hash`, `ts_ms`, ids and payload, so the
  signature is position-bound within the chain; adding `chain_id` closes
  cross-chain transplantation (the record itself does not carry its chain id
  — the filename does, and filenames are attacker-writable).
- Signing the 32-byte digest rather than the full record keeps the signer
  interface identical to `Sealer::sign` (message in, 64 bytes out), which
  matters for the PKCS#11/TPM road.

Replay analysis: a `(record, sig)` pair lifted from one chain fails on any
other chain (chain_id bound); within its own chain it fits only at its
original position (seq + prev_hash bound); stripping the sig is detected by
policy (3.5); substituting an attacker sig fails the trusted-key lookup.

### 3.2 Envelope format

WAL line and pack records become:

```rust
/// A record plus its origin authentication. The signature lives beside the
/// record, never inside it: Record::hash() is frozen.
#[derive(Serialize, Deserialize)]
pub struct SignedRecord {
    #[serde(flatten)]
    pub record: Record,
    /// Ed25519 over digest(ORIGIN_RECORD, chain_id || record.hash()), hex.
    /// Absent on logs written before origin authentication existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_key_id: Option<String>,
}
```

- Old JSONL lines deserialize with `None` fields; new lines are readable by
  `tail` exactly as before, two hex fields longer (+~150 bytes/line).
- `Evidence.records` becomes `Vec<SignedRecord>`; old packs (plain records)
  still parse, `FORMAT` string stays `obsign-evidence/1`. Bumping the format
  would make every existing pack unverifiable for a purely additive change —
  the `anchors` precedent applies.
- `wal::replay` keeps validating the hash chain on `record` exactly as
  today; it additionally returns the envelopes so callers can check origin.

### 3.3 The origin key

New trait in the gateway (mirror of `ledger::Sealer`, deliberately the same
shape):

```rust
pub trait OriginSigner {
    fn key_id(&self) -> &str;
    fn public_key(&self) -> PublicKeyEntry;   // role: "origin"
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error>;
}
```

- MVP: `FileOriginSigner`, a 32-byte hex seed file — same custody class as
  `FileSealer`, acceptable for development and first design partners.
- Roadmap: TPM / OS keychain / PKCS#11-backed signer, key generated
  in-hardware, public half enrolled at the control plane. The trait is the
  boundary; nothing above it changes.
- `PublicKeyEntry` gains `#[serde(default)] role: KeyRole` with
  `Seal | Origin` (default `Seal`, so every existing trusted-keys file and
  pack keeps its meaning). A checkpoint signed by an origin key, or a record
  signed by a seal key, is a verification **error**: role confusion between
  "wrote the log" and "certified the log" is precisely what the two-key
  architecture exists to prevent.

**Trust honesty note (goes in the code comment too):** the origin key lives
with the gateway process, i.e. on the host we assume the attacker can write
to. A disk-writer who can also *read the seed file* forges signatures. The
signature therefore raises the bar from "write WAL directory" to "read the
gateway's key material" — a real and worthwhile raise (WAL dirs get NFS
mounts, backup agents, log shippers; key files get 0600 and, on the roadmap,
hardware) — but it is not, and cannot be, a defense against a compromised
gateway process. The gateway *is* the origin; origin authentication cannot
defend against the origin. That residual is stated, not hidden.

### 3.4 Enforcement point 1 — the ledger refuses to seal forgeries

`seal_pass` gains the trusted origin key set (ledger config: a
`trusted-origin-keys` file of `PublicKeyEntry`, role `origin`). Before
sealing, every unsealed record's signature is verified:

- All good → seal as today.
- Record at seq *k* refused → **seal the authentic prefix `[from..k-1]`,
  then return a loud error naming seq *k*** (`Error::UnauthenticatedRecord`,
  which also names the prefix's upper bound so the operator sees both facts
  in one line). The prefix seals even below the `min_new` batching floor:
  those records' path to proof must not wait on an attacker.
  *(Implementation note: "refused" = no signature under `require`, an
  unresolvable key under `require`, or — always, even in rollout mode — an
  invalid signature under a trusted key or a half-attached pair.)*
- In `run` mode the error is fatal (exit non-zero, like `DivergedLog`): an
  unauthenticated record never self-heals, and looping over it would turn
  an incident into a heartbeat.

Sealing the prefix is deliberate: refusing the whole pass would let an
attacker append garbage to *suppress* sealing of honest records — turning a
forgery primitive into an anti-durability primitive. Sealing the prefix
preserves the honest records' path to proof and converts the attack into a
detected, attributable event. The error is the alarm; `run`-mode passes must
surface it on every iteration, not once.

Migration switch: `--require-origin` (ledger config). Off: unsigned records
seal with a logged warning (pre-upgrade gateways still work). On: unsigned =
unauthenticated, prefix-seal + alarm as above. Flip once every gateway in the
deployment signs. Per-chain grandfathering is not worth the complexity: the
cutover is per-deployment and operators know when their gateways upgraded.

### 3.5 Enforcement point 2 — the gateway refuses to adopt forgeries

`Wal::open` (the owning, resuming path — not the read-only `wal::read`)
verifies the origin signature of every replayed record against the
gateway's *own* current key before resuming on top of it. Any failure →
refuse to open (`Error::ForeignRecord { seq }`), do not trim, do not adopt.
A human decides: a record on disk that the gateway did not write is an
incident, not a recoverable I/O hiccup.

Verification cost is ~50 µs/record once, at open, on a path that already
re-hashes every record; chains are session-sized. Not a concern.

Edge: key rotation while a chain is live means a tail signed by the previous
key. MVP keeps this simple — the signer config may list previous public keys
as still-verifiable — but rotation mid-chain should simply be discouraged:
chains are session-scoped and short-lived; rotate between sessions.

### 3.6 Enforcement point 3 — the offline verifier

`obsign_audit_core::evidence::verify` learns three findings:

- `origin_invalid` (**error**): a signature present but cryptographically
  wrong under a trusted origin key, or half of the sig/key-id pair alone.
  Always an error — only tampering produces these.
- `key_role_mismatch` (**error**): a checkpoint signed by an origin key, or
  a record signed by a sealing key. Writer and certifier must stay distinct
  authorities, whichever way the confusion runs.
- `origin_unverified` (**warning**): records without signatures, or whose
  `origin_key_id` resolves to no trusted origin key *(implementation note:
  the unresolvable-key case was moved here from `origin_invalid` — see the
  status header)*. Self-referential key material is already covered by
  `keys_not_anchored`.
- `origin_not_required` semantics via `--require-origin` on `obsign
  verify`: upgrades `origin_unverified` to an error. Auditors of deployments
  that mandate origin auth run with the flag; `--strict` already fails on
  warnings, so strict runs catch stripped signatures today.

Why the verifier checks at all, given the ledger already refused to seal
forgeries: (a) defense in depth — a compromised *ledger host* config
(emptied trusted-origin-keys file) would seal anything, and the pack is the
last court; (b) the signatures survive in the pack, so the auditor's
verification does not have to trust that the ledger performed 3.4.

Note the interaction that closes the gap end-to-end: after this design, a
fabricated record is (1) never sealed — 3.4, (2) never adopted — 3.5, and
(3) if both those hosts are misconfigured, still visible offline — 3.6.
Reaching exit-0 with `--strict --trusted-keys --require-origin` now requires
the gateway's signing key, not a directory permission.

## 4. What this deliberately does not fix

- **Unsealed-tail deletion.** An attacker who *deletes* honest records
  between write and seal destroys evidence undetectably (until the ledger's
  `TruncatedLog` check, which only sees back to the sealed head). Exposure
  is bounded by seal cadence; this is the WAL-durability/seal-latency
  trade-off, unchanged by origin auth, and closed operationally (frequent
  passes) plus by gap #1's anchored head.
- **Origin key exfiltration.** See the trust note in 3.3; roadmap item, not
  MVP.
- **A compromised gateway process.** Out of scope by construction.

## 5. Implementation plan

**All six steps landed (2026-07-30).** The end-to-end loop is exercised
three ways: `tamper.rs` (7 origin attack tests, offline), `ledger.rs` (5
seal-side tests including forged-tail-after-sealed-head → prefix sealed +
alarm), and `e2e.rs` (the real binary signs; the public entry is parsed off
stderr exactly as an operator would; sealed and verified under
`--require-origin`). The live attack was also run by hand against the built
binaries: a fabricated record with a correctly recomputed hash chain — the
pre-v0 exit-0 scenario — now yields seal exit 1, verify
`--require-origin` exit 1 ("TAMPERING DETECTED"), and a gateway restart
that refuses to adopt the tail.

Order chosen so each step lands green on its own:

1. **obsign-audit-core**: `domain::ORIGIN_RECORD`, `SignedRecord`, `KeyRole` on
   `PublicKeyEntry` (serde-default), origin signing-bytes helper next to the
   one implementation of the proof (nothing else may recompute it).
   Evidence: `Vec<SignedRecord>` + the three findings + role checks.
   Tamper tests: forged append, stripped sig, cross-chain transplant,
   role-confused key, self-referential origin keys.
2. **wal**: envelopes in `append`/`replay`; `Wal::open` verification +
   `ForeignRecord`; signer plumbed in from the caller so the crate stays
   dependency-light (it takes a `&dyn` or a closure, not a key file).
3. **obsign-proxy**: `OriginSigner` + `FileOriginSigner`, `Session::write`
   signs before `wal.append` (durability order unchanged: chain → sign →
   fsync → forward). Config: `--origin-key` / env.
4. **ledger**: trusted-origin-keys config, 3.4 in `seal_pass` with
   prefix-seal semantics, `--require-origin`. Tests: forged tail after
   sealed head → prefix sealed + `UnauthenticatedRecord`; e2e: fabricated
   record can no longer reach a sealed checkpoint.
5. **obsign verify**: `--require-origin`, report fields
   (`records_origin_ok`), docs.
6. **control-plane export**: passes envelopes through untouched (export
   assembles, never judges).

Rough size: the mechanical surface is small (the envelope), the tests are
the bulk — consistent with this codebase's ratio.

## 6. Open decisions (need a call before implementation)

Long-term recommendations for all three in §7; the MVP calls below are
chosen so that every rung of §7's ladder is reachable without a breaking
change.

1. **Key custody at MVP** — seed file (proposed, matches `FileSealer`
   precedent) vs OS keychain from day one. Proposal: seed file, because the
   end state (§7.1) is not "keychain" anyway — it is a hardware identity key
   certifying per-session memory keys, and the seed file exercises the same
   `OriginSigner` boundary.
2. **Origin public-key distribution** — static trusted file on the ledger
   host (proposed for MVP) vs a control-plane-signed artifact. The signed
   bundle is the end state (§7.2): whoever writes the trusted-keys file
   mints authority — the identity/policy bundle precedent. It wants the
   format-rev work already deferred from the claims fix; bundle both there.
3. **`--require-origin` default flip** — per-deployment operationally at
   first; §7.4 argues the *default* must eventually invert.

## 7. Long-term target

The MVP raises the bar from "write the WAL directory" to "read the
gateway's key file". The end state removes the key file from the equation
entirely, and turns key distribution into the same signed-artifact story as
every other piece of authority in the system. Nothing in this section
changes the per-record signature, the envelope, or the pack format — the
ladder only changes where keys come from and how their public halves are
trusted. That is the property to protect when implementing the MVP.

### 7.1 Custody: two-tier keys, not per-record hardware signing

Naive end state — "the TPM signs every record" — is wrong on the hot path:
hardware signing is millisecond-class and serialized, against a per-record
budget set by an fsync in the tens of microseconds. Three records per tool
call through a TPM would multiply gateway latency by ~50.

The correct end state separates identity from throughput:

- **Gateway identity key** — generated *in hardware* (TPM 2.0 / Secure
  Enclave / PKCS#11), non-exportable, long-lived, enrolled once with the
  control plane. It signs rarely and never on the hot path.
- **Session origin key** — generated in memory at session open, never
  touches disk, discarded at session close. The identity key signs a
  **session certificate** over it at open: canonical encoding, own domain
  byte, covering `{session_pubkey, chain_id, gateway_id, not_before,
  not_after}`. Records are signed by the session key — same ~20 µs as the
  MVP, because it is the same code path with a different key provenance.

What this buys, in threat-model terms:

- **No origin key material on disk, ever.** The MVP residual (disk-reader
  forges) disappears rather than being mitigated.
- **Compromise window = one session.** A leaked session key forges one
  chain until its `not_after`; the identity key it would take to mint new
  certificates cannot leave the hardware.
- **Chain binding gets stronger.** The certificate names `chain_id`: a
  fabricated chain cannot obtain a certificate for its chain id without the
  hardware key, so whole-chain forgery (the post-session attack's big
  brother) fails at the certificate, not just at the record.

The verifier's chain of trust becomes: control-plane root → deployment
bundle (§7.2) → gateway identity key → session certificate → per-record
signature. The pack carries the certificate alongside the records;
certificate validity is judged against **anchored RFC 3161 time** when an
anchor is present, not the verifier's clock — the pack is read years later.

### 7.2 Distribution: a control-plane-signed deployment bundle

The static trusted-origin-keys file is the MVP's honest shortcut and the
long-term hole: whoever writes that file on the ledger host mints origin
authority, which is the exact threat the identity and policy bundles were
built to close. Same threat, same answer:

- A **deployment bundle**, signed by the control-plane root like the other
  two bundles: the set of gateway identity keys, each with validity window
  and revocation status, versioned `deployment@<sha>`.
- The **ledger** consumes it for 3.4; the **verifier** consumes it via
  `--trusted-keys` (which then carries one root of trust obtained out of
  band, instead of N ad-hoc key files).
- Reload of the bundle on the ledger/gateway is **recorded in the chain**
  (`ConfigReload` with a new `ConfigKind` — additive, the sanctioned
  extension), so "which origin keys were trusted when this act was sealed?"
  reads from the log exactly like the JWKS question does today.
- **Revocation** is bundle-removal plus republish. Sealed history stays
  valid: checkpoints attest that origin was verified at seal time, anchors
  attest when — revoking a key stops the future, it does not unwrite the
  past.

### 7.3 Crypto agility

`PublicKeyEntry` already carries `algo`; every signature reference carries
`key_id`. That is the whole agility story, kept deliberately boring: when a
post-quantum mandate arrives (auditor-driven, likely ML-DSA), a gateway
dual-signs — the envelope gains a second optional sig field, old verifiers
ignore it, new verifiers require whichever policy demands. No format break,
same additive rule as everything else. Do not build PQ now; do refuse any
MVP shortcut that hardcodes "ed25519" beyond the single point where
`PublicKeyEntry::to_verifying_key` already checks it.

### 7.4 Posture: strict becomes the default

Auditors run defaults. As long as unsigned records are a warning, the
product's headline claim ("exit 0 means proven") carries an asterisk only
experts read. Once design partners have rotated onto signing gateways:

- `--require-origin` disappears; requiring origin **is** the default;
- legacy unsigned chains need an explicit, ugly
  `--allow-unsigned-legacy-chains`, so the asterisk is typed by the person
  accepting it, not silently carried by everyone.

The same inversion eventually applies to `--trusted-keys` (gap #4): the
self-referential mode should be the flagged exception, not the default.

### 7.5 Horizon, explicitly not committed: attesting the origin itself

Origin authentication's hard limit (§3.3) is that it cannot defend against
a compromised gateway process — the origin signs whatever the origin says.
The only known answer beyond that line is **remote attestation**: the
gateway identity key held in a TPM whose quote binds it to a measured boot
and a measured gateway binary, the quote enrolled alongside the key in the
deployment bundle. The claim then strengthens from "the origin signed this"
to "an origin running *this exact software* signed this". Heavy, and worth
building only when a design partner's regulator asks the question — but the
§7.1 architecture is deliberately one signed structure away from it: the
enrollment record grows a quote field, nothing else moves.

### 7.6 Sequencing

- **v0 (MVP, this doc §3–5):** file-seed origin key, static trusted file,
  `--require-origin` opt-in. Design partners.
- **v1:** deployment bundle + rotation/revocation + reloads in-chain;
  default flips (§7.4). Requires the deferred format-rev train.
- **v2:** hardware identity key + per-session certified memory keys (§7.1);
  the seed file dies.
- **v3 (pull, not push):** attestation quotes in enrollment (§7.5).

Each rung changes key *provenance* only. The record path, the envelope, the
signed message and the pack survive every rung — which is exactly why the
MVP must cut its interfaces at `OriginSigner`, `PublicKeyEntry{key_id,
algo, role}`, and a trusted-key *set* input (file today, bundle tomorrow)
rather than a single `--origin-pubkey` flag.
