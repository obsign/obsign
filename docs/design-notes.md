# Design notes

The decisions behind the format and the gateway, what is still open, how the
test suite is organised and why the toolchain is pinned. Back to the
[README](../README.md).

## Design decisions

**Hand-rolled canonical encoding, no JSON for hashes.** JSON allows too much
freedom (key order, whitespace, numbers): two serializers can produce two
hashes for the same data. Here every field is length-prefixed and concatenation
is injective. JSON stays the transport and reading format, never the
computation one.

**Hashes, not contents.** Prompts and tool arguments contain personal data.
Only their hash is recorded: no component here retains the values, so a log or
an evidence pack has nothing to leak. The corollary is stated openly. A pack
proves *that* a tool was called and *under which rule*, without saying what
was passed to it; recovering the arguments means holding them already, and the
hash then proves they are the ones that went through. The format reserves
`SealedRef` for optional retention, encrypted to a key the customer holds;
nothing ships that today.

**Merkle with promotion, not duplication.** With an odd number of elements the
last one is promoted as-is. Duplication (CVE-2012-2459) lets you build two
different batches with the same root.

**Domain separation.** Records, leaves, internal nodes and checkpoints are
hashed with distinct prefixes, so none can be presented as another.

**A single implementation.** `obsign-audit-core` is the only place a hash is
computed. The gateway, the ledger, the control plane and the `obsign` CLI all
depend on it. Two implementations would diverge, and the day the export says
"valid" while the verifier says "tampered", the product is worth nothing.

**The signed catalogue is authoritative.** A tool the bundle does not describe
is refused, even if the MCP server advertises it. An updated or compromised
server can publish new tools at any time; if they are not in the catalogue,
nobody approved their use.

**Arguments become policy inputs only when declared.** The catalogue can
declare, per tool, which arguments the policy may read (`policy_args`: a name,
a JSON pointer, a type, an optional default); the gateway extracts exactly
those and Cedar sees them as `context.args`. That is where real refusals live
("`send_message`, but only to `#support`"), and what tool-level rules cannot
say. The declared allowlist is also the privacy boundary: values exist in
memory for the decision, the log keeps `args_hash`, and a field nobody declared
is never even read. Extraction is total: every declared arg arrives extracted,
defaulted, or the call is refused *before* Cedar runs. A crafted argument shape
is therefore a plain recorded denial, never an evaluation error, and the fail
mode stays reserved for failures of our machinery, out of the agent's reach.
One deliberate asymmetry: `tools/list` evaluates without arguments (a listing
has none), so an argument-restricted tool stays visible; visibility and
permission are different questions, and the call path is the enforcement
point. Declarations require `obsign-policy/2`; design:
[design/argument-policy-v1.md](design/argument-policy-v1.md).

**Stable rule identifiers, enforced.** Cedar numbers its rules `policy0`,
`policy1`… by file order. Since that identifier is engraved in the log,
inserting a rule at the top would silently rename all the following ones and
make every earlier record wrong. Every rule must therefore carry an
`@id("...")` annotation; a bundle missing one is rejected at load time.

**Durability before forwarding.** The gateway writes and `fsync`s the record
*before* letting the call go out to the tool. If the process dies in between,
we have the trace of an act that did not happen, which is awkward but
defensible. The other way round we would have an act with no trace, which
ruins the product.

**Discovery filtering.** The agent only discovers what it can access, since
`tools/list`, `resources/list` and `prompts/list` are all filtered. An
invisible tool is never attempted: that many fewer refusals to handle, and that
much less surface offered to a prompt injection.

**The read channels are arbitrated too.** `resources/read`, `resources/
subscribe`, `resources/unsubscribe` and `prompts/get` move data exactly as
`tools/call` does, so they go through the same gate: identity verified, policy
evaluated (Cedar actions `resource_read` and `prompt_get`, default deny),
attempt recorded (`mcp_access`), effect recorded. There is no signed catalogue
of resource URIs, because the server mints them at runtime, so policies match
the target exactly (`resource == Resource::"docs://runbook"`) or by pattern
(`context.target like "docs://*"`).

**Completions are held to the permission of what they complete.**
`completion/complete` enumerates the values of the object it references:
argument values for a prompt, URI expansions for a resource template. Left
unarbitrated it would walk around the `resources/list` filter, since what the
listing hides, the completer spells out. It therefore reuses the capability
of the referenced object (`ref/resource` maps to `resource_read`, `ref/prompt`
to `prompt_get`): complete only what you could read, and every attempt is
recorded.

**The method space is default-deny, in both directions.** A fixed allowlist
of protocol machinery (`initialize`, `ping`, the three `*/list` discoveries,
`logging/setLevel`, the defined notifications) is relayed as-is, and *only*
relayed: neither arbitrated nor recorded, an exemption with teeth (see the
notifications entry under Known debt); every arbitrated act goes through the
gate; anything else, a vendor extension or a future protocol revision, is
refused with `-32601` and recorded. The refusal's `policy_id` is absent: the
log tells a scope refusal apart from a rule's.

**Server-initiated channels are inside the perimeter.**
`sampling/createMessage` borrows the agent's model; `elicitation/create` puts
a question to the human. Both move data across the boundary in the direction
no policy used to see, so both are arbitrated under their own Cedar actions
(`sampling`, `elicitation`, granted per server:
`permit (principal, action == Action::"sampling", resource);`), default deny.
Refused, the gateway answers the server in the agent's place and records the
attempt; permitted, the request is recorded before it is forwarded and its
effect closes on the agent's response, the same call/decision/effect triple
as an agent act. `ping` and `roots/list` pass (the agent client answers roots
under its own control); unknown server requests are refused, unknown server
notifications dropped, and recorded either way.

## Format compatibility

The `Payload` discriminants and the canonical encoding are **frozen**. Changing
them invalidates every already-sealed log. A new payload type takes the next
free integer; we never renumber.

The rule has already been exercised several times: `Payload::Actor` (tag 7)
was added after the fact for the actor chain instead of a field on
`Delegation`, then `Payload::ConfigReload` (tag 8), `Payload::SessionCert`
(tag 9), `Payload::McpAccess` (tag 10) and `Payload::PrincipalLabel`
(tag 11) the same way. The last of those records a readable name *beside* an
opaque OIDC subject instead of replacing it, which a field on `Delegation`
could not have done without moving every sealed delegation's hash. The
`record_format_is_frozen` test carries reference hashes for the existing
payloads, and none of them moved any of those times. The day that test fails,
the question is not "how do I update the constants" but "which sealed logs
have just been invalidated".

Signed *bundles* evolve differently: their format string is part of the
signed bytes, so a revision is a new string, and every revision an artifact
was published under keeps verifying with the signing bytes of its day.
Exercised four times: `obsign-identity/2` extended the signed bytes with the
machine markers, `obsign-policy/2` with the argument declarations,
`obsign-identity/3` with the display-label claim paths, and
`obsign-identity/4` with a monotonic epoch a gateway will not reload below.
All follow the same two rules: an older bundle keeps its hash and signature,
and an older file carrying fields only a newer format signs is refused
instead of trusted (`UnsignedMachineMarkers`, `UnsignedLabelPaths`,
`UnsignedEpoch`); otherwise those fields would be unsigned authority. Identity
bundles older than `/4` carry no order: one counts as epoch 0, so it never
replaces a `/4` bundle on reload, but nothing orders two of them.

They differ on one point that decides the upgrade order. `obsign-policy/2` is
emitted only when a tool actually declares arguments, so a fleet that never
uses the feature never forces a gateway upgrade. `obsign-identity/3` was
emitted **unconditionally**, and `/4` is the same: upgrading the control plane
alone takes a fleet down, gateways first, control plane second
([deploy-docker.md](deploy-docker.md)). `/4` also needs an epoch at compile
time: the commit time of HEAD, `SOURCE_DATE_EPOCH`, or `--epoch` (required
with `--label`, or where no `git` binary can read the commit).

## Known debt

Three long-standing entries are paid off: the gateway no longer holds any
signing key (its only output is the WAL, every seal comes from the ledger),
`Pkcs11Sealer` puts the production sealing key behind a KMS/HSM, and
configuration reloads are recorded in the chain (tag 8).

**A narrow notification residual remains an unrecorded text channel.**
`notifications/message`, the one server notification that could spell out
the very tool and resource names the listing filter hides, is now
arbitrated per server under its own `notify` capability (default deny, as
`sampling` is), and what passes leaves an `mcp_access` record with the
payload hashed, never in clear. What stays exempt is genuine liveness/UX
machinery that carries free text but cannot enumerate the hidden catalogue:
`notifications/progress` (a `message`) and `notifications/cancelled` (a
`reason`), in both directions. Arbitrating every progress tick would put a
policy decision and an `fsync` on an unbounded hot path, so these remain a
conscious, documented exemption; the same `notify`-style gating is the exit
if a deployment ever needs them recorded too.

**Dependency tree.** Measured as unique crates in `cargo tree -e normal`.
The tree that carries the trust story is the auditor's: `obsign` builds
from 31 crates (`obsign-audit-core` 29); its argument parsing is
hand-rolled (the other binaries use `clap`), so `clap` and its subtree are
gone from that build. Of the 31, five are the
`serde` derive machinery (`serde_derive`, `syn`, `quote`, `proc-macro2`,
`unicode-ident`); manual `serde` implementations in `obsign-audit-core`, the
remaining lever, would leave ~26, nearly all of it the cryptography itself
(`curve25519-dalek`, `sha2` and their arithmetic support). The gateway is a
different story and deliberately so: `obsign-proxy` builds from 114 crates,
dominated by two justified subtrees: Cedar (68 crates; a closed decision)
and `jsonwebtoken` with aws-lc under it (37; enterprise IdPs sign RS256/ES256,
and hand-rolling RSA verification is not an option). The backend was `ring`
until jsonwebtoken 11 made it a feature and the choice became explicit: the
pure-Rust alternative pulls `rsa`, carrying an unfixable advisory on a path
`jwks.rs` genuinely reaches. Neither subtree reaches the auditor's binary. Not a priority before the first design partner.

## Tests

```bash
cargo test --workspace     # 370 tests
```

Six families, each with a distinct role:

- `obsign-audit-core/tests/tamper.rs` — does not check that the code works but
  that it **detects**: modified verdict, deleted record, permuted order,
  wholly rewritten chain, spirited-away checkpoint. Plus the frozen-format
  reference vectors.
- `obsign-identity` — forged signature, modified payload, different issuer or
  audience, expired token, unknown or missing `kid`, algorithm confusion, HMAC
  key forbidden in a JWKS; plus claim mapping (nested Keycloak roles, `scope`
  vs `scp`), the actor chain (single `act`, multi-hop, bounded nesting, service
  account) and rotation (badly signed bundle rejected, truncated or deleted
  file survived, bounded frequency).
- `obsign-policy/tests/delegation.rs` — a service account cannot destroy, a
  delegated human can, and a chain that is too deep is refused. `tests/args.rs`
  covers the argument rules: right channel through, wrong channel refused by
  its rule, crafted shape / float / oversize input refused at extraction even
  on a fail-open tool, an argument-driven evaluation error denied instead of
  failing open, a v1 bundle with injected declarations fails signature
  verification, and a rule reading an argument the catalogue does not declare
  is refused at compile time, naming the rule.
- `obsign-ledger/tests/ledger.rs` — the rewritten-WAL attack (internally
  consistent chain, diverging from sealed history) is refused before any new
  seal; truncated logs, edited or spirited-away checkpoints and rebound key
  ids are detected; a torn final store line survives a crash; anchors
  round-trip into the evidence pack and foreign tokens do not attach. Each
  control has its paired legitimate-path test. `tests/pkcs11_softhsm.rs` runs
  the same pipeline against a real PKCS#11 token: wrong PIN, absent key and
  wrong-type key refused by name, then an evidence pack sealed and verified
  end to end; it needs a provisioned token (`source
  scripts/pkcs11-test-env.sh`, SoftHSM) and passes vacuously without one.
- `obsign-control-plane/tests/control_plane.rs` — every refusal has its
  paired legitimate path: a rule without `@id`, a duplicate tool, a fail-mode
  override with a typo and an unusable JWKS are compile errors; a published
  version cannot change content but rollback (republishing an old sha) works;
  a key id cannot be rebound but rotation under a new id can; a rewritten WAL
  exports flagged invalid, never repaired; the console answers 405 to
  anything but GET and 404 to chain ids shaped like path traversals; git HEAD
  resolves from loose refs, packed refs and detached HEAD without a git
  binary. Compilation is byte-for-byte deterministic, tested by compiling
  twice.
- `obsign-proxy` — unit tests on expiry, delegation renewal and rotation
  recovery (at startup and mid-session, applied reloads and rejected ones both
  surfacing as `config_reload` records), plus `tests/e2e.rs` which runs the
  real binary in front of an MCP server and checks that the refused call
  **never reaches the server**, refused on its name or on its arguments alike.
  Two of those tests are regressions a manual demo found before the unit tests
  did: duplicated effect identifiers when two calls are in flight, and
  unstable Cedar rule identifiers. `tests/http.rs` covers the Streamable HTTP
  transport with a hand-written HTTP client (deliberately not a client
  library, so the tests share no assumptions with the hand-written server) and
  checks session isolation, per-request bearer identity, the SSE stream,
  and that each session's evidence pack seals and verifies independently.

## Toolchain

Pinned to 1.99.1 via `rust-toolchain.toml`, for two reasons: Cedar's
dependencies require rustc ≥ 1.89, and a proof product needs reproducible
builds, since the compiler version is part of what will be audited. The pin is
scoped to this project.

One system dependency beyond the toolchain: `cmake`, which builds the aws-lc
backend the JWT verification links against. Only the gateway needs it. The
offline verifier — the binary an auditor builds to check an evidence pack
without trusting us — does not, and `cargo build -p obsign` stays a rustup
and nothing else.
