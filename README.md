# Probant — enforceable audit log of agent actions

Verifiable proof of what your AI agents did to your systems: which human
delegated, to which agent, to call which tool, with which policy verdict.
Cryptographically sealed, exportable, and verifiable **offline** by an auditor
with access to neither your infrastructure nor ours.

This is not an observability product. Observability answers "what happened?"
for fifteen days. Here we answer "prove it", twenty-four months later, to
someone with no reason to believe you.

## Current state

The critical path runs end to end: an agent speaks MCP to the gateway, the
policy decides, the log is sealed, and the auditor verifies offline.

| Crate | Role | State |
|---|---|---|
| `audit-core` | Record format, hash chain, Merkle, signed sealing, verification | done |
| `probant` | Offline verifier — the CLI the auditor runs | done |
| `policy` | Signed bundles, Cedar evaluation, tool catalogue | done |
| `identity` | Signed identity bundle, claim mapping, RFC 8693 actor chain, hot rotation | done |
| `wal` | Durable local log, replay on startup | done |
| `probant-proxy` | MCP proxy (stdio and Streamable HTTP), `tools/list` filtering, `tools/call` arbitration | done |
| `ledger` | Sealing away from the gateway, checkpoint store, RFC 3161 anchoring, evidence export | done |
| `control-plane` | Compiling policies from git, console, exports | to come |

## Demo — the gateway at work

```bash
cargo build --workspace
cargo run -p policy --example mkbundle -- /tmp/demo
cargo run -p probant-proxy --example mint_demo_token -- /tmp/demo 1800 user

printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_production_db","arguments":{"database":"customers"}}}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ticket_update","arguments":{"ticket":"T-8821"}}}' \
 | ./target/debug/probant-proxy \
     --policy /tmp/demo/policy-bundle.json \
     --trusted-keys /tmp/demo/trusted-keys.json \
     --identity-bundle /tmp/demo/identity-bundle.json \
     --token-file /tmp/demo/token.jwt \
     --wal /tmp/demo/wal --chain-id demo --env prod \
     -- ./target/debug/mock-mcp-server
```

What happens:

```
[probant] identity PROVEN — u:marie.dupont via https://sso.acme.fr/realms/corp — expires in 1756 s
[probant] REFUSED delete_production_db: forbidden by an explicit rule
[probant] tools/list: 2 hidden — delete_production_db, exfiltrate_secrets
[server] EXECUTING ticket_update
```

The MCP server never saw the destructive call. `exfiltrate_secrets`, which the
server advertises but the signed catalogue does not describe, is refused too.

The resulting log:

```
seq=0   deleg-1  delegation     u:marie.dupont  iss=https://sso.acme.fr/realms/corp
seq=1   actor-1  actor          support-copilot -> u:marie.dupont  [delegated_human]
seq=2   agent-1  agent_session  support-copilot
seq=3   call-1   tool_call      delete_production_db
seq=4   dec-1    decision       DENY <forbid_destructive_prod>
seq=5   eff-1    effect         blocked
seq=6   call-2   tool_call      ticket_update
seq=7   dec-2    decision       ALLOW <allow_scoped>
seq=8   eff-2    effect         ok
```

The WAL under `/tmp/demo/wal` is the gateway's only output. It holds no
signing key — sealing that log into an evidence pack, with a key the gateway
never sees, is the ledger's job (see below).

With an expired token (`mint_demo_token -- /tmp/demo -3600`), the gateway
refuses to start and no call is relayed.

## Streamable HTTP — the enterprise transport

The same gateway serves MCP over Streamable HTTP: one shared network service
instead of one process per agent. Each `initialize` opens a session — its own
instance of the wrapped server, its own audit chain, its own identity — and the
token arrives per request in the `Authorization` header, where enterprise SSO
puts it. Deleting the session closes its chain; the ledger then seals it like
any other WAL, under `<chain-id>-<session>`.

```bash
cargo run -p probant-proxy -- \
    --http 127.0.0.1:8080 \
    --policy /tmp/demo/policy-bundle.json \
    --trusted-keys /tmp/demo/trusted-keys.json \
    --identity-bundle /tmp/demo/identity-bundle.json \
    --wal /tmp/demo/wal --chain-id demo --env prod \
    -- ./target/debug/mock-mcp-server

TOKEN=$(cat /tmp/demo/token.jwt)
SID=$(curl -si http://127.0.0.1:8080/mcp \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
      | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:" {print $2}')

curl -s http://127.0.0.1:8080/mcp \
     -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SID" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_production_db","arguments":{}}}'
# → isError: refused by policy, recorded, never reached the server

curl -s -X DELETE http://127.0.0.1:8080/mcp \
     -H "Mcp-Session-Id: $SID"
# → when this returns, the WAL holds the complete session (chain demo-$SID),
#   ready for a probant-ledger pass to seal
```

The HTTP layer is written by hand on `std::net` — no async runtime, no web
framework. The dependency list is part of the product, and the subset of
HTTP/1.1 this transport needs is smaller than any framework's tree. Inbound
HTTP does not touch the "no network calls" invariant, which bans *outbound*
dependencies (JWKS fetches, ledger round trips): identity and policy still
arrive as signed files.

## Identity: proven or declared

This is the distinction the whole attribution chain rests on. A log that traces
back to "marie.dupont" without being able to substantiate it was really her
proves nothing.

| | Proven (OIDC) | Declared (`--insecure-declared-identity`) |
|---|---|---|
| `principal_issuer` in the log | the real issuer | `cli://declared` |
| Expiry | from the `exp` claim | none |
| Verified | signature, `iss`, `aud`, `exp`, `nbf` | nothing |
| Use | production | development only |

Declared mode requires a flag whose name says what it is, and with no identity
configuration at all **the gateway refuses to start** — no silent fallback to
anonymous mode.

Four design choices worth knowing:

**No network calls.** The JWKS lives inside a signed identity bundle,
distributed by the control plane alongside the policy bundle — same channel,
same rotation cadence. The gateway stays deployable air-gapped and adds no
outbound surface to justify in a security review.

**The identity bundle is signed, not just the policy bundle.** The JWKS decides
*who can mint valid tokens*, and the claim mapping decides *which groups get
assigned*. Whoever can write that file can mint an identity for themselves and
bypass the whole attribution chain — the same threat as an unsigned rules file,
deserving the same answer.

**The algorithm comes from the JWKS, never from the token header.** That is the
classic JWT flaw: an attacker declares `HS256` and HMAC-signs with the IdP's
public key, which is public by definition. A dedicated test covers it.

**Expiry is re-evaluated on every act**, not only when the session opens. An
agent session routinely outlives a token; checking once at startup amounts to
drawing unlimited authority from a 30-minute token. If the token was renewed on
disk, the gateway picks it up and **records a new delegation** — otherwise an
act performed under a renewed token would appear authorized by an
already-expired delegation.

## Delegation chain

A token that says "marie.dupont" does not say *who was acting in her name*.
RFC 8693 token exchange does, and Probant records it.

| Token mode | Actor chain | `principal_kind` |
|---|---|---|
| User token | `u:marie.dupont` | `human` |
| Token exchange (`act` claim) | `support-copilot → u:marie.dupont` | `delegated_human` |
| `client_credentials` | `batch-agent` | `machine` |

The third case is the one nobody covers: a batch agent, with no human behind
it, deleting in production. It is recognised by `sub == client_id`, and the
policy can then express it:

```cedar
@id("destructive_requires_human")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };
```

"No agent destroys anything without an identifiable human at the end of the
chain." Cedar also receives `context.actor_chain` (a set),
`context.delegation_depth` (to bound multi-agent topologies) and
`context.principal_kind`.

Try the three modes:

```bash
cargo run -p probant-proxy --example mint_demo_token -- /tmp/demo 1800 exchange
cargo run -p probant-proxy --example mint_demo_token -- /tmp/demo 1800 service
```

## Identity providers

**Nothing is provider-specific, and that is deliberate.** Keycloak, Entra ID,
Okta and Ping are OIDC providers: they work as-is. A connector per product
would be the debt not to take on.

What varies is *where* each provider files the information. The identity bundle
therefore describes the paths, with `*` for segments whose name depends on the
client:

```json
"claims": {
  "subject":   "/sub",
  "scopes":    ["/scope", "/scp"],
  "groups":    ["/groups", "/roles",
                "/realm_access/roles",
                "/resource_access/*/roles"],
  "client_id": ["/client_id", "/azp"]
}
```

These defaults already cover Keycloak and Entra ID. The Keycloak case is worth
flagging: roles are **never** flat, everything sits under `realm_access.roles`
and `resource_access.<client>.roles`. A naive mapping returns empty groups, and
no `principal in Group::"dba"` rule ever matches — with no visible error.

Two realm-side configuration points for Keycloak, done once:

- **audience mapper** — by default access tokens carry `aud: "account"`, not
  your client ID. The gateway will refuse them, and that is intended: relaxing
  the audience check would let through a legitimate token issued for another
  service;
- **token exchange** — [officially supported since Keycloak 26.2](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2),
  enable it on the agent's client to obtain the `act` claim.

For SAML, put Keycloak **in front** as a SAML↔OIDC bridge. The gateway then
never has to know SAML exists.

### Key rotation

Providers rotate their signing keys routinely — Keycloak in particular, on its
realm keys. The gateway makes no network calls, so "rotation" means **reloading
the signed identity bundle from disk**, where the control plane published the
new version.

```bash
python3 scripts/demo-rotation.py /tmp/rot
```

```
[probant] identity PROVEN — u:marie.dupont via …/realms/corp — expires in 2 s — bundle identity@k1
[server] EXECUTING ticket_update
>>> rotation: the IdP moves to k2, the control plane republishes the bundle
[probant] rotation detected (unknown kid "k2") — identity bundle reloaded: identity@k2, 1 key(s)
[probant] delegation renewed (generation 2) — u:marie.dupont — expires in 3596 s
[server] EXECUTING ticket_update
```

Four properties worth knowing:

**Triggered by the unknown `kid`.** That is the exact signal of a rotation, so
reloading costs nothing in nominal operation: zero disk access as long as
nothing rotates. One retry only — looping would turn a permanently invalid
token into a disk-access loop.

**The signature is revalidated on every reload.** Without it, hot rotation
would be the easiest way to inject a JWKS: writing the file would be enough.

**An invalid bundle never takes the gateway down.** Botched deployment,
truncated or deleted file, bad signature: the previous configuration stays in
force and the service keeps running. The return type enforces it —
`ReloadOutcome::Failed` is not an `Err`, so no caller can treat it as fatal by
accident.

**Bounded frequency**, one attempt per second. A flood of tokens with random
`kid` values therefore causes one file read per second, not one per request.
Detection uses the content hash rather than the modification time: mtime
granularity goes up to one second on some filesystems, enough to miss two
writes close together.

## The ledger: sealing away from the gateway

As long as sealing happens inside the gateway, the signing key and the log
cohabit on one host: whoever compromises it can rewrite the log *and* re-seal
it, and the checkpoints then certify the attacker's version of history.
`probant-ledger` runs elsewhere — another machine, or a cron under another
identity — reads the WAL without ever writing to it, and seals with a key the
gateway never holds:

```bash
openssl rand -hex 32 > /tmp/demo/seal-seed.hex

./target/debug/probant-ledger seal \
    --wal /tmp/demo/wal --chain-id demo \
    --store /tmp/demo/ledger \
    --key /tmp/demo/seal-seed.hex --key-id seal-prod

./target/debug/probant-ledger export \
    --wal /tmp/demo/wal --chain-id demo \
    --store /tmp/demo/ledger --out /tmp/demo/evidence.json

./target/debug/probant verify /tmp/demo/evidence.json \
    --trusted-keys /tmp/demo/ledger/keys.json
```

Before sealing anything new, the ledger re-hashes the record at the sealed
boundary and compares it to the sealed head. A rewritten WAL — even one whose
chain was entirely recomputed and is internally consistent — is refused with
`DivergedLog`, and `run` mode exits non-zero on it: divergence never
self-heals, and looping over it would turn an incident into a heartbeat.

The key file is development-grade by construction. Signing goes through the
`Sealer` trait, which is the KMS/HSM boundary: a production implementation
forwards signatures to the HSM and the key material never enters this process
either. The trait also self-verifies every signature before it is persisted —
a misconfigured HSM key slot fails at sealing time, not twenty-four months
later in front of an auditor.

### RFC 3161 anchoring

A checkpoint signature proves *who* sealed, not *when*: the key holder could
backdate `ts_ms`. Anchoring the checkpoint hash at a timestamping authority
makes the date enforceable against a third party. The exchange is by file —
no HTTP client anywhere, air-gapped deployments come first:

```bash
./target/debug/probant-ledger anchor request \
    --store /tmp/demo/ledger --chain-id demo --out /tmp/demo/checkpoint.tsq
# carry the .tsq to your TSA (openssl ts reads and produces these), then:
./target/debug/probant-ledger anchor attach \
    --store /tmp/demo/ledger --chain-id demo \
    --response /tmp/demo/checkpoint.tsr --tsa "tsa.internal.acme.fr"
```

The response is only attached if the TSA granted it and the token imprints
exactly the checkpoint hash — the token names its own checkpoint, there is no
flag to get wrong. In the evidence pack, `probant verify` re-checks both
structurally and reports the anchors; the CMS signature of the token itself is
validated against the TSA certificate with standard tooling (`openssl ts
-verify`), and the report says so rather than passing a structural check off
as a cryptographic one.

## Demo — verification

```bash
cargo run -p audit-core --example gen_sample -- /tmp/sample
cargo run -p probant -- verify /tmp/sample/evidence.json \
    --trusted-keys /tmp/sample/trusted-keys.json
```

Tamper with the result and re-run:

```bash
sed -i '' 's/"outcome": "deny"/"outcome": "allow"/' /tmp/sample/evidence.json
cargo run -p probant -- verify /tmp/sample/evidence.json \
    --trusted-keys /tmp/sample/trusted-keys.json    # exit 1
```

Exit codes: `0` valid, `1` tampered, `2` execution error.

## What verification establishes

1. **No record removed, inserted or modified** — hash chain, contiguous `seq`.
2. **No wholesale rewrite** — the hash chain alone is not enough: whoever holds
   the database can recompute everything. It is the checkpoints, signed with a
   key outside the writing process (KMS/HSM), that close that hole.
3. **No seal spirited away** — checkpoints are chained to each other.
4. **What is not proven is said to be so** — a record that is consistent but
   covered by no valid checkpoint is reported, not passed over in silence.

Without `--trusted-keys`, verification establishes internal consistency only,
and the report says so explicitly. A forged pack signed with a made-up key
validates itself: key anchoring must come from another channel.

## Design decisions

**Hand-rolled canonical encoding, no JSON for hashes.** JSON allows too much
freedom (key order, whitespace, numbers): two serializers can produce two
hashes for the same data. Here every field is length-prefixed and concatenation
is injective. JSON stays the transport and reading format, never the
computation one.

**Hashes, not contents.** Prompts and tool arguments contain personal data. We
store the hash; the content, when retained, is encrypted with a key held by the
customer (`SealedRef`). We can prove *what* without being able to read it.

**Merkle with promotion, not duplication.** With an odd number of elements the
last one is promoted as-is. Duplication (CVE-2012-2459) lets you build two
different batches with the same root.

**Domain separation.** Records, leaves, internal nodes and checkpoints are
hashed with distinct prefixes, so none can be presented as another.

**A single implementation.** `audit-core` is the only place a hash is computed.
The gateway, the ledger, the control plane and the `probant` CLI all depend on it.
Two implementations would diverge, and the day the export says "valid" while
the verifier says "tampered", the product is worth nothing.

**The signed catalogue is authoritative.** A tool the bundle does not describe
is refused, even if the MCP server advertises it. An updated — or
compromised — server can publish new tools at any time; if they are not in the
catalogue, nobody approved their use.

**Stable rule identifiers, enforced.** Cedar numbers its rules `policy0`,
`policy1`… by file order. Since that identifier is engraved in the log,
inserting a rule at the top would silently rename all the following ones and
make every earlier record wrong. Every rule must therefore carry an
`@id("...")` annotation; a bundle missing one is rejected at load time.

**Durability before forwarding.** The gateway writes and `fsync`s the record
*before* letting the call go out to the tool. If the process dies in between,
we have the trace of an act that did not happen — awkward but defensible. The
other way round we would have an act with no trace, which ruins the product.

**`tools/list` filtering.** The agent only discovers the tools it can call. An
invisible tool is never attempted: that many fewer refusals to handle, and that
much less surface offered to a prompt injection.

## Format compatibility

The `Payload` discriminants and the canonical encoding are **frozen**. Changing
them invalidates every already-sealed log. A new payload type takes the next
free integer; we never renumber.

The rule has already been exercised: `Payload::Actor` (tag 7) was added after
the fact for the actor chain, rather than adding a field to `Delegation`. The
`record_format_is_frozen` test carries reference hashes for the existing
payloads — none of them moved. The day that test fails, the question is not
"how do I update the constants" but "which sealed logs have just been
invalidated".

## Known debt

**No KMS/HSM `Sealer` yet.** The gateway no longer holds any signing key —
its only output is the WAL, and every seal comes from the ledger. But the
only `Sealer` implementation is a seed file, one hardened host away from the
cohabitation problem the ledger exists to solve; the KMS/HSM implementation
behind the trait is still to write.

**Configuration reloads are not recorded.** An auditor asking "which keys were
trusted when this action happened?" gets only an indirect answer: the bundle
version is folded into the `config_hash` of the `agent_session` record, so it
is traceable only if a delegation was recorded after the reload. Doing it
properly needs a dedicated record type (tag 8).

**Dependency tree.** `audit-core` pulls in 36 transitive crates, `probant`
52 — 12 of them for `clap`. The stated goal is a tree an auditor reads end to
end. To get closer: manual `serde` implementations and hand-rolled argument
parsing in the verifier. Not a priority before the first design partner.

## Tests

```bash
cargo test --workspace     # 120 tests
```

Five families, each with a distinct role:

- `audit-core/tests/tamper.rs` — does not check that the code works but that it
  **detects**: modified verdict, deleted record, permuted order, wholly
  rewritten chain, spirited-away checkpoint. Plus the frozen-format reference
  vectors.
- `identity` — forged signature, modified payload, different issuer or
  audience, expired token, unknown or missing `kid`, algorithm confusion, HMAC
  key forbidden in a JWKS; plus claim mapping (nested Keycloak roles, `scope`
  vs `scp`), the actor chain (single `act`, multi-hop, bounded nesting, service
  account) and rotation (badly signed bundle rejected, truncated or deleted
  file survived, bounded frequency).
- `policy/tests/delegation.rs` — a service account cannot destroy, a delegated
  human can, and a chain that is too deep is refused.
- `ledger/tests/ledger.rs` — the rewritten-WAL attack (internally consistent
  chain, diverging from sealed history) is refused before any new seal;
  truncated logs, edited or spirited-away checkpoints and rebound key ids are
  detected; a torn final store line survives a crash; anchors round-trip into
  the evidence pack and foreign tokens do not attach. Each control has its
  paired legitimate-path test.
- `probant-proxy` — unit tests on expiry, delegation renewal and rotation recovery (at
  startup and mid-session), plus `tests/e2e.rs` which runs the real binary in
  front of an MCP server and checks that the refused call **never reaches the
  server**. Two of those tests are regressions found by a manual demo, not by
  unit tests: duplicated effect identifiers when two calls are in flight, and
  unstable Cedar rule identifiers. `tests/http.rs` covers the Streamable HTTP
  transport with a hand-written HTTP client — deliberately not a client
  library, so the tests share no assumptions with the hand-written server —
  and checks session isolation, per-request bearer identity, the SSE stream,
  and that each session's evidence pack seals and verifies independently.

## Toolchain

Pinned to 1.97.1 via `rust-toolchain.toml`, for two reasons: Cedar's
dependencies require rustc ≥ 1.89, and a proof product needs reproducible
builds — the compiler version is part of what will be audited. The pin is
scoped to this project.
