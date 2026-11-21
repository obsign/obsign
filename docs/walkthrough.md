# Walkthrough

Hands-on tour of the whole pipeline, from an MCP call refused at the gateway
to an evidence pack verified offline. Every command runs from a checkout
after `cargo build --workspace`. For the short version, see the
[README](../README.md).

## The gateway at work

```bash
cargo build --workspace
cargo run -p obsign-policy --example mkbundle -- /tmp/demo
cargo run -p obsign-proxy --example mint_demo_token -- /tmp/demo 1800 user

printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_production_db","arguments":{"database":"customers"}}}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ticket_update","arguments":{"ticket":"T-8821"}}}' \
 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_message","arguments":{"channel":"#support","text":"T-8821 updated"}}}' \
 '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"send_message","arguments":{"channel":"#all-hands","text":"T-8821 updated"}}}' \
 | ./target/debug/obsign-proxy \
     --policy /tmp/demo/policy-bundle.json \
     --trusted-keys /tmp/demo/trusted-keys.json \
     --identity-bundle /tmp/demo/identity-bundle.json \
     --token-file /tmp/demo/token.jwt \
     --wal /tmp/demo/wal --chain-id demo --env prod \
     --server-id mcp://mock.demo \
     -- ./target/debug/mock-mcp-server
```

What happens:

```
[obsign] identity PROVEN — u:marie.dupont via https://sso.acme.fr/realms/corp — expires in 1756 s
[obsign] REFUSED delete_production_db: forbidden by an explicit rule
[obsign] tools/list: 2 hidden — delete_production_db, exfiltrate_secrets
[server] EXECUTING ticket_update
[server] EXECUTING send_message
[obsign] REFUSED send_message: forbidden by an explicit rule
```

The MCP server never saw the destructive call. `exfiltrate_secrets`, which the
server advertises but the signed catalogue does not describe, is refused too.
And `send_message` was executed exactly once. Same tool, two verdicts, and the
difference is an *argument*. The catalogue declares which arguments the policy
may read (`policy_args`), and the rule decides on the value:

```cedar
@id("support_channel_only")
forbid (principal, action == Action::"tool_call", resource == Tool::"send_message")
when { context.args.channel != "#support" };
```

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
seq=8   call-3   tool_call      send_message
seq=9   dec-3    decision       ALLOW <allow_unscoped>
seq=10  eff-2    effect         ok
seq=11  call-4   tool_call      send_message
seq=12  dec-4    decision       DENY <support_channel_only>
seq=13  eff-4    effect         blocked
seq=14  eff-3    effect         ok
```

(Effects close out of order. The blocked one is written at decision time, the
ok ones when the server answers. `eff-N` binds to `call-N` by construction,
so the log stays unambiguous whatever the interleaving; the channel value
itself appears nowhere, the record keeps `args_hash`.)

The WAL under `/tmp/demo/wal` is the gateway's only output. It holds no
signing key. Sealing that log into an evidence pack, with a key the gateway
never sees, is the ledger's job (see below).

With an expired token (`mint_demo_token -- /tmp/demo -3600`), the gateway
refuses to start and no call is relayed.

## Streamable HTTP, the enterprise transport

The same gateway serves MCP over Streamable HTTP: one shared network service
instead of one process per agent. Each `initialize` opens a session with its
own instance of the wrapped server, its own audit chain and its own identity,
and the token arrives per request in the `Authorization` header, where
enterprise SSO puts it. Deleting the session closes its chain; the ledger then
seals it like any other WAL, under `<chain-id>-<session>`.

```bash
cargo run -p obsign-proxy -- \
    --http 127.0.0.1:8080 \
    --policy /tmp/demo/policy-bundle.json \
    --trusted-keys /tmp/demo/trusted-keys.json \
    --identity-bundle /tmp/demo/identity-bundle.json \
    --wal /tmp/demo/wal --chain-id demo --env prod \
    --server-id mcp://mock.demo \
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
     -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SID"
# → when this returns, the WAL holds the complete session (chain demo-$SID),
#   ready for a obsign-ledger pass to seal
```

The HTTP layer is written by hand on `std::net`, with no async runtime and no
web framework. The dependency list is part of the product, and the subset of
HTTP/1.1 this transport needs is smaller than any framework's tree. Inbound
HTTP does not touch the "no network calls" invariant, which bans *outbound*
dependencies (JWKS fetches, ledger round trips): identity and policy still
arrive as signed files.

The transport is plain HTTP by the same argument (no TLS stack in the
auditable tree), and the bearer token must therefore never cross a network
in clear: TLS terminates in a reverse proxy in front, and the gateway
listens only where TLS ends. Tested nginx and Caddy configurations, the
proxy contract (SSE buffering, timeouts, the `Origin` allowlist), and the
probes to check a deployment: [deploy-tls.md](deploy-tls.md).

## The ledger: sealing away from the gateway

As long as sealing happens inside the gateway, the signing key and the log
cohabit on one host: whoever compromises it can rewrite the log *and* re-seal
it, and the checkpoints then certify the attacker's version of history.
`obsign-ledger` runs elsewhere (another machine, or a cron under another
identity), reads the WAL without ever writing to it, and seals with a key the
gateway never holds:

```bash
openssl rand -hex 32 > /tmp/demo/seal-seed.hex

./target/debug/obsign-ledger seal \
    --wal /tmp/demo/wal --chain-id demo \
    --store /tmp/demo/ledger \
    --key /tmp/demo/seal-seed.hex --key-id seal-prod

./target/debug/obsign-ledger export \
    --wal /tmp/demo/wal --chain-id demo \
    --store /tmp/demo/ledger --out /tmp/demo/evidence.json

./target/debug/obsign verify /tmp/demo/evidence.json \
    --trusted-keys /tmp/demo/ledger/keys.json
```

Before sealing anything new, the ledger re-hashes the record at the sealed
boundary and compares it to the sealed head. A rewritten WAL, even one whose
chain was entirely recomputed and is internally consistent, is refused with
`DivergedLog`, and `run` mode exits non-zero on it: divergence never
self-heals, and looping over it would turn an incident into a heartbeat.
Exiting is only half of alerting; who gets told is the supervisor's job, and
the air-gap-compatible pattern (systemd `OnFailure=`) is in
[alerting.md](alerting.md).

The key file is development-grade by construction. Signing goes through the
`Sealer` trait, which is the KMS/HSM boundary, and the production
implementation is `Pkcs11Sealer`: the key lives in an HSM behind the vendor's
PKCS#11 module, and never enters this process either. The trait self-verifies
every signature before it is persisted, so a misconfigured HSM key slot fails
at sealing time, long before an auditor opens the pack twenty-four months
later.

### Sealing through an HSM (PKCS#11)

PKCS#11 is the interface the target deployments actually have, whether on-prem
HSMs (Trustway, Luna, YubiHSM), smartcard middleware or SoftHSM in development,
and it is a local library call: the module may reach a network HSM internally,
but the ledger itself still makes no network call. A cloud KMS would be
another implementation of the same trait; it is deliberately not this one,
because it would break both that rule and the air-gapped story. The bindings
are hand-rolled over `dlopen`, in the spirit of the HTTP and DER code: the
seven calls sealing needs, without the binding crate that would drag in the
other sixty-one.

```bash
./target/debug/obsign-ledger seal \
    --wal /tmp/demo/wal --chain-id demo \
    --store /tmp/demo/ledger \
    --hsm-module /usr/lib/pkcs11/vendor.so \
    --hsm-key-label seal-prod \
    --hsm-pin-file /etc/obsign/hsm-pin \
    --key-id seal-prod
```

The key pair (Ed25519, both halves under the same label and the same
`CKA_ID`, which is what binds them) is provisioned with
the vendor's tooling; the ledger only ever asks the token to sign, over a
read-only session. When the module exposes several tokens, `--hsm-token-label`
or `--hsm-slot` picks one (a label carried by several tokens is refused, not
resolved by slot order); the PIN comes from a file or `OBSIGN_HSM_PIN`,
never from an argument (arguments end up in `ps` and shell history). Both
are trimmed of surrounding whitespace, and a PIN file readable by group or
others is refused: `chmod 600` it, owned by the ledger's user.
Everything that can be misconfigured fails at startup with the vendor's error
code in clear text: wrong PIN, absent key, or a key of the wrong type. A
P-256 key under the right label is refused as such, instead of being left to
die in signature verification. In `run` mode the PIN is presented exactly
once, at startup: a retry loop that re-presented a wrong PIN every interval
would walk the token to `CKR_PIN_LOCKED`.

What the HSM buys: a compromised ledger host can sign *now*, but cannot
exfiltrate the key and re-seal history *later, offline, at leisure*. What it
does not buy: the HSM signs what it is handed and cannot know whether a
checkpoint honestly summarizes the WAL. That remains the ledger's divergence
detection, one host over from the gateway.

### RFC 3161 anchoring

A checkpoint signature proves *who* sealed; the *when* is only the key
holder's word, since they could backdate `ts_ms`. Anchoring the checkpoint hash
at a timestamping authority makes the date enforceable against a third party.
The exchange is by file, with no HTTP client anywhere, because air-gapped
deployments come first:

```bash
./target/debug/obsign-ledger anchor request \
    --store /tmp/demo/ledger --chain-id demo --out /tmp/demo/checkpoint.tsq
# carry the .tsq to your TSA (openssl ts reads and produces these), then:
./target/debug/obsign-ledger anchor attach \
    --store /tmp/demo/ledger --chain-id demo \
    --response /tmp/demo/checkpoint.tsr --tsa "tsa.internal.acme.fr"
```

The response is only attached if the TSA granted it and the token imprints
exactly the checkpoint hash; the token names its own checkpoint, so there is no
flag to get wrong. In the evidence pack, `obsign verify` re-checks both
structurally (a SHA-256 imprint, a well-formed `genTime`) and lists each anchor
with the time the TSA gave it; an anchor over a checkpoint that failed
verification is shown but not counted. The CMS signature of the token itself is
validated against the TSA certificate with standard tooling (`openssl ts
-verify`), and the report says so instead of passing a structural check off
as a cryptographic one. It says so as a `CAVEAT`, not a warning: the check is
one this tool cannot do offline, so `--strict` does not fail an anchored pack
for it, and the verdict line reminds you it is still yours to run.

## The control plane: from git to the fleet

Everything the gateway trusts arrives as a signed file. `obsign-control` is
where those files come from, and the reason a rule change is a dated,
reviewed pull request instead of a click in a UI. Authoring the rules
themselves (the model Cedar sees, the catalogue, argument rules, rollout
and the backup that keeps old versions readable) is covered in
[policies-cedar.md](policies-cedar.md). Every field of every file
in that source tree, with its type, default and accepted values:
[policy-source-reference.md](policy-source-reference.md).

```bash
# the source tree is a git checkout:
#   policies/*.cedar   tools.json   fail-mode.json   identity/{provider,jwks}.json
openssl rand -hex 32 > /tmp/ops.hex

./target/debug/obsign-control publish \
    --source ~/acme-policies --key /tmp/ops.hex --key-id ops-2026 \
    --dist /srv/obsign/dist
# [control] compiled policies@847d4fca5754 — 1 rule file(s), 2 tool(s), ...
# [control] published release 847d4fca5754 -> /srv/obsign/dist/releases/847d4fca5754
```

The version *is* the commit sha, resolved by reading `.git` directly, with no
git binary required on the build host, worktrees and packed refs included.
Every decision recorded in the log cites `policies@<sha>`; replaying it months
later means checking out that sha.

Compilation validates with the gateway's own code paths (`Engine::load`,
`KeyStore::from_set`), so what passes in CI cannot fail at startup across the
fleet: Cedar syntax, the mandatory `@id` on every rule, duplicate tools,
fail-mode overrides naming tools that do not exist, unusable or forbidden
JWKS keys. The JWKS is a file in git, reviewed like a rule; it decides who
can mint identities, and fetching it from the IdP is the job of whatever
refreshes the repository, never of a gateway-side network call.

Rules are also **type-checked against the model the gateway exposes**,
derived from your own catalogue: `principal.department` or
`context.enviroment` fails to compile, instead of surfacing as an evaluation
error in production, where it would fall to the fail mode and, on a fail-open
tool, turn a `forbid` into a rule that never forbids. `obsign-control
schema` writes that model out as a Cedar schema you commit, so the [Cedar VS
Code extension](policies-cedar.md#your-editor) runs the same check while
you type.

Publication holds two invariants:

- **a version is immutable** — `releases/<sha>/` is written once; publishing
  different content under an existing sha is refused. A crash mid-publish is
  repaired on the next run, a changed source is not;
- **the current files change atomically** — write-then-rename on the files
  the gateways hot-reload, so a reader sees the old release or the new one,
  never a torn file. Rollback needs no tooling: republish the old sha.

The release manifest is signed (canonical encoding, like every other signed
artifact) but the artifact hashes inside it are plain SHA-256 of the file
bytes, deliberately: "is the bundle my gateway loaded the one the manifest
names?" must be answerable with nothing but `sha256sum`.

### The audit dossier

`obsign-ledger export` produces one pack for one chain; an auditor asks for
a period. With the HTTP transport every agent session is its own chain, so
"what did your agents do in Q3" is dozens of packs:

```bash
./target/debug/obsign-control export \
    --wal /srv/obsign/wal --store /srv/obsign/ledger \
    --out /tmp/dossier --key /tmp/ops.hex --key-id ops-2026 \
    --seal-keys /secure/seal-keys.json   # your copy of the sealing keys
```

`--out` must be absent or empty; the dossier is assembled beside it and
appears complete or not at all. `--seal-keys` pins the sealing keys: without
it, packs verify against the store's own `keys.json`.

Every chain is exported, verified on the way out, and listed in a signed
export manifest, so the dossier cannot lose a pack in transit without the loss
being visible. A pack that fails verification is written and flagged, never
repaired or filtered: an export that fixed things on the way out would do
exactly what the product exists to make impossible. The exit code says so.

### The console

```bash
./target/debug/obsign-control console \
    --wal /srv/obsign/wal --store /srv/obsign/ledger --dist /srv/obsign/dist
```

Three server-rendered HTML pages on `std::net`: current release with its
signature verdict, chains with their sealing state (each one re-verified on
request), and records. No JavaScript, no template engine, no cache, so what
the console shows is what the files say now. Read-only **by construction**.
The only accepted method is GET, so the console can never become a second
write path around git. It binds to localhost by default; authentication is the
commercial layer's job, and it is no reason to weaken the core. Binding it
anywhere else prints a warning. It answers only a `Host` header that is
`localhost` or an IP address, so a web page cannot reach it through DNS
rebinding; pass `--allow-host <name>` for each name operators use to reach
it.

## Verification in practice

```bash
cargo run -p obsign-audit-core --example gen_sample -- /tmp/sample
cargo run -p obsign -- verify /tmp/sample/evidence.json \
    --trusted-keys /tmp/sample/trusted-keys.json    # exit 0
```

The sample carries the three roles a real deployment has: the gateway signs
each record as it writes it, the ledger seals over them, and an ops-signed
deployment bundle, embedded in the pack, enrols the gateway. So
`trusted-keys.json` holds **two** keys, seal and ops, and neither is an origin
key: those ride the bundle, which is what keeps the out-of-band set at two
entries however many gateways the deployment grows to.

The report ends on one warning, `identity_not_attested`, and that is the
product working: the sample enrols no TPM, so nothing proves *which software*
ran under the gateway key, and the verifier says so instead of staying quiet.
It is also why this run would exit 1 under `--strict`; see
[the attestation design note](design/attestation-v3.md).

Tamper with the result and re-run:

```bash
sed -i '' 's/"outcome": "deny"/"outcome": "allow"/' /tmp/sample/evidence.json
cargo run -p obsign -- verify /tmp/sample/evidence.json \
    --trusted-keys /tmp/sample/trusted-keys.json    # exit 1
```

Three errors, all at once: the hash chain breaks, the gateway's signature over
that record no longer verifies, and the sealed Merkle root no longer matches
what the records recompute. Editing one field of a sealed log means forging
three independent things held by three different keys.

Exit codes: `0` proven, `1` tampered, `2` execution error, `3` consistent but
unproven. Exit 3 means one of two things. The pack was only checked against the
keys it carries itself (no `--trusted-keys`), which a forged pack passes
identically. Or some record in it is covered by no valid checkpoint (an
unsealed tail, or an empty pack), so the chain is consistent but those records
are not proven. Exit 0 is reserved for a pack whose every record is sealed and
checked against keys obtained outside the pack. Under `--strict` both cases
exit 1, since each raises a warning.

A trusted-key file must bind each `key_id` to one key. An id listed twice with
different key material is an error (`conflicting_key_id`), and neither key is
used, whatever the order of the entries.

## What verification establishes

1. **No record removed, inserted or modified** — hash chain, contiguous `seq`.
2. **No wholesale rewrite** — the hash chain alone is not enough: whoever holds
   the database can recompute everything. It is the checkpoints, signed with a
   key outside the writing process (KMS/HSM), that close that hole.
3. **No seal spirited away** — checkpoints are chained to each other.
4. **What is not proven is said to be so** — a record that is consistent but
   covered by no valid checkpoint is reported, never passed over in silence,
   and keeps the run off exit 0.

Without `--trusted-keys`, verification establishes internal consistency only,
and the report says so explicitly. A forged pack signed with a made-up key
validates itself: key anchoring must come from another channel.

What a pack does **not** prove: its own completeness at the tail. Nothing in
it commits to the head of the chain, so removing the newest checkpoints
together with the records they seal leaves a pack that verifies, exit 0.
Truncation anywhere else is detected: a record missing in the middle breaks
the hash chain, a checkpoint missing in the middle breaks the checkpoint
chain, and a pack that starts after seq 0 says so (`partial_chain`). The
witness for the tail lives outside the pack: an RFC 3161 anchor over the
latest checkpoint, or a copy of that checkpoint's hash kept elsewhere. The
report prints the line to compare with it:

```
  last sealed : seq 41, checkpoint 9f3c…
```

If the witness names a later checkpoint than that line, the pack was cut.
