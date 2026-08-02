# Writing and operating policies

Everything the gateway refuses or allows comes from one signed artifact: the
policy bundle. This page is how you author it, change it safely, and get it
back after losing a machine.

Two properties shape the whole workflow, and both are deliberate:

* **The source of truth is a git checkout, not a running server.** Policies
  are text files reviewed like code, compiled into a signed bundle stamped
  with the commit sha. Nothing is edited in place on a production host.
* **Compilation is byte-for-byte deterministic.** The same tree, the same
  ref, the same key produce the same bundle — so a release can be
  reproduced, compared by hash, and rebuilt from scratch after a disaster.

## The source tree

```
my-policies/                   ← a git repository
├── policies/
│   ├── 00-base.cedar          ← concatenated in lexicographic file order
│   └── 10-finance.cedar
├── tools.json                 ← the signed catalogue
├── fail-mode.json             ← what to do when the engine cannot decide
├── identity/                  ← optional: who may mint identities
│   ├── provider.json          ← issuer + audience
│   └── jwks.json              ← the IdP's public keys
└── deployment/                ← optional: enrolled gateway origin keys
    ├── origin-keys.json
    └── attestation.json       ← optional: TPM enrollments (v3)
```

Only `policies/` and `tools.json` are mandatory. Numeric filename prefixes
are a convention, not a requirement — but since files are concatenated in
lexicographic order, they keep the order readable and stable.

## The model your rules see

A rule is `permit`/`forbid` over a **principal**, an **action**, a
**resource**, guarded by a `when` clause over the **context**.

**Principals.** `User::"<subject>"`, with `Group::"<name>"` as parents — so
`principal in Group::"dba"` works, including nested groups. The subject and
the groups come from the verified token, mapped by the identity bundle's
claim map (Keycloak, Entra and Okta shapes work with no configuration).
The `User` entity carries **no attributes**: permissions are expressed by
group membership or by scopes, never by `principal.<something>`.

**Actions.**

| Action | Triggered by | Resource type |
|---|---|---|
| `tool_call` | `tools/call` | `Tool::"<name>"` |
| `resource_read` | `resources/read`, `resources/subscribe`, `resources/unsubscribe`, and `completion/complete` on a resource template | `Resource::"<uri>"` |
| `prompt_get` | `prompts/get`, and `completion/complete` on a prompt | `Prompt::"<name>"` |
| `sampling` | server-initiated `sampling/createMessage` | `Server::"mcp://wrapped"` |
| `elicitation` | server-initiated `elicitation/create` | `Server::"mcp://wrapped"` |
| `notify` | server-initiated `notifications/message` | `Server::"mcp://wrapped"` |

`Server::"mcp://wrapped"` is a fixed literal, not the deployment's server
name: these channels are granted per server, and the request names no stable
object to key on. The operator's `--server-id` reaches rules as
`context.server` and lands in every record, but **no resource is keyed on
it** — nothing an operator types on a command line decides a verdict the
signed bundle did not already decide. Match on `context.server` if you want
a rule that only applies to one deployment; do not expect a
`Server::"mcp://crm.internal"` entity to exist.

**Resource attributes.** Only `Tool` carries attributes, and only because
the catalogue describes it: `resource.destructive` (bool),
`resource.server` (string), `resource.required_scope` (string, empty when
none). `Resource` and `Prompt` have none — the server mints those URIs at
runtime, so there is nothing signed to attach. Decide on the identifier via
`context.target`.

**Context**, available to every rule:

| Attribute | Type | Meaning |
|---|---|---|
| `context.env` | string | environment declared to the gateway (`--env`: `prod`, `staging`, …) |
| `context.server` | string | the wrapped server as the operator named it (`--server-id`); descriptive, never a resource key |
| `context.session` | string | session identifier, also the audit chain id |
| `context.scopes` | set of strings | scopes granted by the delegation |
| `context.target` | string | resource URI or prompt name (capability actions) |
| `context.principal_kind` | string | `human`, `delegated_human` or `machine` |
| `context.has_human_delegation` | bool | an identifiable human sits at the root of the chain |
| `context.delegation_depth` | long | number of delegation hops (0 without an `act` claim) |
| `context.actor_chain` | set of strings | the attested RFC 8693 chain |
| `context.args.<name>` | per the catalogue | declared call arguments — see below |

## Writing rules

Every rule needs an `@id`, and compilation refuses a rule without one. The
id is not decoration: it is what lands in the audit record as the reason a
call was allowed or refused. An anonymous rule produces an unexplainable
decision, which defeats the product.

```cedar
// Deny wins over permit, always. Start with what must never happen.
@id("forbid_destructive_prod")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && context.env == "prod" };

// Permission by scope, driven by the catalogue: one rule covers every tool
// that declares a required_scope.
@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when {
  resource.required_scope != "" &&
  context.scopes.contains(resource.required_scope)
};

// Permission by group (RBAC), narrowed by environment.
@id("allow_dba_nonprod")
permit (principal in Group::"dba", action == Action::"tool_call", resource)
when { context.env != "prod" };

// Nothing irreversible without a human behind the agent. The distinction
// comes from the token: a client_credentials token has no human at the root.
@id("forbid_robot_destructive")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };

// Resource families, matched on the identifier.
@id("allow_public_docs")
permit (principal, action == Action::"resource_read", resource)
when { context.target like "docs://public/*" };

// Server-initiated channels are default-deny like everything else.
@id("allow_sampling_for_support")
permit (principal in Group::"support", action == Action::"sampling", resource);
```

Cedar is default-deny: an act nobody permits is refused. You never need a
catch-all `forbid`, and you should not write one — it makes every later
`permit` look conditional when it is not.

## The catalogue (`tools.json`)

A tool absent from the catalogue is refused **before** Cedar runs: the
gateway does not forward what it cannot describe. The catalogue is also
what makes generic rules possible, by attaching reviewable metadata to each
tool.

```json
[
  {
    "name": "delete_production_db",
    "server": "mcp://db",
    "destructive": true,
    "required_scope": "db:admin"
  },
  {
    "name": "send_message",
    "server": "mcp://chat",
    "required_scope": "chat:write",
    "policy_args": [
      { "name": "channel", "kind": "string" },
      { "name": "amount_cents", "kind": "long", "default": 0 }
    ]
  }
]
```

`destructive` and `required_scope` are yours to define; the engine only
exposes them. Marking a tool destructive costs nothing and lets one rule
protect every dangerous tool at once, including the ones added later.

## Arguments (`obsign-policy/2`)

`policy_args` declares which call arguments the policy may read. That
allowlist is a privacy boundary, not a convenience: **anything not declared
never reaches the engine**, and the log keeps `args_hash`, never the values.

```cedar
@id("support_channel_only")
forbid (principal, action == Action::"tool_call", resource == Tool::"send_message")
when { context.args.channel != "#support" };
```

| Field | Meaning |
|---|---|
| `name` | the name under `context.args` |
| `kind` | `string`, `long` (integral only — floats are refused, never rounded), `bool`, `string_set` |
| `at` | JSON pointer into the call's `arguments`; defaults to `/<name>` |
| `default` | injected when the call omits the argument |

An argument declared **without** a default is required: a call that omits it
is refused before Cedar runs. That is the safe direction — a rule that reads
a missing field would otherwise fail-closed anyway, but with a much worse
error message.

## Fail mode (`fail-mode.json`)

What happens when the engine cannot decide — an unreadable bundle, or a rule
that raises an evaluation error:

```json
{ "default": "closed", "tools": { "search_docs": "open" } }
```

The default is `closed`, and a customer who wants otherwise declares it
explicitly so it shows up in a pull request. Per-tool because there is no
universally good answer: blocking a read-only search breaks production for
nothing, letting a deletion through is indefensible.

A degradation is never silent: a call allowed under a fail-open rule is
recorded as `AllowFailOpen`, never as a clean `Allow`.

## Compile, publish, deploy

```bash
# Compile only — signed artifacts in ./out, nothing published.
obsign-control compile --source ./my-policies --key ./ops-key.hex --out ./out

# Compile and publish an immutable release the gateways read.
obsign-control publish --source ./my-policies --key ./ops-key.hex --dist /srv/obsign/dist
```

The version label defaults to the short sha of `HEAD`, and **compile refuses
to stamp that sha onto a dirty working tree** — a `policies@<sha>` citation
in an audit record must mean the bytes that commit contains. Use `--label`
for a tree that is not in git.

The distribution directory:

```
dist/
├── policy-bundle.json        ← current, atomically replaced
├── identity-bundle.json      ← current
├── deployment-bundle.json    ← current (when the tree has deployment/)
├── manifest.json             ← current, signed
├── trusted-keys.json         ← accumulated ops public keys
└── releases/<version>/       ← immutable history, one directory per version
```

Publishing the same tree twice is idempotent. A version directory is written
once and never rewritten; **rollback is republishing an older sha**, not
editing anything. A key id cannot be rebound to different key material —
rotation means a new id.

### A policy change needs a gateway restart

The gateway reads the policy bundle **once, at startup**, and verifies its
signature against `--trusted-keys` before loading it. Publishing a new
bundle does not change the behaviour of a running gateway: restart it (or
roll your containers) to pick the change up.

This is the opposite of the identity bundle, which *is* re-read at runtime —
an IdP key rotation must not require a restart, and every reload, applied or
rejected, lands in the log as a `config_reload` record.

Plan changes accordingly: policy rollouts are deployments, not hot edits.

### Order matters when you first declare arguments

The control plane emits bundle format `/2` the moment one tool declares
`policy_args`, and a pre-upgrade gateway **refuses a `/2` bundle at startup**
rather than silently enforcing less than the bundle says. So: upgrade every
gateway image first, publish the bundle that declares arguments second. A
fleet that never declares arguments keeps receiving `/1` and needs nothing.

## Testing before you deploy

Compile first — most mistakes are compile errors by design: a rule without
`@id`, a duplicate tool, a fail-mode override naming a tool that does not
exist, an unusable JWKS.

Then exercise the real binaries against a scratch WAL, which is what the
demo in the README does. Drive the calls you care about, and read the
decisions out of the log:

```bash
obsign-ledger export --wal /tmp/t/wal --chain-id test \
    --store /tmp/t/ledger --out /tmp/t/evidence.json
python3 - <<'EOF'
import json
for r in json.load(open('/tmp/t/evidence.json'))['records']:
    p = r['payload']
    if p.get('kind') == 'decision':
        print(p['outcome'], p.get('policy_id'), p.get('reason'))
EOF
```

The `policy_id` column is the point: it tells you *which* rule decided, so a
call allowed by the rule you did not expect is visible immediately.

## Backup and recovery

The question to answer is not "can I restart the gateway" but **"can I still
show, two years from now, what `policies@a3f19c2` contained?"** Every
decision record cites the bundle version that made it. Lose the tree that
produced that version and the audit trail points at something nobody can
read back.

| Artifact | Reproducible? | How to protect it |
|---|---|---|
| Policy source tree | — it *is* the source | **git remote.** Push it. That is the backup. |
| Ops signing key | **No** | The one irreplaceable secret — see below |
| `dist/` current files | Yes, from source + key | Recompile; deterministic, byte-identical |
| `dist/releases/<sha>/` | Yes, if you kept the tree and the key | Back it up anyway: it is the record of what was actually published, and it is small |
| `trusted-keys.json` | Accumulated over time | Back up with your config; a gateway needs it to trust bundles |

### The ops signing key

Losing it does **not** invalidate anything already signed: verification uses
the public half, which lives in `trusted-keys.json` and inside every pack.
What you lose is the ability to sign *new* bundles.

Recovery is a rotation, not a restore: generate a new key under a **new key
id** (re-binding an old id is refused), republish, and distribute the updated
`trusted-keys.json` to the fleet. Budget for this being a fleet-wide config
change — which is exactly why the key belongs in a KMS/HSM in production,
and why the file-seed form is documented as development-grade.

### Recommended layout

1. **The source tree lives in a git repository with at least one remote.**
   Not "a copy on the VM" — a remote, on infrastructure that fails
   independently. In an air-gapped site, that is a second machine and a
   documented mirroring step, not an excuse to skip it.
2. **The ops key never lives only on the machine that uses it.** HSM in
   production. If a file seed is unavoidable during a pilot, keep a sealed
   offline copy, and treat losing it as a rotation drill rather than a
   catastrophe.
3. **`dist/` is backed up with your configuration** — small, slow-changing,
   and it lets you answer "what was published on that date?" without a
   rebuild.
4. **The WAL, the ledger store and the evidence packs** have their own
   procedure: [runbook-backup-restore.md](runbook-backup-restore.md). Those
   protect the proof; this page protects the ability to *explain* it.

### Rebuilding after losing the VM

```bash
git clone <remote> my-policies && cd my-policies
git checkout <the sha an audit record cites>       # e.g. a3f19c2
obsign-control compile --source . --key ./ops-key.hex --out ./rebuilt
sha256sum rebuilt/policy-bundle.json
```

Because compilation is deterministic, that hash matches the artifact that
was originally published — which is what turns "we think the rule said this"
into a checkable claim. Do this once as a drill, before you need it: it
proves your remote, your key custody and your version labels all work
together.

## Failure modes worth knowing

| Symptom | Cause | What to do |
|---|---|---|
| `tool "x" absent from signed catalogue` | the tool is not in `tools.json` | add it and republish — the refusal is the feature |
| `evaluation failed, fail-closed: … does not have the attribute …` | a rule reads something the model does not expose (e.g. `principal.permissions`) | use `context.scopes` or a group; see the model table above |
| compile: rule without `@id` | an anonymous rule | name it — the id is the audit reason |
| compile refuses the sha | uncommitted changes | commit, or pass `--label` |
| gateway refuses to start on a `/2` bundle | gateway older than the bundle format | upgrade gateways first, then publish |
| a change has no effect | policy is read at startup | restart the gateway |
| `AllowFailOpen` in the log | the engine could not decide and fail mode said open | fix the rule; the degradation is visible on purpose |
