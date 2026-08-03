# The policy source tree, file by file

[policies-cedar.md](policies-cedar.md) explains how to *think* about a policy
bundle. This page is the reference: every file the control plane reads, every
field it accepts, every value an enum admits, and what `obsign-control
compile` does when the field is wrong.

The rule behind the whole layout: **everything that decides an outcome is
signed, and everything that is signed is reviewed as a diff.** That is why
there is no field here that a running server can change, and why a typo is a
compile error in CI rather than a surprise on a gateway.

## Conventions

* **Required** — compilation fails if the field is absent.
* **Default** — the value used when the field is absent. A field with a
  default is safe to omit; the default is what the signature will cover.
* *Refused at compile* means `obsign-control compile` exits non-zero and
  prints the file path. Nothing is written, nothing is published.

> **Unknown fields are ignored, with one exception.** JSON parsing is
> tolerant everywhere except `deployment/origin-keys.json`, which rejects
> unknown fields outright. So `"destructve": true` in `tools.json` compiles
> happily and the tool is **not** destructive. Review diffs on these files
> the way you review code, and prefer copying from the examples below over
> typing from memory.

## At a glance

| Path | Required | Parsed as | Compiles into | Absent means |
|---|---|---|---|---|
| `policies/*.cedar` | **yes** | Cedar source | `policy-bundle.json` | *refused* — no policy set at all |
| `tools.json` | **yes** | array of tool objects | `policy-bundle.json` | *refused* — every tool would be denied |
| `fail-mode.json` | no | fail-mode object | `policy-bundle.json` | `{"default":"closed"}` |
| `identity/provider.json` | with `identity/` | provider object | `identity-bundle.json` | no identity bundle: the gateway starts in declared mode and says so |
| `identity/jwks.json` | with `identity/` | JWKS | `identity-bundle.json` | idem |
| `deployment/origin-keys.json` | with `deployment/` | array of key entries | `deployment-bundle.json` | no gateway enrolled |
| `deployment/attestation.json` | no | array of attestations | `deployment-bundle.json` | no TPM enrollment (v3 unused) |

`identity/` and `deployment/` are all-or-nothing: create the directory and
its mandatory file becomes mandatory too — half an identity configuration
verifies nothing, and an empty `deployment/` deserves an explicit file rather
than a silent empty set.

Any other file in the tree (a `README.md`, a CI config, a test fixture) is
never read. Only the seven paths above reach a bundle.

---

## 1. `policies/*.cedar`

| Rule | Detail |
|---|---|
| Which files | `*.cedar`, regular files, **directly** inside `policies/`. Subdirectories are not traversed — `policies/finance/10-x.cedar` is silently invisible. |
| Order | Sorted by file name, lexicographic (byte order), then concatenated. `00-base.cedar` before `10-finance.cedar`; `9-x.cedar` **after** `10-x.cedar` — pad your prefixes. |
| Provenance | Each file is prefixed with a `// ─── <name> ───` comment in the bundle, so a rule in the compiled artifact can be traced back to its file. |
| Minimum | At least one `.cedar` file. An empty policy set denies everything, which deserves an explicit file saying so. |
| `@id` | Mandatory on every rule, and unique across the whole concatenation. The id is the audit reason. |

There is no schema file to write: the entity model (`User`, `Group`, `Tool`,
`Resource`, `Prompt`, `Server`, the six actions and the context attributes)
is fixed by the gateway and documented in
[policies-cedar.md](policies-cedar.md#the-model-your-rules-see). Declaring
entities the model does not have compiles, then fails at evaluation and lands
under your fail mode — which is why the compile-time smoke check exists (see
`tools.json` below).

---

## 2. `tools.json` — the catalogue

Top level is a **JSON array**, not an object. A tool absent from it is refused
before Cedar runs.

```json
[
  {
    "name": "delete_production_db",
    "server": "mcp://db",
    "destructive": true,
    "required_scope": "db:admin"
  }
]
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `name` | string | **yes** | — | The MCP tool name, matched exactly against `tools/call`. Also the Cedar resource: `Tool::"delete_production_db"`. Must be non-empty and unique in the file. |
| `server` | string | **yes** | — | Which backing server owns the tool. Exposed to Cedar as `resource.server`. Free-form; the convention is the same URI the gateway is started with (`--server-id mcp://db`). Descriptive only — no verdict is keyed on it. |
| `destructive` | bool | no | `false` | Your judgement, not a detection: an effect that cannot be undone (delete, transfer, external send). Exposed as `resource.destructive`. Marking a tool destructive costs nothing and lets one rule protect every dangerous tool, including the ones added later. |
| `required_scope` | string | no | *absent* | Delegation scope the tool needs. Exposed as `resource.required_scope`, **as the empty string when absent** — Cedar has no ergonomic optional, so write `resource.required_scope != ""` rather than a null test. Declaring it does not enforce it: a rule must read it (see `allow_scoped` in policies-cedar.md). |
| `policy_args` | array | no | `[]` | Arguments the policy may read. Any non-empty list makes the bundle `obsign-policy/2` — see the ordering warning below. |

**Refused at compile:** an empty `name`; the same `name` twice (the engine
indexes by name, so a duplicate would shadow one definition and which one
wins would depend on file order); malformed JSON.

### 2.1 `policy_args[]` — the argument allowlist

The allowlist is a **privacy boundary**, not a convenience: an argument not
declared here never reaches the engine, and the audit log keeps `args_hash`,
never the values.

```json
{
  "name": "send_message",
  "server": "mcp://chat",
  "policy_args": [
    { "name": "channel", "kind": "string" },
    { "name": "amount_cents", "kind": "long", "default": 0 },
    { "name": "labels", "kind": "string_set", "default": [] },
    { "name": "target", "kind": "string", "at": "/recipient/id" }
  ]
}
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `name` | string | **yes** | — | The key under `context.args`. Non-empty, unique within the tool. |
| `kind` | enum | **yes** | — | `string` \| `long` \| `bool` \| `string_set`. See the coercion table. |
| `at` | string | no | `/<name>` | RFC 6901 JSON pointer into the call's `arguments` object, for a value that is nested or named differently. Must start with `/`. When derived from `name`, the name is escaped (`~`→`~0`, `/`→`~1`), so an argument literally named `path/glob` reads the key `path/glob` and not `arguments.path.glob`. |
| `default` | any | no | *absent* | Injected when the call omits the argument. Must itself coerce to `kind`. **An argument with no default is required**: a call omitting it is refused before Cedar runs, with an explicit message. |

An explicit JSON `null` in the call counts as *absent*, not as a value — MCP
client SDKs routinely serialize an omitted optional field as `null`, and
treating that as present would deny a call that omitting the key entirely
would have allowed.

#### `kind` values

| `kind` | Accepted JSON | Cedar type | Refused |
|---|---|---|---|
| `string` | string, ≤ 4096 bytes | String | any non-string; a longer string (policy-relevant arguments are identifiers, not payloads) |
| `long` | integral number, `i64` range | Long | any float — **even `2.0`** — and any out-of-range integer. Never rounded: an amount check that rounds is an amount check with a hole. Monetary rules declare minor units (cents). |
| `bool` | `true` / `false` | Bool | strings `"true"` / `"false"`, `0`, `1` |
| `string_set` | array of strings, ≤ 64 elements, each ≤ 4096 bytes | Set of String | a non-array; an array containing anything but strings |

#### Limits

| Limit | Value |
|---|---|
| Declared args per tool | 16 |
| String length (and each set element) | 4096 bytes |
| Set elements | 64 |

**Refused at compile:** `policy_args` on a bundle that is not
`obsign-policy/2` (cannot happen from a source tree — the control plane picks
the format automatically); more than 16 args; an empty or duplicate arg name;
an `at` that does not start with `/`; a `default` that does not coerce to its
`kind`.

#### The smoke check

The moment any tool declares `policy_args`, compilation additionally
evaluates every rule once per tool against a synthetic request built from
your declared defaults (or the zero value: `""`, `0`, `false`, `[]`). A
typo'd `context.args.chanel` therefore fails in CI, naming the rule, instead
of surfacing months later as a fail-mode event on a live gateway.

Trees that declare no arguments keep compiling without this check — blocking
their publish over a synthetic input would override the fail-mode choice they
already made.

#### Ordering warning

The control plane emits `obsign-policy/2` as soon as one tool declares
`policy_args`, and a pre-upgrade gateway **refuses a `/2` bundle at startup**
rather than silently enforcing less than the bundle says. Upgrade every
gateway image first, publish the bundle that declares arguments second.

---

## 3. `fail-mode.json`

What happens when the engine *cannot decide* — a bundle it cannot read, or a
rule that raises an evaluation error. This is not the deny path: a rule that
denies is a decision, and fail mode never applies to it.

```json
{
  "default": "closed",
  "tools": {
    "search_docs": "open",
    "list_tickets": "open"
  }
}
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `default` | enum | **yes**, if the file exists | — | Behaviour for everything without an override. |
| `tools` | object | no | `{}` | Per-tool overrides: tool name → behaviour. |

Omitting the whole file gives `{"default": "closed", "tools": {}}`. But a
file containing `{}` is **refused** — `default` has no default inside the
file, on purpose: writing the file is declaring a position.

#### `default` / `tools.*` values

| Value | Behaviour | Recorded as |
|---|---|---|
| `closed` | Refuse when in doubt. | `Deny`, reason `evaluation failed, fail-closed: …` |
| `open` | Let the call through. | **`AllowFailOpen`** — never a clean `Allow`. The degradation stays visible when the log is read back two years later. |

Per-tool because there is no universally good answer: blocking a read-only
search breaks production for nothing, letting a deletion through is
indefensible.

**Refused at compile:** an override naming a tool that is not in
`tools.json`. A typo there would not fail, it would silently apply the
default to the tool the author meant to override — the worst possible
outcome for a fail-*open* declaration.

> **Overrides apply to catalogued tools only.** The capability actions
> (`resource_read`, `prompt_get`, `sampling`, `elicitation`, `notify`) are
> keyed by action name, and an action name is not a tool name, so compile
> refuses it as an unknown tool. Those actions therefore always follow
> `default`. Keep `default: "closed"` unless you have decided otherwise for
> the whole surface.

---

## 4. `identity/provider.json`

Who may mint identities, and where to read them inside the token. This file
plus `jwks.json` becomes the signed identity bundle — signed because whoever
can write it can mint an identity for themselves, and because moving a claim
path changes which groups get assigned, hence which Cedar rules apply.

```json
{
  "issuer": "https://idp.example.com/realms/corp",
  "audience": "obsign-gateway"
}
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `issuer` | string | **yes** | — | Expected `iss` claim, compared exactly. Must be non-empty. |
| `audience` | string | **yes** | — | Expected `aud` claim. Must be non-empty — an empty audience would accept tokens minted for any other service. |
| `claims` | object | no | the defaults below | Claim map. **All-or-nothing**, see the warning. |

> **Keycloak trap.** Keycloak access tokens carry `aud: "account"` by
> default. Configure an audience mapper in the realm so it emits your
> gateway's audience. Never relax the check on this side.

### 4.1 `claims` — the claim map

The defaults cover Keycloak, Entra ID and Okta with **no configuration at
all**. Omit `claims` entirely unless your IdP puts something somewhere else.

> **`claims` is all-or-nothing for its first four fields.** `subject`,
> `scopes`, `groups` and `client_id` have no per-field default *inside* the
> object: the moment you write `"claims": { … }`, all four must be present or
> the file is refused. Copy the full default block below and edit it, rather
> than writing a partial override. `labels` and `machine` do default
> individually.

```json
{
  "issuer": "https://idp.example.com/realms/corp",
  "audience": "obsign-gateway",
  "claims": {
    "subject": "/sub",
    "scopes": ["/scope", "/scp"],
    "groups": ["/groups", "/roles", "/realm_access/roles", "/resource_access/*/roles"],
    "client_id": ["/client_id", "/azp"],
    "labels": ["/preferred_username", "/email", "/name"],
    "machine": {
      "subject_is_client": true,
      "equals":   [{ "path": "/idtyp", "value": "app" }],
      "prefixes": [{ "path": "/preferred_username", "value": "service-account-" }]
    }
  }
}
```

| Field | Type | Required in `claims` | Default | Resolution |
|---|---|---|---|---|
| `subject` | string (one path) | **yes** | `/sub` | The stable identifier. Becomes `User::"<subject>"` in Cedar and the identity in every audit record. |
| `scopes` | array of paths | **yes** | `["/scope", "/scp"]` | **First path that answers wins.** Scopes do not accumulate across representations: `scope` and `scp` are two spellings of one thing, merging them would produce misleading duplicates. Reaches Cedar as `context.scopes`. |
| `groups` | array of paths | **yes** | `["/groups", "/roles", "/realm_access/roles", "/resource_access/*/roles"]` | **Union of every path**, sorted and deduplicated: a user can legitimately carry both directory groups and application roles. Each becomes a `Group::"<name>"` parent of the principal, so `principal in Group::"dba"` works. |
| `client_id` | array of paths | **yes** | `["/client_id", "/azp"]` | First path that answers. Used by the `subject_is_client` machine marker. |
| `labels` | array of paths | no | `["/preferred_username", "/email", "/name"]` | Human-readable display name, first **non-empty** answer wins. Recorded *beside* the subject, never instead of it — a display name can be renamed, an audit trail needs the identifier that cannot. The claim it came from is recorded with it. |
| `machine` | object | no | the block above | What marks a token as a machine's. See §4.3. |

Values are read leniently at the leaf: a **space-separated string** (`"scope":
"a b c"`) and an **array** (`"scp": ["a","b"]`) both flatten to the same list,
recursively.

### 4.2 Path syntax

Not quite RFC 6901: `/`-separated segments, plus `*` meaning *every child* of
an object or array.

| Path | Reads |
|---|---|
| `/sub` | top-level `sub` |
| `/realm_access/roles` | nested — Keycloak realm roles |
| `/resource_access/*/roles` | the `roles` of **every** client — Keycloak client roles, whose middle segment depends on the client and cannot be hard-coded |
| `/ext/*/login` | any nesting one level deep |

There is **no `~0`/`~1` escaping here** (unlike `policy_args.at`): a claim
whose name literally contains `/` is not addressable. A path that resolves to
nothing is not an error — it simply does not answer, and the next path is
tried.

### 4.3 `machine` — machine markers

These decide `PrincipalKind`, hence which Cedar rules apply, which is why
they travel inside the signed bundle rather than as a plain file option. Every
marker only ever **adds** a Machine verdict, so broadening this can never
downgrade a real human to a robot — only the reverse, which is the safe
direction.

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `subject_is_client` | bool | no | `true` | `sub` == `client_id`: the textbook `client_credentials` shape. Set to `false` if your IdP reuses `azp` == `sub` for first-party human logins. |
| `equals` | array of `{path, value}` | no | `[{"path":"/idtyp","value":"app"}]` | A claim equals a value exactly. The default is Entra ID's app-only marker. |
| `prefixes` | array of `{path, value}` | no | `[{"path":"/preferred_username","value":"service-account-"}]` | A claim starts with a prefix. The default is Keycloak's reserved service-account login prefix, which no human carries. |

`path` uses the same syntax as §4.2, wildcard included. `value` is compared
as a plain string.

Why three markers and not just the first: a real Keycloak or Entra
`client_credentials` token has `sub` set to the service principal's own id,
**distinct** from the client id. `sub == client_id` alone would let a keyless
robot classify as `Human` and satisfy a "requires a human" rule.

The resulting classification:

| `context.principal_kind` | When |
|---|---|
| `machine` | any marker fires |
| `delegated_human` | no marker, and an `act` chain is present (RFC 8693 token exchange) |
| `human` | no marker, no `act` chain |

`act` nesting is followed to a depth of 8 and reaches Cedar as
`context.actor_chain` and `context.delegation_depth`.

### 4.4 Bundle format

`compile` always emits the current format, `obsign-identity/3`, whose
signature covers the label paths and the machine markers. Older bundles
(`/1`, `/2`) still verify, but each refuses exactly what its own signature
does not cover: a `/1` or `/2` bundle carrying custom `labels`, or a `/1`
bundle carrying custom `machine` markers, is rejected at load. Re-signing at
the current format is one `obsign-control compile` away.

---

## 5. `identity/jwks.json`

The IdP's public keys, **loaded from a file, never from the network** — the
gateway sits on the critical path and makes no outbound call. Fetch it from
your provider's `jwks_uri` and commit it verbatim, like a rule:

```bash
curl -s https://idp.example.com/realms/corp/protocol/openid-connect/certs \
  > identity/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "rMx8k…",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuu…",
      "e": "AQAB"
    }
  ]
}
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `keys` | array | **yes** | — | The key set. Must resolve to at least one usable key. |
| `keys[].kty` | enum | **yes** | — | `RSA` \| `EC` \| `OKP`. Anything else is refused. |
| `keys[].kid` | string | **yes** | — | Matched against the token's `kid` header. **Mandatory in the token too**: without it we would have to try every key, which hides a failed rotation and muddies diagnosis. |
| `keys[].alg` | string | no | per `kty`, below | Signing algorithm. |
| `keys[].crv` | string | no | — | Carried and signed, not otherwise interpreted; the curve is implied by `alg` for `EC` and by `kty` for `OKP`. |
| `keys[].n`, `keys[].e` | base64url | for `RSA` | — | Modulus and exponent. |
| `keys[].x` | base64url | for `EC` and `OKP` | — | X coordinate (`EC`) or the raw public key (`OKP`/Ed25519). |
| `keys[].y` | base64url | for `EC` | — | Y coordinate. Ignored for `OKP`. |

#### Accepted `alg` values

| `kty` | Default `alg` | Accepted |
|---|---|---|
| `RSA` | `RS256` | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` |
| `EC` | `ES256` | `ES256`, `ES384` |
| `OKP` | `EdDSA` | `EdDSA` (the field is not consulted — an Ed25519 key signs EdDSA) |

**HMAC algorithms (`HS256` …) and `none` are deliberately absent.** A
symmetric key in a published JWKS is a vulnerability, not a configuration.

**Refused at compile** — the same checks the gateway runs, moved to CI: an
empty or all-unusable key set; a duplicate `kid` (two keys for one id means we
can no longer tell which one signed); a missing component for the declared
`kty`; an unsupported `kty` or `alg`.

**Rotation does not need a restart.** The identity bundle is re-read at
runtime, and every reload — applied or rejected — lands in the log as a
`config_reload` record. This is the opposite of the policy bundle. Publish
the new JWKS *before* the IdP starts signing with the new key, and keep the
old key in the file until every issued token has expired.

---

## 6. `deployment/origin-keys.json`

Which gateways are allowed to write into the log. Enrolling a gateway is
committing its public entry here; revoking is deleting the entry and
republishing.

```json
[
  {
    "key_id": "origin-3f19c2a8b4d70e51",
    "algo": "ed25519",
    "public_key": "3f19c2a8b4d70e51…",
    "role": "origin"
  }
]
```

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `key_id` | string | **yes** | — | Must match the id the gateway signs with, byte for byte. Gateways derive it as `origin-<first 16 hex chars of the public key>`, so do not invent one. |
| `algo` | string | **yes** | — | `ed25519` — the only accepted value today. |
| `public_key` | string | **yes** | — | The raw 32-byte public key, hex, no `0x`. |
| `role` | enum | **in practice yes** | `seal` | `origin` \| `seal` \| `ops`. **Must be `origin` here**, and the default is `seal`, so omitting it is refused. |

> **This file rejects unknown fields.** A misspelled key is a hard parse
> error, not a silent omission — the one place in the tree where that
> protection exists, because these entries decide who may write the log.

Why `role` is not optional in practice: origin keys authenticate the *writer*
(the gateway signs each record as it writes it), sealing keys certify the
*log* (the ledger signs checkpoints over it), and ops keys sign the deployment
bundle that names the origin keys. A sealing key certifying its own writer, or
the ops key that enrolled a gateway also speaking as one, is exactly the
cohabitation the roles prevent — so the deployment bundle carries origin keys
only, and `obsign verify` resolves every key within its role.

### Where the values come from

The gateway prints its own public entry at startup, on stderr. Copy the JSON
object verbatim:

```
[obsign] origin key origin-3f19c2a8b4d70e51 — every record signed directly — public entry: {"key_id":"origin-…","algo":"ed25519","public_key":"…","role":"origin"}
```

Two-tier deployments (`--identity-key`, or `--identity-hsm-module` in
production) print the same line for the identity key — `[obsign] identity key
… — certifies a session key per chain — public entry: {…}`. Enroll *that*
entry: the identity key is what the bundle must trust, and the per-session
keys it certifies are derived and verified from it.

An absent file with `deployment/` present is refused; an empty array `[]` is
accepted and means "no gateway trusted yet" — legitimate before the first
enrollment, and honest rather than silent. Under default-require the ledger
will then refuse to seal anything, which is correct: no trusted writer, no
proof.

---

## 7. `deployment/attestation.json` (optional, v3)

TPM enrollments: proof that a gateway's identity key is resident in real
hardware running measured software. Optional, and only meaningful with a TPM
2.0 — see [real-tpm-interop.md](real-tpm-interop.md) and
[design/attestation-v3.md](design/attestation-v3.md).

Top level is an **array**, one entry per enrolled key.

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `key_id` | string | **yes** | — | Which enrolled origin key this attestation binds. Must name an entry in `origin-keys.json`. |
| `ak_pub` | hex | **yes** | — | The TPM attestation key that signed the quote and the certify. 32 bytes for an Ed25519 AK; 65 bytes (`04 ‖ x ‖ y`, uncompressed point) for an ECDSA-P256 AK — the fallback for the many TPMs that implement no EdDSA. The algorithm is read off the key material, never off a declared field. |
| `ek_cert` | hex (DER) | **yes** | — | The endorsement key certificate. Carried opaquely: it chains to the TPM vendor root, which is validated **out of band**, never here. May be an empty string — the verification report then flags it as unverifiable rather than pretending otherwise. |
| `certify` | hex | **yes** | — | `TPM2_Certify` output: marshalled `TPMS_ATTEST` followed by the AK's 64-byte signature. Binds the identity key to the AK. |
| `quote` | hex | **yes** | — | `TPM2_Quote` output, same shape. Reports the PCR values. |
| `expected_pcrs` | array | **yes** | — | The PCR values the quote must report — this is the policy, and it is under the ops signature. |
| `expected_pcrs[].index` | integer | **yes** | — | PCR index. The gateway-binary measurement conventionally goes in 16. |
| `expected_pcrs[].digest` | hex | **yes** | — | Expected value of that PCR. |
| `identity_pub` | hex | no | *absent* | The identity key's marshalled `TPMT_PUBLIC`. **Present** in everything a real TPM emits: the verifier recomputes the Name the certify must match (`alg ‖ H(these bytes)`) and extracts the raw public key, which must equal the enrolled entry — so entry → public area → Name → AK signature closes with no gap. **Absent** falls back to the earlier synthetic binding, kept so pre-hardware attestations keep verifying. |

All hex fields are lowercase hex with no `0x` prefix.

### Generating it

```bash
obsign-tpm-enroll \
  --tpm /dev/tpmrm0 \
  --key-id origin-3f19c2a8b4d70e51 \
  --binary-hash "$(sha256sum ./obsign-proxy | cut -d' ' -f1)" \
  --pcr 16 \
  --ek-cert-file ./ek.der \
  --out ./one-attestation.json
```

Two things to know:

1. **`--out` writes one bare object; the file must be an array.** Wrap it —
   `jq -s '.' one-attestation.json > deployment/attestation.json` — or paste
   the object into the existing array.
2. **If the tool warns that your TPM produced an `ecdsa-p256` identity key,
   do not paste its `identity_entry` into `origin-keys.json`.** Deployment
   bundles accept only Ed25519 origin keys today, and a P-256 entry takes the
   whole bundle down as `deployment_bundle_invalid`. The attestation itself is
   fine; the entry waits for P-256 origin-key support.

**Refused at compile:** an attestation whose `key_id` is not an enrolled
origin key — a copy-paste slip worth catching in review rather than at the
verifier.

---

## 8. A complete tree

```
my-policies/
├── policies/
│   ├── 00-base.cedar
│   └── 10-finance.cedar
├── tools.json
├── fail-mode.json
├── identity/
│   ├── provider.json
│   └── jwks.json
└── deployment/
    └── origin-keys.json
```

`policies/00-base.cedar`

```cedar
@id("forbid_destructive_prod")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && context.env == "prod" };

@id("forbid_robot_destructive")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };

@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when {
  resource.required_scope != "" &&
  context.scopes.contains(resource.required_scope)
};
```

`policies/10-finance.cedar`

```cedar
@id("forbid_large_transfers")
forbid (principal, action == Action::"tool_call", resource == Tool::"transfer_funds")
when { context.args.amount_cents > 100000 };

@id("allow_finance_transfers")
permit (principal in Group::"finance", action == Action::"tool_call", resource == Tool::"transfer_funds");
```

`tools.json`

```json
[
  {
    "name": "search_docs",
    "server": "mcp://docs"
  },
  {
    "name": "transfer_funds",
    "server": "mcp://ledger",
    "destructive": true,
    "required_scope": "finance:write",
    "policy_args": [
      { "name": "amount_cents", "kind": "long" },
      { "name": "account", "kind": "string", "at": "/destination/iban" }
    ]
  }
]
```

`fail-mode.json`

```json
{ "default": "closed", "tools": { "search_docs": "open" } }
```

`identity/provider.json`

```json
{
  "issuer": "https://idp.example.com/realms/corp",
  "audience": "obsign-gateway"
}
```

`identity/jwks.json` — committed verbatim from the IdP's `jwks_uri`.

`deployment/origin-keys.json` — the `public entry:` object copied from each
gateway's startup line.

Then:

```bash
obsign-control compile --source . --key ./ops-key.hex --out ./out
```

---

## 9. What compile refuses, and why

| Message | File | Cause |
|---|---|---|
| `no policies/ directory` | — | the mandatory directory is missing |
| `no .cedar file in policies/` | `policies/` | an empty policy set denies everything; say so explicitly |
| `rule "…" has no @id annotation` | a `.cedar` | anonymous rule — the id is the audit reason |
| `conflicting or invalid @id values` | a `.cedar` | two rules share an id, across all files |
| `missing tools.json` | — | the catalogue is authoritative; without one every tool is refused |
| `a tool with an empty name` | `tools.json` | — |
| `tool "x" is declared twice` | `tools.json` | which definition wins would depend on file order |
| `policy_args: N declared args, maximum is 16` | `tools.json` | — |
| `policy_args: duplicate arg "x"` / `an arg has an empty name` | `tools.json` | — |
| `arg "x": "…" is not a JSON pointer (must start with '/')` | `tools.json` | malformed `at` |
| `arg "x": default: expected an integer (i64 range, floats refused)` | `tools.json` | a `default` that does not match its `kind` |
| `tool "x": smoke evaluation: …` | a `.cedar` | a rule reads something the model does not expose — typically a typo in `context.args.<name>` |
| `missing field \`default\`` | `fail-mode.json` | the file exists but declares no position |
| `fail-mode override for "x", which is not in the catalogue` | `fail-mode.json` | a typo would silently apply the default instead |
| `identity/ exists but …/provider.json is missing` | `identity/` | half an identity configuration verifies nothing |
| `issuer and audience must both be set` | `provider.json` | an empty audience accepts tokens minted for any other service |
| `missing field \`subject\`` (or `scopes`, `groups`, `client_id`) | `provider.json` | a partial `claims` override — supply all four |
| `unsupported key type: oct` | `jwks.json` | an HMAC key in a JWKS — refused by design |
| `duplicate kid` / `empty JWKS` / `malformed JWK` / `unsupported algorithm` | `jwks.json` | the gateway's own key-store checks, run at compile time |
| `deployment/ exists but …/origin-keys.json is missing` | `deployment/` | an empty deployment directory deserves an explicit file |
| `key "x" has role "seal"` | `origin-keys.json` | `role` omitted or wrong — the bundle carries origin keys only |
| `origin key id "x" is declared twice` | `origin-keys.json` | — |
| `key "x" unusable: …` | `origin-keys.json` | `algo` is not `ed25519`, or `public_key` is not 32 valid hex-encoded bytes |
| `unknown field \`…\`` | `origin-keys.json` | the one file that rejects unknown fields |
| `attestation for "x", which is not an enrolled origin key` | `attestation.json` | copy-paste slip |
| `… is not inside a git repository — pass --label` | — | compile stamps a commit sha, or an explicit label |
| refusal to stamp a dirty tree | — | a `policies@<sha>` citation must mean the bytes that commit contains |

See also [policies-cedar.md](policies-cedar.md#failure-modes-worth-knowing)
for the failures that happen at *runtime* rather than at compile time.
