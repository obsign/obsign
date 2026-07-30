# Argument-aware tool policy — design

Status: **steps 1–3 implemented** (2026-07-31): `ArgSpec` in the
catalogue, `obsign-policy/2` signing, extraction + `context.args` totality
in the engine (step 1, 21 tests in `policy/tests/args.rs`); gateway wiring
+ e2e/http coverage, including "refused on its arguments never reaches the
server" (step 2); compile-time checks — `Engine::smoke_check`, v2 emitted
only when a tool declares args (step 3); demo — `send_message` +
`support_channel_only` in the mkbundle reference policy, argument refusal
in `run-demo.sh`, flow verified live end-to-end including the sealed pack
(step 4); docs — README demo/decision/format sections, v1→v2 cutover rule
in `deploy-docker.md` (step 5). **All five steps landed.** One point
was adjusted on contact with the code and is now §3.8: the `tools/list`
filter reused `evaluate`, which would have *hidden* every
argument-restricted tool — the listing gets its own entry point. Closes the gap between what the policy
engine arbitrates (tool × identity × context) and where real-world refusals
actually live (this tool, but not with *these* arguments). Prompted by a
design-partner question: "how do I allow `send_message`, but only to
`#support`?" — today the honest answer is "split the tool at the MCP
server", which does not survive third-party servers.

## 1. The gap

For a `tools/call`, the engine decides on the principal, the tool's signed
catalogue attributes (`destructive`, `required_scope`), and the delegation
context (`env`, `scopes`, `actor_chain`, …). The call's **arguments never
reach Cedar**: `ToolRequest` has no argument field, and the gateway only
hashes them into the audit record (`args_hash`,
`obsign-proxy/src/gateway.rs`). Both facts are deliberate — the log keeps
hashes, not contents, because arguments carry personal data — but the
*decision* was never supposed to inherit the *log's* blindness.

Consequences today:

1. **The dominant class of real refusals is inexpressible.** "`query` but
   not on table `salaries`", "`send_message` but only to `#support`",
   "`transfer` under 10 000 €" — every one of these is an argument
   constraint. Tool-level policy can only say yes or no to the verb, never
   to the object.
2. **The workaround does not scale.** Splitting `send_message` into
   `send_support_message` at the MCP server works when you own the server.
   The catalogue's own premise is that you often do not (the Slack server
   ships its 20 tools as-is); the gateway exists precisely to subset servers
   you cannot fork.
3. **Capabilities already got this right.** `resources/read` passes
   `context.target` to Cedar and policies pattern-match it
   (`context.target like "docs/*"`, `policy/src/engine.rs`). Tools — the
   channel with actual side effects — are the ones left blind. The
   asymmetry is backwards.

## 2. Decision

**The signed catalogue declares, per tool, which arguments the policy may
see and with which types; the gateway extracts exactly those, and the
engine exposes them to Cedar as `context.args` — in memory only, for the
duration of the decision. The WAL keeps `args_hash`, unchanged.**

Shape of the declaration (`ToolDef` in the policy bundle):

```jsonc
{
  "name": "send_message",
  "server": "slack",
  "policy_args": [
    { "name": "channel", "kind": "string" },
    { "name": "thread",  "kind": "string", "default": "" }
  ]
}
```

And the rule the design partner asked for:

```cedar
@id("support_channel_only")
forbid (principal, action == Action::"tool_call", resource == Tool::"send_message")
when { context.args.channel != "#support" };
```

### Why a declared allowlist and not the raw argument object

- **Cedar needs types.** JSON reaches the gateway untyped and
  attacker-shaped. A declaration gives each exposed value one type, one
  coercion rule, and one failure mode, instead of Cedar improvising over
  arbitrary nesting.
- **Data minimisation by construction.** The bundle is the written,
  reviewed, signed list of exactly which fields the policy may read.
  Arguments carry personal data; "the engine sees only what a pull request
  declared" is the answer a GDPR/DORA auditor accepts, and it is the same
  answer the catalogue already gives for tools ("we do not let through what
  we have not described").
- **Bounded evaluation.** Policies never traverse unbounded input; caps
  (§3.4) are enforceable at extraction because extraction knows what it is
  looking for.

### Rejected alternatives

**Rejected — expose the full `arguments` JSON as a Cedar record.** Every
policy inherits the type confusion of every client: the day an agent sends
`{"channel": {"id": "C01"}}` instead of a string, a `==` comparison becomes
an evaluation error, and evaluation errors fall to the fail mode. An
attacker who controls argument *shape* must not be able to steer the engine
into fail-open (§3.3 makes this structural). Also maximises personal-data
exposure for no expressiveness gain.

**Rejected — per-tool Cedar actions (`Action::"tool_call:send_message"`)
with schema validation.** Cedar's schema could then type `context.args` per
action, catching policy typos at compile time. But it multiplies actions,
breaks the stable-rule-id story (rules engraved in sealed logs must keep
meaning across bundle versions), and forks every existing policy that says
`action == Action::"tool_call"`. Typo protection is bought cheaper in §3.5.

**Rejected — argument rewriting (the gateway forces `channel` to
`"#support"`).** Tempting one-line extension, refused on principle: the
gateway arbitrates and proves, it does not silently alter what the agent
said. A rewritten call makes `args_hash` attest a message the agent never
sent — the audit chain would prove a lie. Refusal is the only honest
verdict.

## 3. Detailed design

### 3.1 Catalogue: `ArgSpec`

```rust
/// One argument the policy is allowed to see. Anything not declared here
/// never reaches the engine — the allowlist is the privacy boundary.
pub struct ArgSpec {
    /// Name under `context.args` in Cedar.
    pub name: String,
    /// Where to read it in the call's `arguments` object: a JSON pointer
    /// (RFC 6901). Defaults to `/<name>` with the name escaped per RFC 6901
    /// (`~`→`~0`, `/`→`~1`), so a name containing those characters resolves
    /// to the literal argument key rather than a nesting path.
    pub at: Option<String>,
    /// string | long | bool | string_set
    pub kind: ArgKind,
    /// Injected when the argument is absent from the call. An arg with no
    /// default is required-if-declared: absence refuses the call (§3.3).
    pub default: Option<serde_json::Value>,
}
```

- `string_set` covers JSON arrays of strings (recipient lists, label sets);
  Cedar receives a set, policies use `.contains()`.
- `long` accepts integral JSON numbers in `i64` range only. Floats are
  refused, not rounded: an amount check that rounds is an amount check with
  a hole. Monetary rules that need decimals declare minor units (cents) —
  stated in the doc comment, not solved with float comparison.
- No nested records: `at` may point *into* nesting
  (`"/message/channel"`), but the value it lands on must be a scalar or an
  array of strings. Structure stays at the extraction boundary; Cedar sees
  flat, typed values.

### 3.2 Engine: `context.args`, total by construction

`Engine::evaluate` gains the raw arguments (`&serde_json::Map`) on
`ToolRequest`. For the evaluated tool the engine builds `context.args`
containing **every declared arg, always**:

- present in the call → extracted and coerced per `kind`;
- absent with a `default` → the default;
- absent without a default → the call is refused before Cedar (§3.3).

- **present as an explicit `null`** → treated as absent (default, or
  refuse). MCP client SDKs routinely serialize an omitted optional field as
  `null`; counting that as a value would coerce-fail and deny a call that
  omitting the key entirely would have allowed.

Totality means a policy reading `context.args.channel` can never hit a
*missing-attribute* error because of anything the agent did. A well-typed
value can still make the expression itself unevaluable — i64 arithmetic
overflow, `ip()`/`decimal()` over a non-parsing string — which surfaces as a
Cedar evaluation error. On a tool that declares arguments, that error is
attacker-triggerable, so it **denies** rather than reaching the fail mode
(§3.3): the customer's fail-open choice governs input-*independent* failures
only.

Tools with an empty `policy_args` get an empty `context.args` record;
existing bundles and policies are untouched.

### 3.3 Input-driven failures are denials, never fail-mode

A declared argument that is missing (no default), of the wrong JSON type,
non-integral, out of `i64` range, or over the size caps refuses the call
**before Cedar runs**: `Outcome::Deny`, `policy_id` absent, reason
`args: channel: expected string` — the same shape as the existing
out-of-catalogue refusal ("policy_id absent: no rule decided, the gate
itself did").

The principle behind this — and the load-bearing one for the whole feature:
**fail-open is only defensible for input-*independent* failures.** The fail
mode exists for failures of *our* machinery (unreadable bundle, a policy
typo), which fail the same way for every request, so the customer can
knowingly trade caution for availability on a read-only tool. The moment a
verdict depends on arguments, a failure becomes input-*dependent* and
attacker-triggerable, and must not reach the open path. Two layers enforce
this on a tool that declares arguments:

1. **Extraction** denies malformed input (wrong type, absent-required,
   oversize) before Cedar runs — a crafted *shape* never reaches a rule.
2. **Evaluation** — a *well-typed* value can still make a policy expression
   unevaluable (i64 arithmetic overflow, `ip()`/`decimal()` over a
   non-parsing string). For a tool that declares arguments, that Cedar
   evaluation error also **denies** (`policy_id` absent, reason
   `policy evaluation failed over arguments, denied`) instead of falling to
   the fail mode. Tools that declare *no* arguments keep the customer's fail
   mode: their evaluation errors cannot be steered by a request.

So a fail-open, argument-declaring tool cannot be pushed to its open path by
any request — malformed or crafted-but-well-typed alike.

### 3.4 Caps

- ≤ 16 declared args per tool (catalogue-time check);
- ≤ 4 KiB per extracted string, ≤ 64 elements per set (call-time, refusal
  per §3.3). Policy-relevant arguments are identifiers — channels, tables,
  paths, amounts — not payloads; the cap is a statement of that, and it
  bounds what a hostile agent can make Cedar chew on (`like` over
  megabytes).

Byte-exact comparison, no Unicode normalisation in v1: the gateway compares
what was sent, the policy author writes patterns accordingly (`like`
exists for families). Normalisation is a semantic opinion about the
*tool's* matching rules, which the gateway does not know (§4.1); silently
NFC-folding would make the engine disagree with `args_hash` about what the
argument was.

### 3.5 Compile-time checks (control plane)

`compile()` already runs `Engine::load` so that what passes CI cannot fail
at gateway startup. It grows, in the same spirit:

- `ArgSpec` validation: duplicate names, invalid JSON pointer, malformed
  default (default must itself coerce under `kind`), caps;
- a **smoke evaluation** per catalogued tool: one synthetic request with
  every declared arg at its default (or zero value), evaluated against the
  real policies. An evaluation error here — almost always a typo'd
  `context.args.<name>` — fails compilation with the rule's `@id`, instead
  of surfacing months later as a fail-mode event on a live gateway. Not
  exhaustive (branches guarded by other conditions survive), stated as
  such; it converts the common case from runtime to CI.

### 3.6 Bundle format: `obsign-policy/2`

`signing_bytes()` is a canonical positional encoding; `ToolDef` growing a
section means the bytes change. Conditional encoding ("only encode
`policy_args` when non-empty, so old signatures keep verifying") is
rejected on principle: a canonical encoding with optional segments is how
two bundles end up sharing bytes, and the whole point of the explicit
`Encoder` is that this class of bug cannot exist.

So: format bumps to `obsign-policy/2`; v2 signing bytes encode the
`policy_args` section unconditionally (empty lists encode as length 0).
The precedent that forbade bumping — evidence packs, where a bump strands
sealed history — does not apply here: bundles are not historical artifacts,
they are re-minted from git at will (`policies@<sha>`), and what the log
engraves is the version string and rule ids, not the bundle encoding.

Compatibility matrix, all paths loud:

- new gateway + v1 bundle → loads, no argument rules (empty `policy_args`
  everywhere);
- old gateway + v2 bundle → `UnknownFormat` at startup, gateway refuses to
  run. Correct: a stale gateway silently enforcing *less* than the bundle
  says would be the worst outcome. Upgrade gateways before publishing v2
  bundles; the control plane can keep emitting v1 until the fleet is ready
  (emit v2 only when some tool declares `policy_args` — mechanical, and
  makes the cutover self-serve).

### 3.7 Privacy and the audit record

Nothing changes in the WAL, the pack, or the console:

- argument values exist in gateway memory for the microseconds of the
  decision; they are never serialised into any record. `args_hash` keeps
  pinning what was sent; the verdict keeps engraving which `@id` decided.
- The known cost, stated: an argument-dependent verdict is **attested but
  not replayable** from the pack alone — the pack proves rule
  `support_channel_only` refused this call, and pins the arguments'
  hash, but does not let the auditor re-run the decision without the
  argument values. That is "hashes, not contents" working as designed. The
  road to replayability already has a reserved seat: the `args_sealed`
  field on `ToolCall` (customer-key-encrypted arguments, hash-bound to
  `args_hash`) — a separate design when a partner's auditor actually
  requires replay, not before.

### 3.8 Listing visibility *(added on contact with the code)*

The `tools/list` filter reuses the engine to decide what the agent sees.
Run through `evaluate`, a tool with a required declared arg would be
refused at extraction — a listing carries no arguments — and therefore
**hidden**, for every agent, precisely because it has argument rules. The
flagship example would remove `send_message` from the catalogue view while
leaving it perfectly callable.

Visibility and permission are different questions ("could this agent ever
use this tool?" versus "is this call allowed?"), so the listing gets its
own entry point, `Engine::evaluate_listing`:

- `context.args` is deliberately absent, and evaluation errors do not fall
  to the fail mode. Cedar treats a rule whose condition cannot evaluate as
  not applying, so the decision is taken *as if the argument rules did not
  exist* — which is exactly the visibility answer: an argument-restricted
  tool stays listed; a tool-level rule (destructive-without-human, group,
  scope, env) still hides.
- The permissive bias is safe by construction: the listing is hygiene, and
  every actual call still goes through strict `evaluate`. The residual is
  cosmetic — a tool whose only permits are argument-dependent shows up in
  the list even for an agent whose every call will be refused.
- True "could any argument make this pass" visibility is satisfiability,
  which Cedar only offers as experimental partial evaluation. Not worth an
  experimental dependency for a listing; revisit if it stabilises.

Two limitations of "drop the unevaluable rule", accepted and pinned by
tests so they are conscious choices rather than surprises:

- **The leniency is not scoped to argument errors.** Any evaluation error
  on the listing path — a typo'd non-argument attribute, a type mismatch —
  is dropped, not escalated to the fail mode the call path would apply. So
  a broken rule can shift a tool's listing visibility with no degradation
  record. Bounded on purpose: visibility is best-effort, the call path is
  the only enforcement point, and the same broken rule is caught strictly
  the moment the tool is actually called.
- **Only `forbid`-style argument rules keep a tool listed.** A tool whose
  *only* permit is argument-conditional (`permit ... when {
  context.args.channel == "#support" }` with no broad permit) has that
  permit dropped on the listing path → default-deny → the tool is hidden,
  though conforming calls succeed. Write argument restrictions as a
  `forbid` paired with a broad `permit` (as the reference policy does), not
  as a permit that gates visibility on `context.args`. Pinned by
  `permit_only_argument_rules_hide_the_tool_from_listings`.

## 4. What this deliberately does not fix

1. **Request-as-written, not effect.** The policy matches the argument the
   agent *sent*. If Slack resolves channel `"C0123ABCD"` to the same place
   as `"#annonces-direction"`, a rule pinned to the display name misses the
   id form. The gateway cannot know a tool's aliasing semantics; authors
   must pin the canonical form the tool actually keys on, and
   tool-splitting at the server stays the right answer where no canonical
   form exists. Same reasoning as `destructive` staying a tool-level bit.
2. **Content, not authorization.** A prompt-injection payload *inside* an
   allowed argument (`message` text sent to the allowed `#support`)
   passes. Judging content is a different product surface (and a different
   failure mode: probabilistic, where this engine is deliberately not).
3. **Responses.** What comes *back* from the tool is not inspected. Result
   filtering/redaction is its own design if it ever earns its place.

Note on a residual that *is* closed: an earlier draft left in-policy
evaluation errors over well-typed arguments (i64 overflow,
`ip()`/`decimal()` parse failures) routing to the fail mode, so a fail-open
argument tool could be pushed to its open path by a crafted-but-well-typed
value. §3.3 now denies those on any argument-declaring tool — the residual
is gone, at the cost that such a tool no longer honours fail-*open* on a
genuine policy typo either (it denies). That is the safe direction, and the
compile-time smoke check (§3.5) catches the typo class before it ships.

## 5. Implementation plan

Order chosen so each step lands green on its own:

1. **policy**: `ArgSpec`/`ArgKind`, `policy_args` on `ToolDef`, format
   constant set `{1, 2}` at load / emit-side selection, v2
   `signing_bytes`; extraction + coercion + caps in the engine
   (`ToolRequest.args`, `context.args` totality, §3.3 refusals). Tests:
   type confusion (object where string expected), float refusal, missing
   required, default injection, set caps, oversize string, v1 bundle
   round-trip untouched.
2. **obsign-proxy**: hand `params.arguments` to the engine; nothing else —
   extraction lives in one place. e2e: a call refused *on its arguments*
   never reaches the server (extend the existing never-reached assertion);
   http.rs: same through the HTTP transport.
3. **control-plane**: §3.5 checks in `compile()`; emit v2 only when used.
   Tests: typo'd arg name in a rule fails compile with the `@id`.
4. **mkbundle + docker demo**: give the reference policy the
   `support_channel_only` rule and the demo script a refused
   `send_message` to a forbidden channel — the argument refusal becomes
   part of the standard demo narrative (it is the question every prospect
   asks first).
5. **README + docs**: the policy section gains the declaration/rule pair
   from §2; `deploy-docker.md` mentions the v1→v2 cutover rule.

Rough size: the mechanical surface is small (one struct, one context
record, one format branch); the tests are the bulk — consistent with this
codebase's ratio.

## 6. Open decisions

1. **`long` vs Cedar `decimal` for amounts.** v1 says integral minor units;
   Cedar has a `decimal` extension type if partners push back. Additive
   later (`kind: "decimal"`), no need to decide now.
2. **Should `context.args` also feed capability arbitration?**
   `resources/read` already has `context.target`; prompts take arguments
   too (`prompts/get` params). Deferred: prompts' arguments are unsigned
   free-form (no catalogue to declare types in — the same reason
   capabilities are default-deny-on-identifier today). Revisit if a
   partner writes prompt-argument rules by hand.
3. **Per-arg redaction marker for future `args_sealed`.** When sealed
   arguments arrive, `ArgSpec` is the natural place for "this field may be
   sealed / this field must never be persisted even encrypted". Reserved,
   not designed here.
