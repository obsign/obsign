# Identity and delegation

How the gateway proves *who* is behind each act: OIDC verification without
network calls, the RFC 8693 actor chain, provider configuration and key
rotation. Back to the [README](../README.md).

## Proven or declared identity

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
configuration at all **the gateway refuses to start**. There is no silent
fallback to anonymous mode.

Design choices worth knowing:

**No network calls.** The JWKS lives inside a signed identity bundle,
distributed by the control plane alongside the policy bundle, on the same
channel and the same rotation cadence. The gateway stays deployable air-gapped
and adds no outbound surface to justify in a security review.

**The identity bundle is signed too.** The JWKS decides *who can mint valid
tokens*, and the claim mapping decides *which groups get assigned*. Whoever can
write that file can mint an identity for themselves and bypass the whole
attribution chain. That is the same threat as an unsigned rules file, and it
deserves the same answer.

**The algorithm comes from the JWKS, never from the token header.** That is the
classic JWT flaw: an attacker declares `HS256` and HMAC-signs with the IdP's
public key, which is public by definition. A dedicated test covers it.

**Expiry is re-evaluated on every act.** An agent session routinely outlives a
token; checking once when the session opens amounts to drawing unlimited
authority from a 30-minute token. If the token was renewed on disk, the gateway
picks it up and **records a new delegation**; otherwise an act performed under
a renewed token would appear authorized by an already-expired delegation.

## Delegation chain

A token that says "marie.dupont" does not say *who was acting in her name*.
RFC 8693 token exchange does, and Obsign records it.

| Token mode | Actor chain | `principal_kind` |
|---|---|---|
| User token | `u:marie.dupont` | `human` |
| Token exchange (`act` claim) | `support-copilot → u:marie.dupont` | `delegated_human` |
| `client_credentials` | `batch-agent` | `machine` |

The third case is the one nobody covers: a batch agent, with no human behind
it, deleting in production. It is recognised by the union of the markers the
target IdPs actually emit (`sub == client_id`, Entra ID's `idtyp: "app"`,
Keycloak's `service-account-` username prefix), and the policy can then
express it:

```cedar
@id("destructive_requires_human")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };
```

"No agent destroys anything without an identifiable human at the end of the
chain." Cedar also receives `context.actor_chain` (a set),
`context.delegation_depth` (to bound multi-agent topologies) and
`context.principal_kind`.

A malformed chain is refused, never read around: an `act` without a string
`sub`, or nested more than 8 deep, fails verification instead of being
recorded as a shorter chain (or as no delegation at all).

Try the three modes:

```bash
cargo run -p obsign-proxy --example mint_demo_token -- /tmp/demo 1800 exchange
cargo run -p obsign-proxy --example mint_demo_token -- /tmp/demo 1800 service
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
no `principal in Group::"dba"` rule ever matches, with no visible error.

The same goes for what marks a token as a machine's. The defaults recognise
the three shapes the target IdPs emit; an IdP with its own convention is
described in the bundle instead of being special-cased in code (signed from
format `obsign-identity/2` on):

```json
"claims": {
  "machine": {
    "subject_is_client": true,
    "equals":   [{ "path": "/idtyp", "value": "app" }],
    "prefixes": [{ "path": "/preferred_username", "value": "service-account-" }]
  }
}
```

Marker paths speak the same language as the claim paths, wildcard included.
Because these markers decide `principal_kind`, and hence which Cedar rules
apply, they live **inside the signed bundle**, never as a file option: widening
what counts as human must be signed like any other authorization change. A
`obsign-identity/1` bundle still verifies unchanged, but only with the
default markers; carrying custom ones requires re-signing as `/2`, since the
v1 signature does not cover them.

Two realm-side configuration points for Keycloak, done once:

- **audience mapper** — by default access tokens carry `aud: "account"`
  instead of your client ID. The gateway will refuse them, and that is
  intended: relaxing the audience check would let through a legitimate token
  issued for another service;
- **token exchange** — [officially supported since Keycloak 26.2](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2),
  enable it on the agent's client to obtain the `act` claim.

For SAML, put Keycloak **in front** as a SAML↔OIDC bridge. The gateway then
never has to know SAML exists.

### Key rotation

Providers rotate their signing keys routinely, Keycloak in particular on its
realm keys. The gateway makes no network calls, so "rotation" means **reloading
the signed identity bundle from disk**, where the control plane published the
new version.

```bash
python3 scripts/demo-rotation.py /tmp/rot
```

```
[obsign] identity PROVEN — u:marie.dupont via …/realms/corp — expires in 2 s — bundle identity@k1
[server] EXECUTING ticket_update
>>> rotation: the IdP moves to k2, the control plane republishes the bundle
[obsign] rotation detected (unknown kid "k2") — identity bundle reloaded: identity@k2, 1 key(s)
[obsign] delegation renewed (generation 2) — u:marie.dupont — expires in 3596 s
[server] EXECUTING ticket_update
```

Properties worth knowing:

**Triggered by the unknown `kid`.** That is the exact signal of a rotation, so
reloading costs nothing in nominal operation: zero disk access as long as
nothing rotates. One retry only; looping would turn a permanently invalid
token into a disk-access loop.

**The signature is revalidated on every reload.** Without it, hot rotation
would be the easiest way to inject a JWKS: writing the file would be enough.

**An older bundle is refused on reload.** A signature proves the control
plane published a bundle once, not that it still stands by it: an old bundle
still listing an IdP key revoked since verifies as well as the current one.
`obsign-identity/4` signs an epoch (the source commit time, in seconds; see
`obsign-control compile --epoch`), and a reload below the epoch in force is
refused like any other invalid bundle. A pre-`/4` bundle counts as epoch 0,
so it cannot replace a `/4` one; between two pre-`/4` bundles there is no
order. The epoch in force lives in memory: a gateway restarted on an older
file starts on it, so the file's own write access stays the boundary.

**An invalid bundle never takes the gateway down.** Botched deployment,
truncated or deleted file, bad signature: the previous configuration stays in
force and the service keeps running. The return type enforces it.
`ReloadOutcome::Failed` is not an `Err`, so no caller can treat it as fatal by
accident.

**Bounded frequency.** One attempt per second. A flood of tokens with random
`kid` values therefore causes one file read per second, however many requests
arrive. Detection uses the content hash instead of the modification time:
mtime granularity goes up to one second on some filesystems, enough to miss
two writes close together.

**The reload is itself recorded.** A `config_reload` record (tag 8) goes
into the audit chain, carrying the version and content hash of the bundle in
force after the attempt. A reload changes what the log means: the same token
is refused before it and accepted after, so "which keys were trusted when
this act happened?" must read directly off the chain, from the last applied
`config_reload` or the opening `agent_session` above the act. Rejected
reloads are recorded too, with the hash of the refused bytes: dropping a
rogue JWKS on disk is an attack, and the attempt is precisely what an
investigation wants to see.
