# Contributing

Contributions are welcome. Two rules govern every change, and neither is a
style preference. The product is a proof artifact, and its guarantees live
in the invariants:

1. **Read the invariants first** (see the README): frozen record format,
   `obsign-audit-core` as the sole proof implementation, no JSON hashing, no network
   calls in the gateway, everything authorizing must be signed, fsync before
   forwarding, degradations stay visible. A pull request that weakens one of
   these will be refused regardless of what it gains.
2. **Codebase and documentation are English only.**

## Licensing of contributions

The project is licensed under [Apache-2.0](LICENSE). Inbound = outbound: by
contributing, you license your contribution under Apache-2.0, nothing more is
asked. There is no CLA, no copyright assignment, no relicensing grant.

Instead, the project uses the [Developer Certificate of
Origin](https://developercertificate.org/) (DCO 1.1): every commit must be
signed off, certifying you have the right to submit the change under the
project's license.

```bash
git commit -s
```

adds the required trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and a reachable email address. Unsigned commits will not
be merged.

## Before opening a pull request

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

Match the style of the surrounding code; the tree is not rustfmt-clean and a
wholesale reformat is its own decision, not a side effect of your change.

New behavior comes with tests; a change to anything signed or hashed comes
with a tamper test proving the verifier refuses the altered artifact.
