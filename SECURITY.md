# Security policy

Obsign exists to make a claim checkable rather than believed. A flaw that lets
someone produce a pack which verifies while the log is false is the worst
thing that can happen to this project, and it is the kind of report we most
want to receive.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting, on the **Security** tab of this
repository ("Report a vulnerability"). It opens a private thread with the
maintainers and needs no account beyond your GitHub one.

If you would rather use email: **guillaume@obsign.tech**.

Please do not open a public issue for something that lets an attacker forge or
break a proof. For anything else, a normal issue is fine and faster.

What helps, roughly in order of usefulness:

- the invariant you believe is broken, stated in one sentence;
- the commit or version tag you tested;
- a reproduction, ideally as a failing test in the style of
  `crates/obsign-audit-core/tests/tamper.rs`, which asserts that the verifier
  *fails* to detect something it should catch;
- what an attacker gets out of it.

## What to expect

Acknowledgement within three business days, and an assessment of whether we
agree it is a vulnerability within ten. This project has a small maintainer
team and no on-call rotation; if you have heard nothing after ten days, that
is our failure, and you are welcome to nudge us by opening a public issue that
says only that you are waiting on a private report, with no detail.

We fix, publish a release, credit you in the advisory unless you would rather
we did not, and coordinate the disclosure date with you. There is no bug
bounty and no swag. Saying so plainly is more useful than leaving you to
guess.

## Supported versions

Pre-1.0, only the most recent version tag on `main` is supported. There are no
backports to earlier tags.

## In scope

The trust story, first and foremost:

- a forged, altered or truncated evidence pack that `obsign verify
  --trusted-keys` still exits 0 on;
- an act that reaches the MCP server without a recorded decision, or a
  recorded decision that does not match what was actually enforced;
- a token accepted that should not have been: algorithm confusion, audience or
  expiry not enforced, a signature verified against the wrong key;
- anything unsigned acquiring authority, whether it is a policy, a tool
  catalogue, an identity bundle, its machine markers or a deployment bundle;
- an argument the catalogue does not declare being read, or an argument value
  reaching the log instead of its hash;
- the gateway coming into possession of a signing key, or the ledger sealing
  over a WAL that diverges from sealed history;
- a discovery filter that can be walked around, so that an agent reaches a
  tool, resource or prompt the policy hides from it.

## Out of scope

Not because these do not matter, but because they are already known, already
documented, or deliberate. Telling us about them is not a vulnerability
report:

- the exemptions listed under **Known debt** in the README:
  `notifications/progress` and `notifications/cancelled` carry free text and
  are relayed unrecorded, in both directions;
- `--insecure-declared-identity`. It is a development flag whose name says
  what it does, and the log marks what it produced as declared, not proven;
- verification without `--trusted-keys` exiting 3 rather than 1 on a pack
  signed with a made-up key. A pack that vouches for itself proves nothing,
  and the report says so;
- an evidence pack not containing prompt or argument values. It holds their
  hashes by design, and that corollary is stated in the README;
- resource exhaustion caused by an already-authenticated agent, and the
  absence of rate limiting. The gateway arbitrates authority, not capacity;
- the demonstration material: `examples/`, `mkbundle`, `mint_demo_token`, and
  the seal seed read from a file. These are development-grade by construction
  and documented as such; the production paths are the signed bundles and
  `Pkcs11Sealer`;
- a vulnerability in a third-party dependency. Report it upstream. Do tell us
  if the way Obsign uses it makes it exploitable here, because that part is
  ours.

## Threat model

The README section **What verification establishes** states what a pack proves
and, just as importantly, what it does not. `docs/design/` carries the design
notes for attestation, session certificates, WAL origin authentication and the
argument policy. A report that shows one of those documents to be wrong is as
valuable as one that shows the code to be.
