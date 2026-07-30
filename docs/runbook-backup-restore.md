# Backup, restore and retention runbook

The operator's counterpart to [deploy-docker.md](deploy-docker.md): how to
back up the WAL and the ledger store, restore them after a loss, and keep
proofs verifiable over your retention window. How long that window is comes
from your contract or your regulator; this runbook uses 24 months — a
common regulatory floor — as the worked example, and the procedure is the
same for longer windows.

One property shapes everything here: **integrity travels with the data, not
with the backup**. Every record is hash-chained and origin-signed, every
checkpoint is signed and re-verified on load, and a store whose disk was
edited refuses to open instead of serving rewritten history. A backup
therefore protects *availability* (a lost disk must not lose the audit
trail) and *confidentiality* (records name identities, tools and arguments —
encrypt copies at rest), never integrity. The corollary is just as useful:
a restored copy proves itself or refuses to load, so every restore ends
with a machine-checkable verdict, not a judgement call.

## What there is to save

| Artifact | Written by | Typical path (Docker) | Contents |
|---|---|---|---|
| WAL directory | gateway (`obsign-proxy`) | volume `obsign-wal`, `/var/lib/obsign/wal` | one `<chain>.jsonl` per audit chain — with the HTTP transport, one chain (hence one file) per session, named `<chain-id>-<session>` |
| Ledger store | ledger (`obsign-ledger`) | volume `obsign-store`, `/store` | per chain: `<chain>.checkpoints.jsonl`, `<chain>.anchors.jsonl`; store-wide: `keys.json` (public halves of every sealing key) |
| Evidence packs | `obsign-ledger export` | wherever `--out` pointed | self-contained proof (records + checkpoints + keys + anchors); **the retention artifact** — see below |
| Trust material | ops | version-controlled config | `trusted-keys.json` (ops keys), the signed deployment bundle. Small, changes rarely; treat as configuration, back up with your config. |
| Sealing key | HSM | never on these paths | not yours to file-copy: the HSM vendor's backup ceremony applies. Losing it stops **new** seals; it invalidates nothing already sealed (verification uses the recorded public key). A replacement key takes a **new** `key_id` — re-binding an old id is refused (`KeyConflict`). |

Everything in the first three rows is JSONL or JSON, append-only, readable
with `tail`. That is deliberate, and it makes backup boring: files only
grow, a torn final line (crash mid-append) is tolerated and trimmed by the
owning process, and `keys.json` is replaced atomically (write-then-rename).
Hot copies are safe at the file level.

## Backing up

### Copy order matters

The store's files reference each other: an anchor names a checkpoint, a
checkpoint names a signing key. `Store::open` re-verifies those references
and refuses a store where they dangle. A copy taken in the wrong order
while the ledger is sealing can capture a reference without its referent —
a backup that refuses to restore even though production is healthy.

Copy **in reference order**, so the copy can never hold a reference to
something it missed:

1. `*.anchors.jsonl`
2. `*.checkpoints.jsonl`
3. `keys.json`

Across the two directories: **store before WAL**. Sealed coverage must
never run past the end of the log (that is `TruncatedLog`, an incident, not
a retry). Copying the store first guarantees the WAL in the same backup set
is at least as advanced as the store.

```bash
# Hot backup, safe while gateway and ledger run.
rsync -a store/*.anchors.jsonl      backup/store/ 2>/dev/null || true
rsync -a store/*.checkpoints.jsonl  backup/store/
rsync -a store/keys.json            backup/store/
rsync -a wal/                       backup/wal/
```

A single atomic filesystem snapshot (LVM, ZFS, EBS) of both directories is
equivalent and simpler — the ordering above exists for plain file copies.
Either way, restore-test it (below).

### Frequency

Records lost between the last backup and a disk failure are lost acts:
their proofs end at the backup point. Your backup interval **is** your RPO
for the audit trail. The WAL is append-only and fsync'd per record, which
makes continuous replication cheap; at minimum, back up at the sealing
interval, so nothing sealed exists only on one disk.

### Verify every backup

A backup nobody has opened is a hope. Export and verify from the copy —
`export` reads the WAL without writing to it, and both `export` and the
verifier fail loudly on a damaged copy:

```bash
for f in backup/wal/*.jsonl; do
  chain=$(basename "$f" .jsonl)
  obsign-ledger export --wal backup/wal --store backup/store \
      --chain-id "$chain" --out "/tmp/$chain.pack.json" \
      --deployment-bundle deployment-bundle.json
  obsign verify --strict --trusted-keys trusted-keys.json \
      "/tmp/$chain.pack.json" || echo "BACKUP BAD: $chain"
done
```

Exit code 0 or the backup is not a backup. (Opening the store copy may trim
a torn final line captured mid-append — that is the normal crash-recovery
path, not damage.)

Then encrypt and follow 3-2-1: two media, one off-site. The copies carry no
key material, but they do carry who did what — treat them as confidential.

## Restoring

Ground rules for every scenario: restore WAL and store **from the same
backup set**; a newer WAL with an older store is fine (the unsealed tail
gets sealed on the next pass), an older WAL with a newer store is
`TruncatedLog`. And volumes must be writable by the runtime user
(uid 65532 in the shipped images).

### Gateway host lost

Restore the WAL directory onto a volume that honours `fsync`, restart the
gateway. It replays the log, verifies every record's origin signature
against the deployment bundle, and resumes exactly where the copy ends.
Two refusals are possible, and both are the system working:

- `BrokenChain` / `Corrupt` — the copy is damaged; restore the previous
  backup.
- `ForeignRecord` — the tail carries records no trusted origin key signed:
  either the copy was tampered with, or the deployment bundle handed to the
  gateway is missing a key that legitimately signed (a rotation window).
  Nothing is trimmed or adopted; a human decides. Do not "fix" this by
  deleting lines.

Acts performed after the last backup are absent from the restored log.
Say so in the incident record — a documented gap is a defensible gap; a
quietly shortened chain is not.

### Ledger host lost

Restore the store directory and run one seal pass. `Store::open`
re-verifies every checkpoint (signature, chaining, gapless coverage) before
serving anything, so a successful open *is* the integrity check.

- `StoreBroken` — the copy is damaged or was edited; restore an older
  backup. The WAL is untouched by this: once a good store is back, sealing
  resumes and covers the interim.
- `TruncatedLog` on the next pass — your restored WAL is older than the
  store: sealed records are missing from the log. Restore a newer WAL
  backup. If none exists, the store and the archived packs remain the
  evidence of what was sealed; open an incident rather than deleting the
  store to make the error go away.
- `DivergedLog` — the WAL and the store disagree about sealed history: one
  of them is not the original. The anchors arbitrate — an RFC 3161 token
  fixes what the checkpoint said, and when.

### Both hosts lost

The archived evidence packs are self-contained and verify offline with no
service: history is not lost, it is already in its long-term form.
Operations resume on fresh chains (with the HTTP transport, every new
session is a new chain anyway). Do not attempt to reconstruct WAL files
from packs to "resume" old chains — the packs are the proof of record;
new work gets new chains.

### Sealing key lost

Nothing already sealed is affected. Provision a new key in the HSM, seal
under a **new** `key_id`, and distribute the updated public key to whoever
verifies. The old id stays bound to the old key forever — that binding is
what keeps old seals verifiable.

## Retention

The retention artifact is the **evidence pack**, not the raw WAL. A pack is
one JSON file, self-contained, offline-verifiable for as long as you can
run `sha256` and Ed25519 — the right shape for a multi-year shelf. The WAL
and store are the working set; the archive is packs.

Per chain (with the HTTP transport: per session), the lifecycle is:

1. **Close** — the session ends; the chain file stops growing.
2. **Seal** — a pass reports nothing left to seal for that chain.
3. **Anchor** — `anchor request` / `anchor attach` on the latest
   checkpoint; it transitively covers every earlier one through the
   checkpoint chain, so one anchor per chain suffices.
4. **Export** — `obsign-ledger export --deployment-bundle …` writes the
   pack and self-verifies; a non-zero exit means do not archive.
5. **Verify independently** — `obsign verify --strict --trusted-keys` with
   the *out-of-band* copy of the keys, exit 0 required. This is the check
   an auditor would run; run it before they do.
6. **Archive** — pack plus its `sha256` into immutable storage (S3 Object
   Lock or equivalent), retention set to your window (here: 24 months)
   counted from the anchor's TSA time, two locations. A layout that ages well: `archive/<yyyy>/<mm>/<chain>.pack.json`.
7. **Prune** — only now may the chain's WAL file and its
   `<chain>.checkpoints.jsonl` / `<chain>.anchors.jsonl` be deleted.
   Pruning removes whole chains' files, never lines within a file — a
   shortened file is indistinguishable from tampering, and the tooling will
   treat it as such. `keys.json` is kept for the life of the store.

## Periodic re-verification

Quarterly, and after every restore, re-verify the archive:

```bash
fail=0
for pack in archive/*/*/*.pack.json; do
  sha256sum -c "$pack.sha256" || fail=1
  obsign verify --strict --trusted-keys trusted-keys.json "$pack"
  [ $? -eq 0 ] || { echo "FAIL: $pack"; fail=1; }
done
exit $fail
```

Treat **any** non-zero exit as a failure, including 3: exit 3 means the
verifier ran self-referentially — internally consistent, but checked only
against keys the pack itself supplied. In a scheduled job that is a
misconfiguration (the trusted-keys file did not reach the verifier), not a
pass. The codes: 0 proven, 1 invalid, 2 execution error, 3 consistent but
unproven.

Two long-horizon points the quarterly run should carry:

- **Keys**: the `trusted-keys.json` used for re-verification must be the
  out-of-band copy under your control, not one extracted from a pack — and
  it must accumulate, never shrink: a key retired from *new* deployments
  still verifies two years of old seals.
- **TSA material**: archive the TSA's certificate chain alongside the
  packs. The token embedded in each anchor stays bit-identical forever, but
  proving *who* issued it in year two requires the issuer's certificates,
  and the TSA will have rotated by then.

Once a year, run a restore drill: pick a backup set at random, restore it
to a scratch host, and run the verification loop above against what comes
out. The drill's exit code is the only evidence that this runbook works.

## Error messages, meaning, action

| Message contains | Where | Meaning | Action |
|---|---|---|---|
| `broken link` / `expected seq` | gateway or ledger reading the WAL | copy damaged, or file edited | restore previous backup |
| `unreadable record at line` | same | corruption mid-file (a torn *final* line is handled silently) | restore previous backup |
| `not signed by a trusted origin key` (`ForeignRecord`) | gateway resuming | tail not written by a trusted gateway key | human decision: tampering vs missing rotation key in the bundle; never trim |
| `sealed records have disappeared` (`TruncatedLog`) | seal pass | WAL older than store | restore newer WAL; else incident |
| `the WAL was rewritten after sealing` (`DivergedLog`) | seal pass | WAL and store disagree on sealed history | incident; anchors arbitrate |
| `checkpoint store:` (`StoreBroken`) | any ledger command | store copy damaged or edited | restore older store backup |
| `key id … already recorded with different key material` | seal pass | attempted key-id reuse after rotation | use a new `key_id` |
| `not authenticated by any trusted origin key` (`UnauthenticatedRecord`) | seal pass | unsigned/foreign record past the sealed head | incident: someone other than the gateway wrote to the WAL; the authentic prefix is already sealed |

None of these self-heal, and that is the design: the `run` loop exits
non-zero on all of them so the orchestrator alerts, instead of turning an
incident into a heartbeat.
