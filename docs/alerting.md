# Alerting on divergence

When the ledger finds that sealed history no longer matches the WAL, it
refuses to seal and exits non-zero. That is deliberate: a rewritten log is an
incident, not a heartbeat, and a service that retried it every thirty seconds
would dress the incident up as one. The conditions in this class never
self-heal:

| Error | Meaning |
|---|---|
| `DivergedLog` | the record at the sealed boundary no longer hashes to the sealed head — the WAL was rewritten after sealing |
| `TruncatedLog` | sealed records have disappeared from the WAL |
| `UnauthenticatedRecord` | a record no trusted origin key vouches for — someone other than the gateway wrote to the WAL |
| `StoreBroken` | the checkpoint store itself is corrupt |
| `KeyConflict` | a key id reused with different key material |

Everything else — an I/O blip, a WAL segment caught mid-write — is retried
inside `run` mode's loop and never exits. So any exit of `run` mode is in the
never-self-heals class by construction.

Exiting is only half the job. The other half is the question this page
answers: **who is told?** Not by the ledger itself — it makes no network
calls, ever, for the same reason RFC 3161 anchoring works by file exchange:
the deployments this product targets are air-gapped first, and a webhook that
cannot leave the enclave is an alert nobody receives. Telling someone is the
supervisor's job, and on the target deployments the supervisor is systemd.

## The pattern: `OnFailure=`, not a webhook

Two units. The ledger service declares what happens when it fails; a separate
alert unit does the telling, through channels that exist inside the enclave.

`obsign-ledger.service` (daemon mode):

```ini
[Unit]
Description=Obsign ledger — seals the gateway audit log
OnFailure=obsign-alert@%n.service

[Service]
Type=exec
User=obsign-ledger
ExecStart=/usr/local/bin/obsign-ledger run \
    --wal /var/lib/obsign/wal --chain-id prod \
    --store /var/lib/obsign/ledger \
    --hsm-module /usr/lib/pkcs11/vendor.so \
    --hsm-key-label seal-prod \
    --hsm-pin-file /etc/obsign/hsm-pin \
    --key-id seal-prod \
    --deployment-bundle /etc/obsign/deployment-bundle.json \
    --trusted-keys /etc/obsign/ops-keys.json
# No Restart=. Transient failures are retried inside the loop and never
# exit; whatever does exit never self-heals. Restart=on-failure would
# re-detect the same divergence at every start — the heartbeat the exit
# code exists to avoid — and OnFailure= would only fire once the restart
# counter gave up, minutes after the incident.
Restart=no

[Install]
WantedBy=multi-user.target
```

`obsign-alert@.service` — a template unit, instantiated with the name of the
failing unit (`%n` above), so one alert path serves every Obsign service on
the host:

```ini
[Unit]
Description=Audit incident alert for %i

[Service]
Type=oneshot
ExecStart=/usr/local/bin/obsign-raise-alert %i
```

And `obsign-raise-alert`, the site-specific part. Everything in it is local
or stays on the management network — no HTTP, no cloud endpoint. The journal
entry is the minimum; keep whichever other channels the site already
monitors:

```sh
#!/bin/sh
unit="$1"

# 1. A critical journal entry — the SIEM collector that already reads
#    this host's journal picks it up without any new plumbing.
echo "AUDIT INCIDENT: $unit failed — sealed history no longer matches \
the WAL. journalctl -u $unit for the refusal." | systemd-cat -t obsign -p crit

# 2. Everyone logged in on the host, immediately.
echo "AUDIT INCIDENT: $unit failed — see journalctl -u $unit" | wall

# 3. Local mail through the site's internal relay, with the evidence
#    attached: the ledger's stderr says exactly what diverged and where.
{ printf 'Subject: [obsign] AUDIT INCIDENT on %s: %s\n\n' "$(hostname)" "$unit"
  journalctl -u "$unit" -n 50 --no-pager
} | sendmail ops@site.internal

# 4. If the site runs an NMS on the management network, an SNMP trap:
# snmptrap -v2c -c "$COMMUNITY" nms.internal '' ...
```

The ledger's refusal message — which sequence number diverged, whether an
authentic prefix was sealed — is on stderr, hence in the journal of the
failed unit. The alert only has to point at it.

## Cron-style deployments: `seal` + a timer

One-pass `seal` is the cron- and air-gap-friendly mode, and the same pattern
applies to the oneshot unit — with one addition. A timer keeps firing after a
failure, each pass re-detects the same divergence, and each detection
re-alerts: the heartbeat again, just slower. The latch below stops sealing
after the first incident until an operator explicitly clears it — which is
the right posture anyway, since divergence never self-heals and the halted
state is exactly what the investigation wants to look at.

```ini
# obsign-seal.service
[Unit]
Description=Obsign sealing pass
OnFailure=obsign-alert@%n.service
# The latch: an unmet condition is a skip, not a failure, so once the
# flag exists the timer stops producing alerts (and seals) until the
# operator removes the file. Clearing it is a deliberate act that
# concludes an investigation, not a retry.
ConditionPathExists=!/var/lib/obsign/ledger/INCIDENT

[Service]
Type=oneshot
User=obsign-ledger
ExecStart=/usr/local/bin/obsign-ledger seal \
    --wal /var/lib/obsign/wal --chain-id prod \
    --store /var/lib/obsign/ledger \
    --hsm-module /usr/lib/pkcs11/vendor.so \
    --hsm-key-label seal-prod \
    --hsm-pin-file /etc/obsign/hsm-pin \
    --key-id seal-prod \
    --deployment-bundle /etc/obsign/deployment-bundle.json \
    --trusted-keys /etc/obsign/ops-keys.json
ExecStopPost=/bin/sh -c '[ "$$SERVICE_RESULT" = success ] || \
    touch /var/lib/obsign/ledger/INCIDENT'

# obsign-seal.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

One honest caveat: unlike `run` mode, a one-shot `seal` cannot retry
internally, so a transient failure (the HSM briefly unreachable, an I/O
error) also exits non-zero and also raises the alert. The journal tail in the
alert says which class you are in. If that distinction matters at your scale,
run the daemon; its exits are all incident-class.

## Containerized ledgers

The distroless ledger image has no systemd inside — keep the supervisor
outside. Run the container from a systemd unit
(`ExecStart=docker run --rm ...` with the mounts from
[deploy-docker.md](deploy-docker.md)): the container's exit code becomes the
unit's, and `OnFailure=` applies unchanged. A compose `restart: always` (or
`on-failure`) policy on the ledger is the same mistake as
`Restart=on-failure` — it converts the incident back into a heartbeat, with
nobody told.

## When it fires

Treat it as an incident, not an outage. The WAL and the ledger store are the
evidence; do not "fix" them to get sealing green again. `obsign-ledger
export` still works and writes the pack even when it fails verification —
a failing pack on disk is exactly what the investigation wants. The last
sealed checkpoint (and its RFC 3161 anchor, if any) bounds when the rewrite
happened: everything up to `to_seq` is still provable, and that boundary is
the starting point of the timeline.
