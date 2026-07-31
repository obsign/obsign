#!/bin/sh
# obsign-slack-alert — post an audit-incident alert to Slack, best-effort.
#
# Called with the name of the failed unit (systemd `%i`), it builds a message
# from that unit's journal tail and posts it to a Slack Incoming Webhook.
#
# Air-gap posture. The whole point of the alerting design is that the ledger
# makes no network call — the network call lives out here, in the supervisor.
# In a real enclave Slack is reachable only through the site's approved
# egress proxy (or not at all), so this script is:
#
#   * best-effort — it never fails the alert. It runs alongside the local
#     channels in obsign-raise-alert (journal, wall, mail), which are the
#     guarantee; Slack is a convenience on top. Unreachable Slack must not
#     swallow the incident.
#   * bounded — a hung proxy cannot wedge the oneshot alert unit
#     (--connect-timeout / --max-time).
#   * proxy-aware — it honours https_proxy / HTTPS_PROXY, the enclave's
#     vetted egress path. No proxy set and no direct route → it degrades to a
#     journal warning and exits 0.
#   * secret-file based — the webhook URL grants posting to a channel; it is
#     read from a root-owned file, never baked into the unit or an argument.
#
# Configuration (all via environment, e.g. a systemd EnvironmentFile):
#   SLACK_WEBHOOK_URL   the webhook, inline. Takes precedence.
#   SLACK_WEBHOOK_FILE  path to a file holding the webhook (default
#                       /etc/obsign/slack-webhook). Used when the URL is not
#                       set inline.
#   HTTPS_PROXY         the enclave egress proxy, if any (curl honours it).
#   OBSIGN_ALERT_DRYRUN when set, print the target and payload instead of
#                       posting — for validating a deployment offline.
#
# Exit status is always 0: an alert channel must not become the incident.

set -u

unit="${1:-unknown.unit}"
host="$(hostname 2>/dev/null || echo unknown-host)"

log() { echo "obsign-slack-alert: $1" | systemd-cat -t obsign -p "${2:-info}" 2>/dev/null \
        || echo "obsign-slack-alert: $1" >&2; }

webhook="${SLACK_WEBHOOK_URL:-}"
if [ -z "$webhook" ]; then
    webhook_file="${SLACK_WEBHOOK_FILE:-/etc/obsign/slack-webhook}"
    if [ -r "$webhook_file" ]; then
        webhook="$(cat "$webhook_file")"
    fi
fi
if [ -z "$webhook" ]; then
    log "no webhook configured (SLACK_WEBHOOK_URL / SLACK_WEBHOOK_FILE) — \
skipping Slack, local channels still fired" warning
    exit 0
fi

# The journal tail is the evidence: the ledger's refusal names the diverged
# sequence and whether an authentic prefix was sealed.
tail_text="$(journalctl -u "$unit" -n 20 --no-pager -o cat 2>/dev/null \
             || echo '(journal unavailable)')"

# Escape a text stream into a JSON string body (no surrounding quotes),
# joining lines with \n. Portable awk only — no python/jq dependency on the
# host.
json_body() {
    awk '
        BEGIN { ORS = "" }
        {
            line = $0
            gsub(/\\/, "\\\\", line)
            gsub(/"/, "\\\"", line)
            gsub(/\t/, "\\t", line)
            gsub(/\r/, "", line)
            gsub(/[[:cntrl:]]/, " ", line)
            if (NR > 1) printf "\\n"
            printf "%s", line
        }
    '
}

header=":rotating_light: *Obsign audit incident* on \`$host\`
unit \`$unit\` failed — sealed history no longer matches the WAL.
This never self-heals: treat it as an incident, not an outage. The WAL and
ledger store are the evidence; do not repair them. See \`journalctl -u $unit\`."

payload="$(
    printf '{"text":"'
    { printf '%s\n' "$header"
      printf '```\n%s\n```' "$tail_text"
    } | json_body
    printf '"}'
)"

if [ -n "${OBSIGN_ALERT_DRYRUN:-}" ]; then
    proxy_note="${HTTPS_PROXY:-${https_proxy:-<direct>}}"
    # printf, not echo: the payload holds literal \n escapes, and some echo
    # implementations expand them — which would misreport a valid payload as
    # broken to an operator validating a deployment.
    printf '[dry-run] POST %s (via proxy: %s)\n' "$webhook" "$proxy_note"
    printf '[dry-run] payload:\n%s\n' "$payload"
    exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
    log "curl not found — cannot reach Slack; local channels still fired" warning
    exit 0
fi

# Bounded and quiet on success; one retry for a flaky proxy, nothing more.
# curl's stderr is captured into a variable — never a temp file, whose
# directory a hardened oneshot unit (WorkingDirectory=/, unprivileged user)
# may not be able to write.
if err="$(curl --silent --show-error --fail \
        --connect-timeout 5 --max-time 15 --retry 1 \
        -H 'Content-Type: application/json' \
        -X POST --data "$payload" \
        "$webhook" 2>&1 >/dev/null)"; then
    log "posted incident for $unit to Slack"
else
    log "Slack post failed ($err) — enclave egress? local channels still fired" warning
fi
exit 0
