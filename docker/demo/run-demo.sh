#!/bin/sh
# The README demo, in containers: drive the gateway over Streamable HTTP,
# then seal the session's WAL with the ledger and verify the evidence pack
# offline. Exits with `obsign verify`'s status — 0 means the pack proved
# intact against keys obtained outside the pack.
set -eu

GW="${GATEWAY_URL:-http://gateway:8080/mcp}"
DEMO="${DEMO_DIR:-/demo}"
WAL="${WAL_DIR:-/wal}"
STORE="${STORE_DIR:-/store}"

TOKEN="$(cat "$DEMO/token.jwt")"
AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"

# The gateway may still be binding when we start.
for _ in $(seq 1 30); do
    curl -s -o /dev/null "$GW" -X POST -H "$AUTH" -H "$CT" -d '{}' && break
    sleep 1
done

echo "[demo] initialize"
SID=$(curl -si -X POST "$GW" -H "$AUTH" -H "$CT" -d '{
        "jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-03-26","capabilities":{},
                  "clientInfo":{"name":"docker-demo","version":"0"}}}' \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
test -n "$SID" || { echo "[demo] no session id — is the gateway up?"; exit 2; }
# One HTTP session = one audit chain, named <chain-id-prefix>-<session-id>.
CHAIN="${CHAIN_PREFIX:-default}-$SID"
echo "[demo] session: $SID (audit chain: $CHAIN)"

post() {
    curl -s -X POST "$GW" -H "$AUTH" -H "$CT" -H "Mcp-Session-Id: $SID" -d "$1"
    echo
}

echo "[demo] tools/list — hidden tools are filtered out:"
post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

echo "[demo] destructive call — refused in the server's place:"
post '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"delete_production_db","arguments":{"database":"customers"}}}'

echo "[demo] scoped call — allowed:"
post '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"ticket_update","arguments":{"ticket":"T-8821"}}}'

echo "[demo] closing the session (completes the log)"
curl -s -X DELETE "$GW" -H "$AUTH" -H "Mcp-Session-Id: $SID" > /dev/null

echo "[demo] sealing — the key never enters the gateway container"
obsign-ledger seal \
    --wal "$WAL" --chain-id "$CHAIN" --store "$STORE" \
    --key "$DEMO/seal-seed.hex" --key-id seal-demo

obsign-ledger export \
    --wal "$WAL" --chain-id "$CHAIN" --store "$STORE" \
    --out "$DEMO/evidence-$SID.json"

echo "[demo] offline verification against keys from outside the pack."
echo "[demo] (the demo gateway runs without an origin key, so verification"
echo "[demo]  needs the explicit legacy opt-out; production gateways sign"
echo "[demo]  every record — see the origin-authentication section of the README)"
obsign verify "$DEMO/evidence-$SID.json" \
    --trusted-keys "$STORE/keys.json" \
    --allow-unsigned-legacy-chains
