#!/bin/sh
# Generates the demo configuration into the shared volume: signed policy
# bundle, signed identity bundle, a demo token, and a development-grade
# sealing seed. One-shot; the gateway waits for it to finish.
set -eu

DIR="${1:-/demo}"
mkdir -p "$DIR"

mkbundle "$DIR"
mint_demo_token "$DIR" 86400 user
openssl rand -hex 32 > "$DIR/seal-seed.hex"

echo "[init] demo configuration ready in $DIR"
