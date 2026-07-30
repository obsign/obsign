#!/usr/bin/env bash
# Real-hardware TPM interop pass — see docs/real-tpm-interop.md.
#
# Run from the repo root on a Linux machine with a TPM 2.0. Performs the
# preflight checks, then a full enrollment against /dev/tpmrm0. The enroller
# self-verifies with audit-core before emitting: exit 0 is the pass.

set -euo pipefail

DEVICE="${TPM_DEVICE:-/dev/tpmrm0}"
OUT="${1:-attestation-real-hw.json}"

say() { printf '\033[1m[real-tpm]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[real-tpm]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "this pass needs Linux with a TPM character device (found $(uname -s))"
[ -e "$DEVICE" ] || die "$DEVICE not found — no TPM 2.0 exposed (check BIOS/UEFI, or fTPM enabled?)"
[ -r "$DEVICE" ] && [ -w "$DEVICE" ] || die "$DEVICE not readable/writable — join the tss group or rerun under sudo"

say "TPM device: $DEVICE"
if command -v tpm2_getcap >/dev/null 2>&1; then
    say "TPM manufacturer/firmware (for the interop record):"
    tpm2_getcap properties-fixed 2>/dev/null | grep -A2 -E 'MANUFACTURER|FIRMWARE_VERSION_1' || true
else
    say "tpm2-tools not installed — fine, only used for the EK certificate and the interop record"
fi

say "building the enroller"
cargo build --release -p tpm-enroll

EK_ARGS=()
if command -v tpm2_getekcertificate >/dev/null 2>&1; then
    EK_DER="$(mktemp)"
    if tpm2_getekcertificate -o "$EK_DER" >/dev/null 2>&1 && [ -s "$EK_DER" ]; then
        say "EK certificate dumped ($(wc -c <"$EK_DER") bytes DER) — carried opaquely"
        EK_ARGS=(--ek-cert-file "$EK_DER")
    else
        say "no EK certificate readable — attestation will carry none (flagged as attestation_not_rooted)"
    fi
fi

BIN=target/release/probant-tpm-enroll
HASH="$(sha256sum "$BIN" | cut -d' ' -f1)"

say "enrolling: PCR 16, binary hash $HASH"
"$BIN" \
    --tpm "$DEVICE" \
    --key-id "real-hw-$(hostname -s)" \
    --binary-hash "$HASH" \
    --pcr 16 \
    "${EK_ARGS[@]}" \
    --out "$OUT"

say "PASS — attestation self-verified by audit-core, written to $OUT"
say "record the machine + TPM in docs/real-tpm-interop.md"
