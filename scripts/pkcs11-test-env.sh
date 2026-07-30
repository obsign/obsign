#!/bin/sh
# Provisions a throwaway SoftHSM token for the PKCS#11 integration tests and
# exports the variables they read. Source it, do not run it:
#
#   source scripts/pkcs11-test-env.sh
#   cargo test -p obsign-ledger --test pkcs11_softhsm
#
# Needs softhsm2-util and pkcs11-tool (brew install softhsm opensc /
# apt install softhsm2 opensc). Everything lands in a fresh temp directory;
# nothing touches the machine's real SoftHSM state.

set -u

_obsign_die() { echo "pkcs11-test-env: $1" >&2; return 1; }

command -v softhsm2-util >/dev/null 2>&1 || _obsign_die "softhsm2-util not found" || return 1
command -v pkcs11-tool >/dev/null 2>&1 || _obsign_die "pkcs11-tool not found" || return 1

# The module lives next to the softhsm2-util binary's prefix.
_obsign_prefix=$(dirname "$(dirname "$(command -v softhsm2-util)")")
_obsign_module=$(find -L "$_obsign_prefix/lib" -name 'libsofthsm2.so' 2>/dev/null | head -1)
[ -n "$_obsign_module" ] || _obsign_die "libsofthsm2.so not found under $_obsign_prefix/lib" || return 1

_obsign_dir=$(mktemp -d "${TMPDIR:-/tmp}/obsign-softhsm.XXXXXX")
mkdir -p "$_obsign_dir/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
    "$_obsign_dir" > "$_obsign_dir/softhsm2.conf"

export SOFTHSM2_CONF="$_obsign_dir/softhsm2.conf"
export OBSIGN_TEST_PKCS11_MODULE="$_obsign_module"
export OBSIGN_TEST_PKCS11_PIN="123456"
export OBSIGN_TEST_PKCS11_KEY_LABEL="seal-test"
export OBSIGN_TEST_PKCS11_P256_LABEL="seal-test-p256"

softhsm2-util --init-token --free --label obsign-test \
    --so-pin 12345678 --pin "$OBSIGN_TEST_PKCS11_PIN" >/dev/null \
    || _obsign_die "token init failed" || return 1

# The Ed25519 sealing pair, and a P-256 pair the tests use to prove a
# wrong-type key is refused by type rather than by signature mismatch.
pkcs11-tool --module "$OBSIGN_TEST_PKCS11_MODULE" --login \
    --pin "$OBSIGN_TEST_PKCS11_PIN" --keypairgen \
    --key-type EC:edwards25519 --label "$OBSIGN_TEST_PKCS11_KEY_LABEL" >/dev/null 2>&1 \
    || _obsign_die "Ed25519 keygen failed (SoftHSM >= 2.6 required)" || return 1
pkcs11-tool --module "$OBSIGN_TEST_PKCS11_MODULE" --login \
    --pin "$OBSIGN_TEST_PKCS11_PIN" --keypairgen \
    --key-type EC:prime256v1 --label "$OBSIGN_TEST_PKCS11_P256_LABEL" >/dev/null 2>&1 \
    || _obsign_die "P-256 keygen failed" || return 1

echo "pkcs11-test-env: token ready — SOFTHSM2_CONF=$SOFTHSM2_CONF" >&2
echo "pkcs11-test-env: module $OBSIGN_TEST_PKCS11_MODULE" >&2
