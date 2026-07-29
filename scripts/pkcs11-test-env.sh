#!/bin/sh
# Provisions a throwaway SoftHSM token for the PKCS#11 integration tests and
# exports the variables they read. Source it, do not run it:
#
#   source scripts/pkcs11-test-env.sh
#   cargo test -p ledger --test pkcs11_softhsm
#
# Needs softhsm2-util and pkcs11-tool (brew install softhsm opensc /
# apt install softhsm2 opensc). Everything lands in a fresh temp directory;
# nothing touches the machine's real SoftHSM state.

set -u

_probant_die() { echo "pkcs11-test-env: $1" >&2; return 1; }

command -v softhsm2-util >/dev/null 2>&1 || _probant_die "softhsm2-util not found" || return 1
command -v pkcs11-tool >/dev/null 2>&1 || _probant_die "pkcs11-tool not found" || return 1

# The module lives next to the softhsm2-util binary's prefix.
_probant_prefix=$(dirname "$(dirname "$(command -v softhsm2-util)")")
_probant_module=$(find -L "$_probant_prefix/lib" -name 'libsofthsm2.so' 2>/dev/null | head -1)
[ -n "$_probant_module" ] || _probant_die "libsofthsm2.so not found under $_probant_prefix/lib" || return 1

_probant_dir=$(mktemp -d "${TMPDIR:-/tmp}/probant-softhsm.XXXXXX")
mkdir -p "$_probant_dir/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
    "$_probant_dir" > "$_probant_dir/softhsm2.conf"

export SOFTHSM2_CONF="$_probant_dir/softhsm2.conf"
export PROBANT_TEST_PKCS11_MODULE="$_probant_module"
export PROBANT_TEST_PKCS11_PIN="123456"
export PROBANT_TEST_PKCS11_KEY_LABEL="seal-test"
export PROBANT_TEST_PKCS11_P256_LABEL="seal-test-p256"

softhsm2-util --init-token --free --label probant-test \
    --so-pin 12345678 --pin "$PROBANT_TEST_PKCS11_PIN" >/dev/null \
    || _probant_die "token init failed" || return 1

# The Ed25519 sealing pair, and a P-256 pair the tests use to prove a
# wrong-type key is refused by type rather than by signature mismatch.
pkcs11-tool --module "$PROBANT_TEST_PKCS11_MODULE" --login \
    --pin "$PROBANT_TEST_PKCS11_PIN" --keypairgen \
    --key-type EC:edwards25519 --label "$PROBANT_TEST_PKCS11_KEY_LABEL" >/dev/null 2>&1 \
    || _probant_die "Ed25519 keygen failed (SoftHSM >= 2.6 required)" || return 1
pkcs11-tool --module "$PROBANT_TEST_PKCS11_MODULE" --login \
    --pin "$PROBANT_TEST_PKCS11_PIN" --keypairgen \
    --key-type EC:prime256v1 --label "$PROBANT_TEST_PKCS11_P256_LABEL" >/dev/null 2>&1 \
    || _probant_die "P-256 keygen failed" || return 1

echo "pkcs11-test-env: token ready — SOFTHSM2_CONF=$SOFTHSM2_CONF" >&2
echo "pkcs11-test-env: module $PROBANT_TEST_PKCS11_MODULE" >&2
