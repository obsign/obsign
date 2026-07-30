# Real-hardware TPM interop pass

## Where interop evidence stands

The TPM 2.0 marshalling in `tpm-enroll` and the `TPMS_ATTEST` /
`TPMT_PUBLIC` parsing in `audit-core` are hand-rolled. Three independent
lines of evidence say our reading of the TCG format is the consensus one:

1. **swtpm/libtpms** (`tests/swtpm.rs`): a full enrollment ceremony against
   a real TPM 2.0 *implementation*, verified offline, plus tamper cases.
2. **go-tpm cross-validation** (`tests/interop_go_tpm.rs`): every structure
   we marshal decodes and re-encodes byte-identically under Google's
   go-tpm — an independent implementation exercised against real hardware
   fleets — and an enrollment marshalled entirely *by* go-tpm verifies
   under `audit_core::verify_attestation`. This rules out a shared private
   dialect between our encoder and our parser.
3. **Real silicon** — this document. The one thing the first two cannot
   prove: the behavior of an actual discrete/firmware TPM (provisioned
   hierarchy auth, EK certificates in NV, capability pagination, vendor
   quirks). Until this pass has been run on at least one real machine, do
   not claim hardware compatibility.

## What to run

Any Linux machine (laptop is fine) with a TPM 2.0 exposed as
`/dev/tpmrm0`. The enroller talks to the character device directly
(`--tpm /dev/tpmrm0`); no TSS stack is needed. `tpm2-tools` is optional,
only used to dump the EK certificate and inspect capabilities.

```sh
# one command, from the repo root, on the target machine:
scripts/real-tpm-enroll.sh
```

or by hand:

```sh
cargo build --release -p tpm-enroll
sudo target/release/probant-tpm-enroll \
    --tpm /dev/tpmrm0 \
    --key-id lab-hw-1 \
    --binary-hash "$(sha256sum target/release/probant-tpm-enroll | cut -d' ' -f1)" \
    --pcr 16 \
    --out attestation.json
```

The binary self-verifies the attestation with `audit-core` before emitting
anything: **exit 0 with JSON on stdout is the pass**. Keep the emitted
`attestation.json` and the machine/TPM identification (`tpm2_getcap
properties-fixed | grep -A2 MANUFACTURER`) as the interop record — the
attestation also verifies on any other machine, which is the product claim.

## Preconditions and expected failure modes

| Symptom | Cause | Response |
|---|---|---|
| `connecting to the TPM at /dev/tpmrm0: Permission denied` | not in the `tss` group | `sudo`, or `usermod -aG tss $USER` |
| `TPM2_CreatePrimary failed with TPM_RC 0x9a2` (auth fail) | endorsement/owner hierarchy has a password set (Windows dual-boot does this) | run on a machine whose hierarchies carry empty auth; `tpm2_clear` resets them but **wipes all TPM-resident keys — only on a disposable test machine** |
| `TPM_RC 0x902` (object memory) | loaded-session/object slots full | reboot, or `tpm2_flushcontext -t` |
| warning: `this TPM produced a ecdsa-p256 identity key` | expected — real TPMs implement no EdDSA, the enroller falls back to P-256 as designed | keep the attestation; the identity entry waits for P-256 origin-key support |
| `TPM2_Startup failed with TPM_RC 0x100` | never — `TPM_RC_INITIALIZE` is treated as success (the kernel already started the TPM) | file a bug if seen |

EK certificate: real TPMs ship one in NV (`0x01C00002` RSA,
`0x01C0000A` ECC). The enroller carries it opaquely:

```sh
tpm2_getekcertificate -o ek.der   # then add: --ek-cert-file ek.der
```

Without it the attestation is still valid; the report flags the missing
vendor root as `attestation_not_rooted`, as designed.

## PCR note

PCR 16 is the resettable debug PCR — right for an interop pass, wrong for
production (a reset-and-replay is trivial). Production enrollment binds a
launch-wrapper PCR; the interop pass only needs to prove the wire formats
and the device transport against real silicon.

## Recording the result

Append to this file, one line per machine:

| Date | Machine | TPM (manufacturer, fw) | Result |
|---|---|---|---|
| _none yet_ | | | |
