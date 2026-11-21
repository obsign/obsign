# Real-hardware TPM interop pass

## Where interop evidence stands

The TPM 2.0 marshalling in `obsign-tpm-enroll` and the `TPMS_ATTEST` /
`TPMT_PUBLIC` parsing in `obsign-audit-core` are hand-rolled. Three independent
lines of evidence say our reading of the TCG format is the consensus one:

1. **swtpm/libtpms** (`tests/swtpm.rs`): the full attestation-v4 exchange
   ([attestation-v4.md](design/attestation-v4.md)) against a real TPM 2.0
   *implementation*: `TPM2_ActivateCredential` of a credential made in
   software, the PCR-policy identity key, qualified certify and quote,
   verified offline. Plus the negatives on real TPM behavior: an AK from
   another TPM cannot activate, replayed or unqualified statements and an
   identity key without the policy are refused, and the identity key stops
   signing once the PCR moves.
2. **go-tpm cross-validation** (`tests/interop_go_tpm.rs`): every structure
   we marshal (EK, AK and identity public areas, qualified statements)
   decodes and re-encodes byte-identically under Google's go-tpm (an
   independent implementation exercised against real hardware fleets); an
   enrollment marshalled entirely *by* go-tpm verifies under
   `obsign_audit_core::verify_attestation`; and a credential made by go-tpm's
   `credactivation` activates through our TPM path. This rules out a shared
   private dialect between our encoder and our parser, and between our
   MakeCredential and the TPM's ActivateCredential.
3. **Real silicon**: this document. The one thing the first two cannot
   prove: the behavior of an actual discrete/firmware TPM (provisioned
   hierarchy auth, EK certificates in NV, capability pagination, vendor
   quirks). Until this pass has been run on at least one real machine, do
   not claim hardware compatibility.

## What to run

Any Linux machine (laptop is fine) with a TPM 2.0 exposed as
`/dev/tpmrm0`. The enroller talks to the character device directly
(`--tpm /dev/tpmrm0`); no TSS stack is needed. `tpm2-tools` is optional,
only used to dump the EK certificate and inspect capabilities. Run it right
after a boot: it extends PCR 16 once, and `finish` checks the PCR holds
exactly that one extension.

```sh
# one command, from the repo root, on the target machine:
scripts/real-tpm-enroll.sh
```

or by hand:

```sh
cargo build --release -p obsign-tpm-enroll
E=target/release/obsign-tpm-enroll
H="$(sha256sum "$E" | cut -d' ' -f1)"
sudo $E measure   --tpm /dev/tpmrm0 --pcr 16 --binary-hash "$H"
sudo $E request   --tpm /dev/tpmrm0 --ek-cert-file ek.der --out request.json
     $E challenge --request request.json --out challenge.json --state ops-state.json
sudo $E respond   --tpm /dev/tpmrm0 --challenge challenge.json \
                  --key-id lab-hw-1 --pcr 16 --out response.json
     $E finish    --state ops-state.json --response response.json \
                  --binary-hash "$H" --out attestation.json
```

In production `challenge` and `finish` run on the ops side, and
`ops-state.json` (which holds the credential) never leaves it; for an
interop pass one machine plays both. `finish` runs the offline verifier on
the completed attestation before writing it: **exit 0 with JSON on stdout
is the pass**. Keep the emitted `attestation.json` and the machine/TPM
identification (`tpm2_getcap properties-fixed | grep -A2 MANUFACTURER`) as
the interop record. That attestation also verifies on any other machine,
which is the product claim. `sudo $E sign --tpm /dev/tpmrm0 --attestation
attestation.json --message-file <file>` then exercises the PCR-gated
signing path.

## Preconditions and expected failure modes

| Symptom | Cause | Response |
|---|---|---|
| `connecting to the TPM at /dev/tpmrm0: Permission denied` | not in the `tss` group | `sudo`, or `usermod -aG tss $USER` |
| `TPM2_CreatePrimary failed with TPM_RC 0x9a2` (auth fail) | endorsement/owner hierarchy has a password set (Windows dual-boot does this) | run on a machine whose hierarchies carry empty auth; `tpm2_clear` resets them but **wipes all TPM-resident keys, so only on a disposable test machine** |
| `TPM_RC 0x902` (object memory) | loaded-session/object slots full | reboot, or `tpm2_flushcontext -t` |
| warning: `this TPM produced a ecdsa-p256 identity key` | expected — real TPMs implement no EdDSA, the enroller falls back to P-256 as designed | keep the attestation; the identity entry waits for P-256 origin-key support |
| `TPM2_Startup failed with TPM_RC 0x100` | never — `TPM_RC_INITIALIZE` is treated as success (the kernel already started the TPM) | file a bug if seen |
| `TPM2_ActivateCredential failed with TPM_RC 0x1df` (integrity) | the challenge was made for another AK than this TPM's | redo `request` and `challenge` against this TPM |
| `TPM2_ActivateCredential failed with TPM_RC 0x2c4` (value) | the credential was encrypted to another EK | same |
| `refused: the enrolled PCR does not hold exactly one extension…` | PCR 16 was extended before (a previous run, other software) | reboot, then run again |
| `TPM2_Sign failed with TPM_RC 0x99d` (policy fail) | the PCRs no longer hold the enrolled values: the gate working | expected after any further extension |

EK certificate: real TPMs ship one in NV (`0x01C00002` for the RSA EK the
exchange uses). The verifier checks that it certifies the recorded EK; its
chain to the vendor root stays out of band:

```sh
tpm2_getekcertificate -o ek.der   # then add to `request`: --ek-cert-file ek.der
```

Without it the attestation is still valid, but nothing then distinguishes
the TPM from a software one; the report flags the vendor root as
`attestation_not_rooted`, as designed. Some vendors' certificates are not
strict DER; one the parser refuses is worth recording here.

## PCR note

PCR 16 is the resettable debug PCR, right for an interop pass and wrong
for production, where a reset-and-replay is trivial: anyone with access to
the TPM can reset it, extend the expected hash, and use the identity key.
What PCR 16 proves, and what it does not, is spelled out in
[attestation-v4.md §5](design/attestation-v4.md#5-what-is-proven-and-what-is-not).
The interop pass only needs to prove the wire formats, the credential
exchange and the device transport against real silicon.

## Recording the result

Append to this file, one line per machine:

| Date | Machine | TPM (manufacturer, fw) | Result |
|---|---|---|---|
| _none yet_ | | | |
