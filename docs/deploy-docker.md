# Deploying with Docker

Day-2 operations — backing up the WAL and the store, restoring after a
loss, long-term retention: [runbook-backup-restore.md](runbook-backup-restore.md).

Four images, one binary each, distroless (no shell, nonroot, glibc):

| Image | Binary | Role |
|---|---|---|
| `ghcr.io/obsign/obsign-proxy` | `obsign-proxy` | the gateway |
| `ghcr.io/obsign/obsign-ledger` | `obsign-ledger` | sealing, anchoring, evidence export |
| `ghcr.io/obsign/obsign-control` | `obsign-control` | compile, publish, export, console |
| `ghcr.io/obsign/obsign` | `obsign` | offline verifier (convenience — see below) |

Built by `.github/workflows/docker.yml` on every `v*` tag: multi-arch
(amd64/arm64), signed with cosign (keyless), tagged with the semver and the
exact source sha. Verify before running:

```bash
cosign verify ghcr.io/obsign/obsign-proxy:1.0.0 \
    --certificate-identity-regexp 'github.com/obsign/obsign' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

glibc rather than a static musl build, deliberately: PKCS#11 modules are
loaded with `dlopen`, and a fully static binary cannot host a vendor HSM
library.

## The gateway image is a base image

`obsign-proxy` wraps an MCP server it spawns as a child process, so the
image ships without one. Extend it:

```dockerfile
FROM ghcr.io/obsign/obsign-proxy:1.0.0
COPY --chown=nonroot:nonroot my-mcp-server /usr/local/bin/my-mcp-server
# Config (signed bundles) is mounted, not baked: whoever can write the
# identity bundle can mint identities.
```

```bash
docker run -d \
  -v ./config:/etc/obsign:ro \
  -v obsign-wal:/var/lib/obsign/wal \
  -p 127.0.0.1:8080:8080 \
  my-gateway \
  --policy /etc/obsign/policy-bundle.json \
  --trusted-keys /etc/obsign/trusted-keys.json \
  --identity-bundle /etc/obsign/identity-bundle.json \
  --http 0.0.0.0:8080 \
  --wal /var/lib/obsign/wal \
  --env prod \
  -- /usr/local/bin/my-mcp-server
```

## Non-negotiables

**The WAL volume must honour `fsync`.** The gateway's guarantee is
fsync-before-forward; it is only as good as the volume under it. A local
named volume or a directly attached disk qualifies. A network filesystem
that acknowledges writes before they are durable (NFS with `async`, some
overlay drivers) silently voids the guarantee — treat the WAL volume like
you would a database's.

**The ledger runs in a separate container — ideally a separate host.** The
whole point of the split is that whoever compromises the gateway cannot
re-seal history. Same rule in Docker: the gateway container gets the WAL
volume read-write and no key material; the ledger container gets the WAL
read-only and the key (or the HSM), and writes its own store volume.

```bash
docker run --rm \
  -v obsign-wal:/wal:ro \
  -v obsign-store:/store \
  -v ./seal-seed.hex:/run/secrets/seal-seed.hex:ro \
  ghcr.io/obsign/obsign-ledger \
  seal --wal /wal --chain-id <chain> --store /store \
       --key /run/secrets/seal-seed.hex --key-id seal-prod
```

**The console has no authentication.** Publish its port on loopback or a
private network only (auth on the console is the commercial layer). The
compose file in this repo binds it to `127.0.0.1` — keep that property.

**Both runtime users are `nonroot` (uid 65532).** Pre-created host
directories mounted as volumes must be writable by that uid.

## HSM (PKCS#11) and TPM

The vendor's PKCS#11 module is loaded at runtime with `dlopen`: mount the
`.so` (and whatever it needs — sockets, config, its own libraries) into the
ledger container and pass `--hsm-module`:

```bash
docker run --rm \
  -v obsign-wal:/wal:ro -v obsign-store:/store \
  -v /usr/lib/softhsm:/usr/lib/softhsm:ro \
  -v softhsm-tokens:/var/lib/softhsm/tokens \
  -v ./hsm-pin:/run/secrets/hsm-pin:ro \
  ghcr.io/obsign/obsign-ledger \
  seal --wal /wal --chain-id <chain> --store /store \
       --hsm-module /usr/lib/softhsm/libsofthsm2.so \
       --hsm-key-label seal-prod --hsm-pin-file /run/secrets/hsm-pin \
       --key-id seal-prod
```

TPM enrollment (`obsign-tpm-enroll`) needs the kernel resource manager:
`--device /dev/tpmrm0`. It is an operator ceremony, not a service — run it
from the source tree on the enrolling host (`scripts/real-tpm-enroll.sh`),
not from a long-lived container.

## Air-gapped delivery

The registry is a convenience, not a dependency. For an air-gapped site:

```bash
# Connected side: pull by digest, save, hash.
docker pull ghcr.io/obsign/obsign-proxy@sha256:<digest>
docker save ghcr.io/obsign/obsign-proxy@sha256:<digest> -o obsign-proxy.tar
sha256sum obsign-proxy.tar > obsign-proxy.tar.sha256

# Air-gapped side: verify the hash out of band, then load.
sha256sum -c obsign-proxy.tar.sha256
docker load -i obsign-proxy.tar
```

The digest travels out of band (it is in the signed release notes); the
cosign verification happens on the connected side, before the export.

## The verifier image is a convenience

`obsign verify`'s argument is that the auditor builds it themselves, from
source, and runs it with no network. The image exists for CI pipelines
(`docker run ghcr.io/obsign/obsign verify pack.json --trusted-keys keys.json`
gates on the exit code); it is not the channel to hand an auditor.

## Local demo

```bash
docker compose up -d gateway console
docker compose run --rm demo    # drives the gateway, seals, verifies: exit 0
```

The demo image (shell, token minter, file seed) is compose-only and never
published — the means to forge tokens has no business in a shipped artifact.
