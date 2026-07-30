# syntax=docker/dockerfile:1
#
# One build stage, several runtime targets — pick with `--target`:
#
#   proxy     ghcr.io/…/probant-proxy     the gateway (extensible base image)
#   ledger    ghcr.io/…/probant-ledger    sealing, anchoring, evidence export
#   control   ghcr.io/…/probant-control   compile/publish/export/console
#   verifier  ghcr.io/…/probant           offline verifier (convenience only:
#                                         the auditor's canonical channel is
#                                         building it from source)
#   demo      local only                  every binary + the demo generators
#
# Runtime images are distroless (glibc, no shell, nonroot): the dependency
# list is part of the product, and an image an auditor can enumerate in one
# `docker sbom` is the same argument as the readable Cargo.lock. glibc rather
# than a static musl build because PKCS#11 modules are loaded with dlopen —
# a fully static binary cannot host a vendor HSM library.

FROM rust:1.97.1-slim-bookworm AS build
WORKDIR /src
COPY . .
# --locked: the lockfile is audited content; a build that would update it
# must fail here, not drift silently. --bins AND --examples: naming only
# --examples would narrow cargo's target selection to examples alone.
RUN cargo build --release --workspace --bins --examples --locked

# ---------------------------------------------------------------------------
# Gateway. Deliberately does not contain an MCP server: extend this image and
# add yours (see docs/deploy-docker.md), or run --http and point it at one.
FROM gcr.io/distroless/cc-debian12:nonroot AS proxy
COPY --from=build /src/target/release/probant-proxy /usr/local/bin/probant-proxy
# The WAL must land on a volume that honours fsync — see the deploy doc.
VOLUME ["/var/lib/probant/wal"]
ENTRYPOINT ["/usr/local/bin/probant-proxy"]

# ---------------------------------------------------------------------------
# Ledger. Runs on another host or at least another container than the
# gateway: the sealing key and the WAL writer must never cohabit.
FROM gcr.io/distroless/cc-debian12:nonroot AS ledger
COPY --from=build /src/target/release/probant-ledger /usr/local/bin/probant-ledger
ENTRYPOINT ["/usr/local/bin/probant-ledger"]

# ---------------------------------------------------------------------------
# Control plane: compile, publish, export, console. The console has no
# authentication — never publish its port beyond loopback or a private
# network you trust (auth is the commercial layer).
FROM gcr.io/distroless/cc-debian12:nonroot AS control
COPY --from=build /src/target/release/probant-control /usr/local/bin/probant-control
ENTRYPOINT ["/usr/local/bin/probant-control"]

# ---------------------------------------------------------------------------
# Verifier. A convenience for pipelines; the auditor-facing story remains
# `cargo build -p probant` from the published source.
FROM gcr.io/distroless/cc-debian12:nonroot AS verifier
COPY --from=build /src/target/release/probant /usr/local/bin/probant
ENTRYPOINT ["/usr/local/bin/probant"]

# ---------------------------------------------------------------------------
# Demo: everything in one image, with a shell — for docker-compose only,
# never published. The token minter is an example binary precisely so it
# cannot end up in a shipped artifact; the same rule applies to this image.
FROM debian:bookworm-slim AS demo
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/probant-proxy \
                  /src/target/release/probant-ledger \
                  /src/target/release/probant-control \
                  /src/target/release/probant \
                  /src/target/release/mock-mcp-server \
                  /usr/local/bin/
COPY --from=build /src/target/release/examples/mkbundle \
                  /src/target/release/examples/mint_demo_token \
                  /src/target/release/examples/gen_sample \
                  /usr/local/bin/
COPY docker/demo/init.sh docker/demo/run-demo.sh /usr/local/bin/
