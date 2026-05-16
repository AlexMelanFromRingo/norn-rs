# syntax=docker/dockerfile:1.7

# ── Stage 1: build ────────────────────────────────────────────────────────
# Pin to a specific rustlang/rust:slim digest at release time for
# reproducibility. We bump it during the release process.
FROM rust:1.85-slim-bookworm AS build

# Build deps for ed25519/blake2 and TUN (libcap optional; nornd only needs
# CAP_NET_ADMIN at runtime, not build time).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Pre-build dependencies in a separate layer so source-only changes don't
# bust the dependency cache. We copy a stub main.rs so cargo resolves and
# compiles every crate.io dep first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
 && echo "fn main(){}" > src/bin/nornd.rs \
 && echo "fn main(){}" > src/bin/nornctl.rs \
 && echo "" > src/lib.rs \
 && cargo build --release --bin nornd --bin nornctl --features tun-support \
 && rm -rf src

# Now build the real source.
COPY . .
RUN touch src/lib.rs src/bin/nornd.rs src/bin/nornctl.rs \
 && cargo build --release --bin nornd --bin nornctl --features tun-support \
 && strip target/release/nornd target/release/nornctl

# ── Stage 2: runtime (distroless) ─────────────────────────────────────────
# Distroless has only ca-certs + glibc, no shell/package manager.
# Smaller attack surface than even alpine. About 25 MiB compressed.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Copy binaries.
COPY --from=build /src/target/release/nornd   /usr/local/bin/nornd
COPY --from=build /src/target/release/nornctl /usr/local/bin/nornctl

# Default config path. Mount a host config to /etc/norn/norn.toml.
ENV NORND_CONFIG=/etc/norn/norn.toml

# TCP listen + multicast discovery + metrics.
EXPOSE 9001/tcp
EXPOSE 9001/udp
EXPOSE 9090/tcp

# Healthcheck: the metrics endpoint must respond. Operators can enable
# this by also setting metrics_addr = "0.0.0.0:9090" in norn.toml.
# (HEALTHCHECK requires shell — distroless has none; the orchestrator
# is expected to probe externally via the metrics port.)

# nornd needs CAP_NET_ADMIN for TUN; distroless `nonroot` user uid 65532
# can hold it via `--cap-add NET_ADMIN` on `docker run`.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/nornd"]
CMD ["-c", "/etc/norn/norn.toml"]
