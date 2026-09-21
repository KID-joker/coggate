FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --manifest-path playground/Cargo.toml

FROM debian:bookworm-slim AS web
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin arena
COPY --from=build /src/playground/target/release/coggate-playground /usr/local/bin/coggate-playground
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/coggate-playground"]

FROM debian:bookworm-slim AS broker
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/playground/target/release/arena-runner /usr/local/bin/arena-runner
ENTRYPOINT ["/usr/local/bin/arena-runner"]
