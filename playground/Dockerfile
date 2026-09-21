FROM node:22-bookworm-slim AS frontend
WORKDIR /web
RUN corepack enable && corepack prepare pnpm@11.17.0 --activate
COPY playground/web/package.json playground/web/pnpm-lock.yaml playground/web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY playground/web/ ./
RUN pnpm run build

FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=frontend /static /src/playground/static
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
