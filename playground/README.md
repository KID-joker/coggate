# CogGate Playground

CogGate Playground is an independent workspace that consumes `coggate-core` and `coggate-contracts` through local path dependencies. It provides anonymous rules and rotating previews, GitHub OAuth on submission, a SQLite-backed daily quota and queue, one-shot CogGate verification, atomic first-winner closure, SSE refresh, and a durable GitHub Issue outbox.

The `coggate-playground` process never receives the Docker socket. The separate `arena-runner` broker is the only process allowed to reach Docker and accepts a bounded Unix-socket protocol with fixed language commands. It always asks Docker for `runsc`, `network=none`, a read-only root filesystem, no capabilities, a non-root container user, and fixed CPU, memory, PID and output limits.

## Required configuration

Copy `playground/deploy/.env.example` to `playground/deploy/.env` and fill every blank. Production image values must be immutable digests. The host Docker daemon must have the gVisor `runsc` runtime installed and each runner image must already be present locally.

The MAC keyring is a JSON file outside SQLite:

```json
{
  "keys": {
    "arena-primary-v1": "BASE64URL_WITHOUT_PADDING_32_BYTES_OR_MORE",
    "arena-retiring-v0": "BASE64URL_WITHOUT_PADDING_32_BYTES_OR_MORE"
  }
}
```

`ARENA_MAC_KEY_ID` selects the issuance key. Retiring keys stay in the file until all issued challenges and recovery leases are outside their retention window.

The GitHub OAuth App callback is `https://<domain>/auth/github/callback`. The GitHub App must be installed on the target repository with read/write Issues permission; configure its numeric app and installation IDs and mount its PEM key.

## Initialize a round

Schema creation is automatic. A new round deliberately starts as `PREPARING` and is never opened by a web-service restart:

```sh
cargo run --manifest-path playground/Cargo.toml --bin coggate-playground -- admin create-round 0.1.0 <git-commit> 1.0 <runner-manifest-sha256>
cargo run --manifest-path playground/Cargo.toml --bin coggate-playground -- admin open-round <round-id>
```

Only run `open-round` after all seven digest-pinned images have passed compile, stdin/stdout, timeout, no-network and resource-limit self-checks. The command writes an `admin_audit` record.

## Run locally

Start the broker first, then the web process. The broker refuses startup without all seven image digests and `ARENA_WEB_UID`, and rejects Unix peers with any other UID.

```sh
cargo run --manifest-path playground/Cargo.toml --bin arena-runner
cargo run --manifest-path playground/Cargo.toml --bin coggate-playground
```

The Compose example is in `playground/deploy/compose.yaml`. It intentionally mounts the Docker socket only into the broker. The standard Caddy image does not provide application-aware rate limiting; configure edge rate/concurrency limits with the chosen provider firewall or a reviewed Caddy module before public launch.

## Data retention

Failed source is needed only while queued or recoverably compiling. Every failure terminal transition sets `source = NULL` and retains only `source_sha256`. The winning source remains until the Issue outbox reaches `CREATED`. The actual public challenge and bounded compiler/runtime output are removed after 24 hours.

## Verification

```sh
cargo test --manifest-path playground/Cargo.toml
cargo clippy --manifest-path playground/Cargo.toml --all-targets -- -D warnings
```
