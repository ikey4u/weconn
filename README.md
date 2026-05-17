# weconn

Stable connection tooling for **SSH port forwarding** and **TCP bridging** (plain TCP or over WebSocket).

## Build

Rust toolchain compatible with **Edition 2024** (see `Cargo.toml`).

```bash
cargo build --release
```

## Features

- **SSH**: OpenSSH-compatible `-L` / `-R` with automatic reconnect and backoff
- **SSH**: ProxyJump (`-J` or `~/.ssh/config`); full hop chain rebuilds on reconnect
- **SSH**: `-L` listeners stay up during reconnect (clients wait up to 120s)
- **SSH**: Multiple `-L` / `-R` / `-J` in one command; reads `~/.ssh/config`
- **Bridge**: TCP→TCP relay, or TCP↔WebSocket (`--to` / `--from`)
