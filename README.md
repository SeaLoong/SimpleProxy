# SimpleProxy

A lightweight, configurable local HTTP/HTTPS proxy server written in Rust. Intercept, redirect, replace, or block HTTP requests based on flexible rules. Includes a built-in web dashboard for visual management.

## Features

- **Rule-based interception** – Match URLs by exact string or regex, then redirect, replace content, block, or forward requests
- **Web dashboard** – Built-in control panel at `http://127.0.0.1:9000` for editing configuration and rules in the browser
- **Hot reload** – Rules file is watched for changes and reloaded automatically
- **Upstream proxy** – Route traffic through an HTTP or SOCKS5 upstream proxy
- **System proxy** – Auto-configure OS-level proxy settings (Windows / macOS / Linux) with RAII-based restore on exit
- **HTTPS tunneling** – Full CONNECT method support for TLS passthrough
- **Minimal footprint** – Single binary, no runtime dependencies

## Quick Start

```bash
# Build
cargo build --release

# Run (uses config.json in current directory by default)
./target/release/simple-proxy

# Run with a custom config path
./target/release/simple-proxy --config path/to/config.json
```

On first launch the web dashboard opens automatically at `http://127.0.0.1:9000`.

## Configuration

Settings live in **config.json** (separate from rules):

```json
{
  "port": 8888,
  "rulesFile": "rules.json",
  "webPort": 9000,
  "autoOpenBrowser": true,
  "systemProxy": false,
  "upstreamProxy": null
}
```

| Field             | Type         | Default        | Description                                           |
| ----------------- | ------------ | -------------- | ----------------------------------------------------- |
| `port`            | number       | `8888`         | Proxy server listen port                              |
| `rulesFile`       | string       | `"rules.json"` | Path to the rules JSON file (relative to config file) |
| `webPort`         | number       | `9000`         | Web dashboard listen port                             |
| `autoOpenBrowser` | boolean      | `true`         | Open the dashboard in the default browser on start    |
| `systemProxy`     | boolean      | `false`        | Auto-set OS proxy settings to point at this proxy     |
| `upstreamProxy`   | string\|null | `null`         | Global upstream proxy URL (`http://`, `socks5://`)    |

If the config file does not exist, a default one is created automatically.

## Rules

Rules are stored as a plain JSON array in **rules.json**:

```json
[
  {
    "comment": "Redirect old page to new page",
    "match": "http://example.com/old",
    "type": "redirect",
    "target": "http://example.com/new",
    "statusCode": 302,
    "enabled": true
  },
  {
    "comment": "Block analytics",
    "match": "^https?://analytics\\.example\\.com/.*",
    "isRegex": true,
    "type": "block",
    "statusCode": 403,
    "enabled": true
  }
]
```

### Rule Fields

| Field           | Type    | Required | Description                                                |
| --------------- | ------- | -------- | ---------------------------------------------------------- |
| `match`         | string  | yes      | URL pattern (exact match or regex)                         |
| `type`          | string  | yes      | `redirect` \| `replace` \| `block` \| `proxy` \| `forward` |
| `isRegex`       | boolean | no       | Treat `match` as a regex pattern                           |
| `target`        | string  | no       | Target URL (for `redirect` / `proxy`)                      |
| `statusCode`    | number  | no       | HTTP status code to return                                 |
| `body`          | string  | no       | Response body (for `replace` / `block`)                    |
| `contentType`   | string  | no       | Content-Type header (for `replace`)                        |
| `file`          | string  | no       | Local file path to serve (for `replace`)                   |
| `headers`       | object  | no       | Custom headers to inject (for `proxy`)                     |
| `upstreamProxy` | string  | no       | Per-rule upstream proxy (for `forward`)                    |
| `comment`       | string  | no       | Human-readable description                                 |
| `enabled`       | boolean | no       | Enable/disable the rule (default `true`)                   |

### Rule Types

| Type       | Behavior                                               |
| ---------- | ------------------------------------------------------ |
| `redirect` | Returns a redirect response with `Location` header     |
| `replace`  | Returns custom content (inline `body` or local `file`) |
| `block`    | Returns an error response (default 403)                |
| `proxy`    | Forwards the request to a different `target` URL       |
| `forward`  | Forwards through a specific `upstreamProxy`            |

## Web Dashboard

The built-in dashboard provides:

- **Configuration panel** – Edit all config.json fields and save
- **Rules table** – View, add, edit, delete, and toggle rules
- **Live persistence** – Changes are saved to disk immediately

Access it at `http://127.0.0.1:<webPort>` (default 9000).

## CLI

```
simple-proxy [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to the config JSON file [default: config.json] [env: CONFIG_FILE]
  -h, --help             Print help
  -V, --version          Print version
```

## Project Structure

```
src/
  main.rs          – Entry point, CLI parsing, orchestration
  config.rs        – Config file loading and management
  rule_engine.rs   – Rule loading, matching, hot-reload
  proxy.rs         – HTTP/HTTPS proxy server (raw TCP)
  upstream.rs      – HTTP and SOCKS5 upstream proxy connector
  system_proxy.rs  – OS-level proxy configuration (Win/Mac/Linux)
  web.rs           – Web dashboard server and embedded UI
  lib.rs           – Library crate exports
config.json        – Application settings
rules.json         – Interception rules (plain array)
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test

# Lint
cargo clippy
```

## License

ISC
