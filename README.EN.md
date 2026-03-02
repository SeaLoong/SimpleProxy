# SimpleProxy

[简体中文](README.md) | **English**

A lightweight, configurable local HTTP/HTTPS proxy server written in Rust. Intercept, redirect, replace, or block requests based on flexible rules with full HTTPS MITM support. Includes a built-in bilingual web dashboard for visual management.

## Features

- **Rule-based interception** – Match URLs by exact string or regex, then redirect, replace content, block, or forward requests
- **HTTPS MITM interception** – Transparently intercept HTTPS traffic; auto-generates CA and per-host leaf certificates
- **Virtual NIC proxy (TUN)** – Create a virtual network adapter for transparent TCP/UDP proxying with custom routing and DNS, no system proxy required
- **Web dashboard** – Built-in bilingual (English/Chinese) control panel at `http://127.0.0.1:9000`
- **Hot reload** – Rules file is watched for changes and reloaded automatically
- **Upstream proxy** – Route traffic through an HTTP or SOCKS5 upstream proxy (global or per-rule)
- **System proxy** – Auto-configure OS-level proxy settings (Windows / macOS / Linux) with real-time toggle from the web dashboard; automatically restored on exit
- **Certificate management** – Auto-generate CA, system trust store detection, one-click download from dashboard
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

On first launch:

1. A CA certificate is generated in the `ca/` directory
2. The web dashboard opens automatically at `http://127.0.0.1:9000`
3. Install the CA certificate to enable seamless HTTPS interception

## Configuration

Settings live in **config.json** (separate from rules):

```json
{
  "port": 8888,
  "rulesFile": "rules.json",
  "webPort": 9000,
  "autoOpenBrowser": true,
  "systemProxy": false,
  "upstreamProxy": null,
  "tun": {
    "enabled": false,
    "address": "10.0.0.33",
    "netmask": "255.255.255.0",
    "dns": null,
    "mtu": 1500,
    "routes": [],
    "excluded_ips": []
  }
}
```

| Field             | Type         | Default        | Description                                                     |
| ----------------- | ------------ | -------------- | --------------------------------------------------------------- |
| `port`            | number       | `8888`         | Proxy server listen port                                        |
| `rulesFile`       | string       | `"rules.json"` | Path to the rules JSON file (relative to config file)           |
| `webPort`         | number       | `9000`         | Web dashboard listen port                                       |
| `autoOpenBrowser` | boolean      | `true`         | Open the dashboard in the default browser on start              |
| `systemProxy`     | boolean      | `false`        | Auto-set OS proxy on start (can be toggled live from dashboard) |
| `upstreamProxy`   | string\|null | `null`         | Global upstream proxy URL (`http://`, `socks5://`)              |
| `tun`             | object       | see below      | Virtual NIC (TUN) proxy configuration                           |

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
| `headers`       | object  | no       | Custom headers to inject (for `proxy` / `forward`)         |
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

## HTTPS Interception

SimpleProxy supports HTTPS MITM (Man-In-The-Middle) interception:

- On first run, a root CA certificate and key pair are generated in the `ca/` directory
- For hosts matching any rule, TLS is terminated and requests are inspected
- For non-matching hosts, a plain TCP tunnel is used (no interception)
- Per-host leaf certificates are generated on-the-fly and cached

### Installing the CA Certificate

**Windows:**

```powershell
# GUI: Double-click ca/ca.crt → Install Certificate → Local Machine → Trusted Root CAs
# Or via command line (run as Administrator):
certutil -addstore Root ca\ca.crt
```

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca/ca.crt
```

**Linux:**

```bash
sudo cp ca/ca.crt /usr/local/share/ca-certificates/simpleproxy-ca.crt
sudo update-ca-certificates
```

The web dashboard shows the CA trust status and provides a download button.

## Virtual NIC Proxy (TUN)

SimpleProxy supports transparent network proxying via a virtual network adapter (TUN device), without manual system or browser proxy configuration.

### Prerequisites

- Run with **administrator privileges** (required for TUN device creation and route management)
- **Windows**: Place `wintun.dll` in the executable directory or system PATH. Download from [wintun.net](https://www.wintun.net/)

### TUN Configuration

| Field          | Type         | Default           | Description                                         |
| -------------- | ------------ | ----------------- | --------------------------------------------------- |
| `enabled`      | boolean      | `false`           | Enable the virtual NIC proxy                        |
| `address`      | string       | `"10.0.0.33"`     | Virtual adapter IP address                          |
| `netmask`      | string       | `"255.255.255.0"` | Subnet mask                                         |
| `dns`          | string\|null | `null`            | Custom DNS server (redirects DNS queries)           |
| `mtu`          | number       | `1500`            | Maximum Transmission Unit                           |
| `routes`       | string[]     | `[]`              | CIDR routes to capture (e.g., `"0.0.0.0/1"`)        |
| `excluded_ips` | string[]     | `[]`              | IPs/CIDRs to exclude from TUN routing (avoid loops) |

### TUN Usage Example

```json
"tun": {
  "enabled": true,
  "address": "10.0.0.33",
  "netmask": "255.255.255.0",
  "dns": "8.8.8.8",
  "mtu": 1500,
  "routes": ["0.0.0.0/1", "128.0.0.0/1"],
  "excluded_ips": ["your-gateway-ip/32"]
}
```

> **Note**: To capture all traffic, use `0.0.0.0/1` + `128.0.0.0/1` instead of `0.0.0.0/0`, and add your real gateway IP to `excluded_ips` to avoid routing loops.

## Web Dashboard

The built-in dashboard provides:

- **Certificate status** – Shows whether the CA is trusted, with download and re-check buttons
- **System proxy toggle** – Enable or disable the system proxy in real time without restarting; instant status feedback
- **Configuration panel** – Edit all config.json fields and save
- **Rules table** – View, add, edit, delete, and toggle rules
- **Bilingual UI** – Switch between English and Chinese with one click
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
  proxy.rs         – HTTP/HTTPS proxy server with MITM support
  cert.rs          – CA certificate management and per-host cert generation
  upstream.rs      – HTTP and SOCKS5 upstream proxy connector
  system_proxy.rs  – OS-level proxy configuration (Win/Mac/Linux)
  tun_proxy.rs     – Virtual NIC (TUN) transparent proxy
  web.rs           – Web dashboard server and embedded bilingual UI
  lib.rs           – Library crate exports
config.json        – Application settings
rules.json         – Interception rules (plain array)
ca/                – Auto-generated CA certificate and key (gitignored)
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

[MIT](LICENSE)
