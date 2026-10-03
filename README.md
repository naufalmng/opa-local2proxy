# opa-local2proxy

Rotating residential proxy from your local machine — **Tor + Cloudflare Warp** multi-port
backend with automatic IP rotation. No monthly subscription.

Compatible with `curl`, Python (`requests`/`aiohttp`), Playwright, and Puppeteer (anything
that speaks SOCKS5).

## Features

- **Multi-port sticky identities** — each port (10800, 10801, 10802…) is its own "identity"
  holding one exit IP until you rotate it.
- **HTTP proxy mode** — optional HTTP proxy listener (CONNECT tunnel + absolute-URI) via
  `RP_HTTP_IDENTITIES`, for clients that only speak HTTP proxy (e.g. many Node/Next.js apps).
- **Auto IP rotation** — per N requests (`RP_ROTATE_EVERY_REQS`) or per N minutes (`RP_ROTATE_MINS`).
- **Dual backend** — round-robin between **Tor** (real rotating exit nodes) and **Cloudflare Warp**
  (cleaner Cloudflare-range IPs, better for anti-bot).
- **REST control API** — `/status`, `/ip`, `/rotate`.
- Single Rust binary, no runtime deps.

## Architecture

```
[client] ──SOCKS5──> listener 127.0.0.1:10800 ─┐
        ──SOCKS5──> listener 127.0.0.1:10801 ──┼─> BackendRouter (round-robin)
        ──SOCKS5──> listener 127.0.0.1:10802 ──┘     ├─> Tor  (127.0.0.1:9050, NEWNYM rotate)
                                                     └─> Warp (system tunnel, disconnect/connect rotate)
                              REST API 127.0.0.1:10808 ── /status /ip /rotate
```

## Prerequisites

### Tor (backend 1)

Install Tor Browser or the Tor expert bundle, then enable the SOCKS5 + control port in
`torrc`:

```
SOCKSPort 9050
ControlPort 9051
# Option A: no-auth control (only bind to localhost)
# Option B: HashedControlPassword 16:<hash>
```

Generate a control password hash if you want auth:

```bash
tor --hash-password "yourpassword"
```

Set `RP_TOR_CONTROL_PASSWORD` accordingly (or leave empty for no-auth).

### Cloudflare Warp (backend 2)

Install [WARP](https://one.one.one.one/). Switch it to **proxy mode** and it exposes a
SOCKS5 endpoint on `127.0.0.1:40000`:

```bash
warp-cli mode proxy
warp-cli connect
```

Set `RP_WARP_BINARY` to the `warp-cli` full path (default Windows path is pre-set) and
`RP_WARP_SOCKS` to `127.0.0.1:40000`. Rotation = `warp-cli disconnect` + `connect`
(new Cloudflare egress IP).

> Warp exit IPs are Cloudflare (AS13335). In Indonesia they resolve to local PoPs
> (Jakarta / Bekasi / etc.) so you get a clean ID IP, but it's still datacenter-range,
> not a true residential ISP IP.

## Build

```bash
cargo build --release
# binary at target/release/opa-local2proxy
```

## Run

```bash
# defaults: 3 identities (10800-10802), both backends, API on 10808
./opa-local2proxy
```

### Configuration (env vars)

| Var | Default | Meaning |
|---|---|---|
| `RP_IDENTITIES` | `127.0.0.1:10800,127.0.0.1:10801,127.0.0.1:10802` | listener addrs (one per identity) |
| `RP_API` | `127.0.0.1:10808` | REST control API |
| `RP_BACKENDS` | `both` | `tor` / `warp` / `both` |
| `RP_TOR_SOCKS` | `127.0.0.1:9050` | Tor SOCKS5 upstream |
| `RP_TOR_CONTROL` | `127.0.0.1:9051` | Tor control port (NEWNYM) |
| `RP_TOR_CONTROL_PASSWORD` | `` | Tor control auth (empty = no-auth) |
| `RP_WARP_BINARY` | `warp-cli.exe` (Windows path) | warp-cli path |
| `RP_WARP_SOCKS` | `127.0.0.1:40000` | Warp proxy-mode SOCKS5 endpoint |
| `RP_HTTP_IDENTITIES` | `` (disabled) | HTTP proxy listener addrs (comma-separated) |
| `RP_ROTATE_EVERY_REQS` | `0` | rotate each identity every N requests (0=off) |
| `RP_ROTATE_MINS` | `0` | rotate each identity every N minutes (0=off) |

## Usage examples

```bash
# check exit IP through identity #0
curl -x socks5h://127.0.0.1:10800 http://lumtest.com/myip.json

# rotate all identities
curl -X POST http://127.0.0.1:10808/rotate

# status
curl http://127.0.0.1:10808/status
```

Python:

```python
import requests
proxies = {"http": "socks5h://127.0.0.1:10800", "https": "socks5h://127.0.0.1:10800"}
print(requests.get("http://lumtest.com/myip.json", proxies=proxies).text)
```

Playwright / Puppeteer: set the browser proxy to `socks5://127.0.0.1:10800`.

## HTTP proxy mode

For clients that only speak HTTP proxy (Node/Next.js apps, tools without SOCKS5 support),
run with `RP_HTTP_IDENTITIES`:

```bash
RP_BACKENDS=warp RP_HTTP_IDENTITIES=127.0.0.1:10810 ./opa-local2proxy
```

Then point the client at `http://127.0.0.1:10810` (supports both `CONNECT` tunneling for
HTTPS and absolute-URI forwarding for plain HTTP).

## systemd service

A ready-to-use unit file is in `deploy/opa-local2proxy.service`. Install:

```bash
sudo cp deploy/opa-local2proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now opa-local2proxy
```

It runs with Warp backend + HTTP proxy on `127.0.0.1:10810` + SOCKS5 on `127.0.0.1:10900`,
auto-starts on boot and restarts on failure.

## Notes

- **Tor is blocked by Google/reCAPTCHA** (exit nodes are flagged). Use **Warp** identity for
  Google-facing work; use Tor for general scraping.
- Rotation is **async best-effort**: a rotate triggers on the next request after the threshold,
  not mid-stream.
- Warp rotation = `warp-cli disconnect` + `connect` (new Cloudflare egress IP).
