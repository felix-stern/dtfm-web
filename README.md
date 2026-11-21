# dtfm-web

**E2EE, read-only, single-tab Chrome MV3 browser bridge for remote AI agents** (`dtfm-web` extension + stateless `lmdtfy-web` Go CLI).

`dtfm-web` lets you share a **single browser tab** (for example, a multi-step tax portal, bank form, or admin console on ChromeOS, macOS, or Linux) with a remote AI agent over `wss://relay.dtfm.dev/ws` — with **zero local daemon**, **zero SSH tunnel**, **end-to-end AES-256-GCM encryption**, and **strict read-only guarantees**.

---

## Security & Audit Guarantees

`extension/` is intentionally **vanilla JavaScript with zero npm dependencies and zero build step** so you can audit the entire extension in ~3 minutes:

- **Minimal MV3 permissions**: `["activeTab", "scripting", "storage"]` + `optional_host_permissions: ["https://*/*", "http://*/*"]`.
  - No `chrome.debugger`, no `cookies`, no `webRequest`, no blanket `<all_urls>`.
- **Single-origin, single-tab pinning**: Clicking **Share this tab** requests host permission *only* for the active tab's origin (`https://example.com/*`), pins that single `tabId`, and displays a green `LIVE` badge. Clicking **Stop Sharing** or closing the tab immediately closes the WebSocket, clears the badge, wipes the in-memory key, and revokes the origin permission (`chrome.permissions.remove`).
- **End-to-End Encrypted (E2EE)**: Uses Web Crypto (`crypto.subtle`) with exact wire parity to [`github.com/iinozemtsev-lab/dtfm/pkg/e2ee`](https://github.com/iinozemtsev-lab/dtfm/tree/main/pkg/e2ee) (HKDF-SHA256 key derivation, per-connection HMAC-SHA256 handshakes, AES-256-GCM with monotonic 64-bit counter nonces and AAD binding). The relay never sees your secret key, DOM, or screenshots.
- **Fail-closed screenshot guard**: Before calling `chrome.tabs.captureVisibleTab`, the extension checks `sharedTab.active === true`. If you switched tabs, it refuses and returns `ERR_TAB_NOT_ACTIVE` instead of leaking another tab.
- **Strictly read-only DOM extraction**: `content.js` never clicks, types, or submits forms. `<input type="password">` values are automatically masked as `"[REDACTED]"`, and hidden CSRF/session inputs are omitted.

---

## Installing the Chrome Extension (ChromeOS / Chrome)

### Option A: Download from GitHub Releases (Recommended on ChromeOS)

No Git, Go, or Linux container required on your Chromebook:

1. Open the [**Releases**](https://github.com/iinozemtsev-lab/dtfm-web/releases) page and download `dtfm-web-extension-<tag>.zip` (and optionally verify against `SHA256SUMS`).
2. In ChromeOS **Files**, right-click `dtfm-web-extension-<tag>.zip` and choose **Extract all** (creates a folder containing `manifest.json`).
3. Open `chrome://extensions` in Chrome and enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the extracted folder.
5. Pin **dtfm-web** to your toolbar for quick access.

### Option B: Load Directly from a Local Clone

```bash
git clone https://github.com/iinozemtsev-lab/dtfm-web.git
```

Then open `chrome://extensions` -> enable **Developer mode** -> **Load unpacked** -> select the `dtfm-web/extension/` directory.

---

## Pairing Workflow

1. Navigate to the browser tab you want your remote AI agent to inspect.
2. Click the **dtfm-web** toolbar icon.
3. (Optional) Adjust the **Relay WebSocket URL** (default: `wss://relay.dtfm.dev/ws`).
4. Click **Share this tab** and approve the single-origin host permission prompt.
5. The toolbar badge turns **`LIVE`**. Click **Copy Pairing Token** (`<session-id>#<hex-key>`).
6. Pass the token to your remote agent via `--relay` or `DTFM_WEB_RELAY`.
7. When finished, click **Stop Sharing** (or simply close the shared tab) — the session terminates and the origin permission is automatically revoked.

---

## `lmdtfy-web` CLI (Agent Side)

`lmdtfy-web` is a stateless, single-binary (`CGO_ENABLED=0`) Go CLI that runs on your remote agent machine.

### Install

Download the prebuilt static binary for your platform from [GitHub Releases](https://github.com/iinozemtsev-lab/dtfm-web/releases) (`lmdtfy-web-linux-amd64`, `lmdtfy-web-linux-arm64`, `lmdtfy-web-darwin-amd64`, `lmdtfy-web-darwin-arm64`), or build from source:

```bash
make build
# Binary written to bin/lmdtfy-web
```

### Usage

```bash
export DTFM_WEB_RELAY="<session-id>#<64-char-hex-key>"
# Optional: override relay endpoint (default: wss://relay.dtfm.dev/ws)
# export DTFM_WEB_RELAY_URL="wss://relay.dtfm.dev/ws"

# Check shared tab status (title, URL, whether tab is currently active)
lmdtfy-web status

# Extract read-only DOM as compact Markdown (default, ~2-8 KB)
lmdtfy-web dom

# Extract read-only DOM as structured JSON
lmdtfy-web dom --format json

# Capture visible PNG screenshot of the shared tab (fail-closed if tab is inactive)
lmdtfy-web shot /tmp/page.png
```

You can also pass `--relay` and `--relay-url` explicitly on any subcommand:

```bash
lmdtfy-web status --relay "<session-id>#<hex-key>" --relay-url wss://relay.dtfm.dev/ws
lmdtfy-web dom --format md --relay "<session-id>#<hex-key>"
lmdtfy-web shot page.png --relay "<session-id>#<hex-key>"
```

### Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Success |
| `1`  | CLI error, auth failure (`403`), persistent `409 Conflict`, or browser guard error (e.g. `ERR_TAB_NOT_ACTIVE`) |
| `2`  | Session inactive (tab closed/not shared, HTTP `404`, or relay unreachable) |

On transient HTTP `409 Conflict` (e.g., accidental parallel agent tool calls), `lmdtfy-web` automatically retries once after ~250ms jitter.

---

## Development & Testing

```bash
# Run JS WebCrypto + DOM tests and Go unit, race, and cross-language E2EE tests
make test

# Build static local binary
make build

# Cross-compile static binaries for linux/darwin (amd64/arm64)
make cross
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
