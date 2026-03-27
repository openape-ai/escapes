# escapes — Privilege Elevation via OpenApe Grants

`escapes` is a setuid-root binary that replaces traditional `sudo` with a grant-based approval workflow. Instead of a password, each privileged command requires real-time approval from an authorized approver through an [OpenApe](https://docs.openape.at) Identity Provider (IdP).

```
grapes "escapes" "whoami" --approval once
    │
    ▼
┌───────────┐   POST /api/grants    ┌────────────────┐
│  grapes   │ ──────────────────────►│  OpenApe IdP   │
│  (CLI)    │ ◄── approved + JWT ───│                │
└─────┬─────┘                       └───────┬────────┘
      │ escapes --grant <jwt> -- whoami         │
      ▼                               Approver approves
┌───────────┐   POST /consume        in browser UI
│  escapes  │ ──────────────────────►
│  (setuid) │ ◄── OK ──────────────
│           │ verify 7 properties
└─────┬─────┘ elevate, exec
      ▼
Command runs as root
```

**Key properties:**

- **Grant-token only** — `escapes` receives a pre-approved JWT from `grapes`; no key management, no polling
- **7-step verification chain** before any command runs:
  1. Issuer is in `allowed_issuers`
  2. JWT signature valid (JWKS)
  3. Approver is in `allowed_approvers`
  4. Audience is in `allowed_audiences`
  5. `target_host` matches this machine
  6. Command/cmd_hash matches
  7. IdP consume check passes (replay protection)
- Environment is sanitized before exec (LD_PRELOAD, PATH, etc.)
- Full audit log in JSONL format

### Security Model

The security boundaries are:

- **`allowed_issuers`** — which IdPs are trusted (only their JWKS is fetched)
- **`allowed_approvers`** — who can approve grants (equivalent to sudoers)
- **`allowed_audiences`** — which services this instance accepts grants for (default: `["escapes"]`)
- **`target_host`** — grants are bound to a specific machine; a grant for "macmini" won't work on "server01"
- **Config is root-owned** — `/etc/openape/config.toml` defines the trust boundary; only root can modify it

## Prerequisites

- **A running OpenApe IdP** with grants support — see [docs.openape.at](https://docs.openape.at)
- **grapes CLI** — the companion tool that handles login, grant requests, and token retrieval
- **macOS** (aarch64/x86_64) or **Linux** (amd64/arm64)

## Install

### macOS (recommended)

Download the `.pkg` installer from [GitHub Releases](https://github.com/openape-ai/escapes/releases/latest) and double-click. The installer sets the setuid bit, creates `/etc/openape/config.toml`, and the audit log directory.

### Linux (Debian/Ubuntu)

```bash
curl -sSfLO https://github.com/openape-ai/escapes/releases/latest/download/openape-escapes_0.3.0_amd64.deb
sudo dpkg -i openape-escapes_0.3.0_amd64.deb
```

### Linux (RHEL/Fedora)

```bash
curl -sSfLO https://github.com/openape-ai/escapes/releases/latest/download/openape-escapes-0.3.0.x86_64.rpm
sudo rpm -i openape-escapes-0.3.0.x86_64.rpm
```

### Shell installer (all platforms)

```bash
curl -sSf https://raw.githubusercontent.com/openape-ai/escapes/main/packaging/install.sh | sudo bash
```

Downloads the latest release, verifies SHA256 checksums, and installs with the setuid bit.

### From source

Requires [Rust](https://rustup.rs) 1.70+:

```bash
cargo build --release
sudo make install
```

## Update

```bash
escapes --update
```

Checks GitHub Releases for a new version, downloads, verifies the checksum, and atomically replaces the binary (preserving setuid root).

## Uninstall

### macOS (.pkg)

```bash
curl -sSf https://raw.githubusercontent.com/openape-ai/escapes/main/packaging/macos/uninstall.sh | sudo bash
```

### Linux (.deb)

```bash
sudo apt remove openape-escapes
```

### Linux (.rpm)

```bash
sudo rpm -e openape-escapes
```

### Manual

```bash
sudo make uninstall
sudo rm -rf /etc/openape /var/log/openape  # optional: remove config + logs
```

## Configuration

Config lives at `/etc/openape/config.toml` (permissions `0644`, owned by root).

```toml
# host = "macmini"                             # default: system hostname
# run_as = "root"                              # default: "root"
# audit_log = "/var/log/openape/audit.log"        # default

[security]
allowed_issuers = ["https://id.openape.at"]    # REQUIRED
allowed_approvers = ["phofmann@delta-mind.at"] # REQUIRED
# allowed_audiences = ["escapes"]                 # default: ["escapes"]

# [tls]
# ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
```

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | no | system hostname | Machine identifier for `target_host` verification |
| `run_as` | no | `"root"` | Default user to execute commands as |
| `audit_log` | no | `/var/log/openape/audit.log` | Path to the JSONL audit log |
| `security.allowed_issuers` | **yes** | — | Trusted IdP URLs |
| `security.allowed_approvers` | **yes** | — | Identifiers of users who can approve grants |
| `security.allowed_audiences` | no | `["escapes"]` | Accepted JWT audience values |
| `tls.ca_bundle` | no | system default | Custom CA bundle path |

## Usage

Use `grapes` to request, approve, and execute:

```bash
# Login to IdP (once)
grapes login --idp https://id.openape.at --key ~/.ssh/id_ed25519 --email agent+user@id.openape.at

# Request grant and execute
grapes run escapes "whoami" --approval once

# With a reason
grapes run escapes "systemctl restart nginx" --reason "deploy v2.1"
```

Or provide the JWT directly:

```bash
escapes --grant <jwt> -- whoami
escapes --grant-file /tmp/grant.jwt -- systemctl restart nginx
echo "$JWT" | escapes --grant-stdin -- apt update
```

### What happens when you run a command

1. `escapes` loads the config (as root)
2. Resolves the grant JWT from `--grant`, `--grant-stdin`, or `--grant-file`
3. Extracts the issuer from the JWT (unverified)
4. Checks issuer is in `allowed_issuers`
5. Fetches JWKS from `{issuer}/.well-known/jwks.json`
6. Verifies JWT signature
7. Checks `decided_by` is in `allowed_approvers`
8. Checks `aud` is in `allowed_audiences`
9. Checks `target_host` matches this machine
10. Verifies command matches grant (array or cmd_hash)
11. Calls IdP consume endpoint (replay protection)
12. Elevates to root (or `run_as` user from JWT/config)
13. Sanitizes environment
14. Writes audit log entry
15. Replaces process with command via `execvp`

## Audit Log

Every execution and error is logged in JSONL format. Default location: `/var/log/openape/audit.log`.

**`grant_run`** — command approved and executed:
```json
{"ts":"2026-01-15T10:30:00Z","event":"grant_run","real_uid":1000,"command":["whoami"],"cmd_hash":"ab12...","grant_id":"...","grant_type":"once","agent":"agent@id.openape.at","issuer":"https://id.openape.at","decided_by":"phofmann@delta-mind.at","audience":"escapes","target_host":"macmini","host":"macmini"}
```

**`error`** — unexpected failure:
```json
{"ts":"...","event":"error","real_uid":1000,"command":["..."],"host":"macmini","message":"..."}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran) |
| 1 | Configuration error, HTTP error, I/O error |
| 5 | JWT verification failed or cmd_hash mismatch |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

## License

AGPL-3.0-or-later
