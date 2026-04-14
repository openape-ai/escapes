---
name: openape-escapes
description: Human-gated privilege elevation via the apes CLI. Use when an agent needs to execute commands with elevated (root) privileges, requiring explicit human approval through the OpenApe grant system.
metadata:
  openclaw:
    emoji: "\U0001F510"
    requires:
      bins:
        - apes
---

# OpenApe Privilege Elevation (apes + escapes)

Setuid-root binary for grant-authorized command execution. Every privileged action requires explicit human approval — there is no autonomous privilege escalation.

## Architecture

Two binaries work together:

- **`apes`** — the TypeScript CLI (npm package `@openape/apes`) that handles login, grant requests, approval polling, and command dispatch. This is what an agent invokes.
- **`escapes`** — the setuid-root Rust binary that receives a pre-approved JWT from `apes`, performs the 7-step verification chain, and executes the command under the target user.

When `apes run` sees `--as <user>`, it automatically switches the audience to `escapes`, posts the grant to the IdP, retrieves the JWT after approval, and invokes `escapes --grant <jwt> -- <command>`.

## Prerequisites

- **`apes` CLI** installed (`npm install -g @openape/apes`) and logged in (`apes login`)
- **`escapes` binary** installed and setuid-root (via `.pkg`, `.deb`, `.rpm`, or `sudo make install`)
- **Config file** at `/etc/openape/config.toml` (root-owned, `0644`) with `allowed_issuers` and `allowed_approvers` populated

## Execute Privileged Commands (primary flow)

Use `apes run --as <user>` — this is the canonical entry point:

```bash
apes run --as root -- whoami
apes run --as root -- systemctl restart nginx
apes run --as postgres -- pg_dump mydb
```

**Flow:**
1. `apes` detects `--as <user>`, switches the grant audience to `escapes`
2. Posts a grant request to the IdP (`POST /api/grants`)
3. Returns an async-pending marker (exit 75 = EX_TEMPFAIL) with the approval URL
4. Agent informs the user about the approval URL, then blocks on `apes grants run <id> --wait`
5. When the user approves in the browser, the polling loop resolves
6. `apes` retrieves the JWT from the IdP
7. `apes` invokes `escapes --grant <jwt> -- <command>`
8. `escapes` performs the 7-step verification chain and elevates

**Approval types:**

```bash
apes run --as root --approval once   -- apt update           # default; single-use
apes run --as root --approval timed  -- tail -f /var/log/syslog
apes run --as root --approval always -- systemctl status docker
```

**With a reason:**

```bash
apes run --as root --reason "deploy v2.1" -- systemctl restart api
```

## Execute with a Grant Token Directly (escapes-only)

When you already have a grant JWT (e.g. from a prior `apes` invocation or an out-of-band workflow):

```bash
escapes --grant <jwt> -- <command> [args...]
```

Alternative input methods:

```bash
echo "$JWT" | escapes --grant-stdin -- apt update
escapes --grant-file /tmp/grant.jwt -- systemctl restart nginx
```

## escapes CLI Reference

`escapes` accepts flags only; it has no subcommands.

| Flag | Description |
|------|-------------|
| `--config <path>` | Path to config file (default: `/etc/openape/config.toml`) |
| `--grant <jwt>` | Grant token JWT (or set `ESCAPES_GRANT` env var) |
| `--grant-stdin` | Read the JWT from stdin |
| `--grant-file <path>` | Read the JWT from a file |
| `--run-as <user>` | Execute command as this user instead of root |
| `--update` | Self-update from GitHub Releases |
| `-- <cmd> [args...]` | Command to execute with elevated privileges |

## 7-Step Verification Chain

Before any command runs, `escapes` verifies:

1. Issuer is in `allowed_issuers`
2. JWT signature valid (JWKS)
3. Approver (`decided_by`) is in `allowed_approvers`
4. Audience (`aud`) is in `allowed_audiences`
5. `target_host` matches this machine
6. Command / `cmd_hash` matches the JWT
7. IdP `/api/grants/{id}/consume` call succeeds (replay protection)

Only then does `escapes` elevate and `execvp` the command.

## Configuration

**File:** `/etc/openape/config.toml` (root-owned, `0644`)

```toml
# host = "macmini"                              # default: system hostname
# run_as = "root"                               # default: "root"
# audit_log = "/var/log/openape/audit.log"      # default

[security]
allowed_issuers = ["https://id.openape.at"]     # REQUIRED — trusted IdP URLs
allowed_approvers = ["phofmann@delta-mind.at"]  # REQUIRED — who can approve grants
# allowed_audiences = ["escapes"]               # default: ["escapes"]

# [tls]
# ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
```

**Fields:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | no | system hostname | Machine identifier for `target_host` verification |
| `run_as` | no | `"root"` | Default user to execute commands as |
| `audit_log` | no | `/var/log/openape/audit.log` | Path to the JSONL audit log |
| `security.allowed_issuers` | **yes** | — | Trusted IdP URLs |
| `security.allowed_approvers` | **yes** | — | Identifiers of users who can approve grants |
| `security.allowed_audiences` | no | `["escapes"]` | Accepted JWT audience values |
| `tls.ca_bundle` | no | system default | Custom CA bundle path |

## Audit Log

**Format:** JSONL (one JSON object per line), appended to `/var/log/openape/audit.log`.

**`grant_run`** — command approved and executed:

```json
{
  "ts": "2026-04-14T10:30:00Z",
  "event": "grant_run",
  "real_uid": 1000,
  "command": ["apt", "install", "curl"],
  "cmd_hash": "ab12...",
  "grant_id": "...",
  "grant_type": "once",
  "agent": "agent+deploy@id.openape.at",
  "issuer": "https://id.openape.at",
  "decided_by": "phofmann@delta-mind.at",
  "audience": "escapes",
  "target_host": "macmini",
  "host": "macmini"
}
```

**`error`** — unexpected failure:

```json
{
  "ts": "...",
  "event": "error",
  "real_uid": 1000,
  "command": ["..."],
  "host": "macmini",
  "message": "..."
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran) |
| 1 | Configuration error, HTTP error, I/O error |
| 5 | JWT verification failed or `cmd_hash` mismatch |
| 75 | (from `apes run`) Grant pending — retry with `apes grants run <id> --wait` |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

## Security

- **Environment sanitized** before exec: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `IFS`, `BASH_ENV` etc. are removed
- **Command integrity** verified via SHA-256 hash binding between request and JWT
- **Privilege dropping:** grant resolution and IdP calls happen as the real user; root is only used for config access and the final exec
- **No ambient authority:** every command requires explicit human approval — no agent-to-agent or automatic flows
- **Replay protection:** IdP `consume` call fails on a second use of the same grant

## Guardrails

- **Never use as autonomous privilege escalation.** Every invocation must be human-gated.
- **`sudo` is not available inside `ape-shell`.** Use `apes run --as root -- <cmd>` instead. `ape-shell` detects `sudo` at the line start and returns an explicit error message pointing to the correct form.
- **Use `once` grants** unless a standing grant is explicitly needed. `timed` and `always` are available when the user wants reuse without re-approval.
- **Monitor the audit log** at `/var/log/openape/audit.log` for unexpected patterns.
