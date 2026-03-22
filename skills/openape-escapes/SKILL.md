---
name: openape-escapes
description: Human-gated privilege elevation via the apes CLI. Use when an agent needs to execute commands with elevated (root) privileges, requiring explicit human approval through the OpenAPE grant system.
metadata:
  openclaw:
    emoji: "\U0001F510"
    requires:
      bins:
        - apes
---

# OpenAPE Privilege Elevation (apes)

Setuid-root binary for grant-authorized command execution. Every privileged action requires explicit human approval — there is no autonomous privilege escalation.

## Prerequisites

- **`escapes` binary** installed (via `cargo install openape-escapes` or from release)
- Binary must be setuid-root: `chmod 4755 apes && chown root:root apes`
- Config file at `/etc/openape/config.toml` (root-owned, `0644`)

## Agent Enrollment

Register a new agent keypair:

```bash
sudo escapes enroll \
  --server https://id.example.com \
  --agent-email agent+deploy@example.com \
  --agent-name web-deploy \
  --key /etc/openape/agent.key
```

- Generates an Ed25519 keypair at `--key` if it doesn't exist
- Appends `[[agents]]` entry to `/etc/openape/config.toml`
- Prints enrollment URL for admin to approve on the IdP

Use `--existing` to skip enrollment URL generation when the agent already exists on the server.

## Execute with Grant Token (preferred)

When you already have a grant JWT (e.g. from `grapes exec` or `grapes token`):

```bash
escapes --grant <jwt> -- <command> [args...]
```

Alternative input methods:

```bash
echo "$JWT" | escapes --grant-stdin -- apt update
escapes --grant-file /tmp/grant.jwt -- systemctl restart nginx
```

**Flow:**
1. Verify JWT signature against IdP JWKS
2. Verify command matches grant's `cmd_hash`
3. Call IdP `/api/grants/{id}/consume` to mark grant as used
4. Elevate privileges and execute command

## Execute with Key (legacy mode)

Polls the IdP for human approval:

```bash
escapes --key /etc/openape/agent.key -- systemctl restart myapp
```

**Options:**
- `--key <path>` — path to agent's Ed25519 private key
- `--timeout <secs>` — poll timeout (default: from config, typically 300s)
- `--reason <text>` — human-readable reason for the request
- `--run-as <user>` — switch to user instead of root (default: `root`)

**Flow:**
1. Authenticate with IdP via Ed25519 challenge-response
2. Create grant request
3. Poll for approval (every 2s, up to timeout)
4. Verify returned JWT
5. Elevate and execute

## Agent Management

Update an agent's IdP URL:

```bash
sudo escapes update --email agent+deploy@example.com --server https://new-idp.example.com
```

Remove an agent locally:

```bash
sudo escapes remove --email agent+deploy@example.com
```

Remove locally and from IdP:

```bash
sudo escapes remove --email agent+deploy@example.com --remote
```

## Configuration

**File:** `/etc/openape/config.toml`

```toml
# Optional hostname override (default: system hostname)
target = "server01"

# Optional audit log path (default: /var/log/openape/audit.log)
audit_log = "/var/log/openape/audit.log"

[poll]
interval_secs = 2        # Poll interval (default: 2)
timeout_secs = 300        # Max wait time (default: 300)

[tls]
ca_bundle = "/etc/openape/ca.pem"   # For self-signed certs

[idp]
issuer = "https://id.openape.at"                           # Trusted issuer
jwks_uri = "https://id.openape.at/.well-known/jwks.json"   # Optional, defaults to {issuer}/.well-known/jwks.json

[security]
allowed_audiences = ["escapes"]   # JWT audience claim whitelist (default: ["escapes"])

[[agents]]
name = "web-deploy"
email = "agent+deploy@example.com"
public_key = "ssh-ed25519 AAAA..."
server_url = "https://id.example.com"
```

Multiple `[[agents]]` blocks are supported for multi-agent setups.

## Audit Log

**Format:** JSONL (one JSON object per line), appended to `/var/log/openape/audit.log`.

**Event types:**

| Event | Meaning |
|-------|---------|
| `run` | Command executed (legacy mode) |
| `grant_run` | Command executed (grant-token mode) |
| `denied` | Grant was denied by approver |
| `timeout` | No approval within timeout |
| `error` | Execution or verification error |

**Example entry:**

```json
{
  "ts": "2026-01-15T10:30:00Z",
  "event": "grant_run",
  "mode": "grant-token",
  "real_uid": 1000,
  "command": ["apt", "install", "curl"],
  "cmd_hash": "ab12...",
  "grant_id": "...",
  "grant_type": "once",
  "agent": "agent+deploy@id.openape.at",
  "issuer": "https://id.openape.at",
  "decided_by": "admin@id.openape.at",
  "target": "server01",
  "cwd": "/root"
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (inherits child exit code) |
| 1 | Config, HTTP, I/O, or parse error |
| 2 | Authentication failure |
| 3 | Grant denied |
| 4 | Timeout (no approval received) |
| 5 | JWT verification or cmd_hash mismatch |
| 126 | Exec or privilege error |
| 127 | Command not found |

## Security

- **Environment sanitized** before exec: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `IFS`, `BASH_ENV` etc. are removed
- **Command integrity** verified via SHA-256 hash binding between request and JWT
- **Privilege dropping:** Key loading happens as real user; root only for config access and final exec
- **No ambient authority:** Every command requires explicit human approval — no agent-to-agent or automatic flows

## Guardrails

- **Never use as autonomous privilege escalation.** Every invocation must be human-gated.
- **Prefer grant-token mode** (`--grant`) over legacy (`--key`) for better auditability.
- **Use `once` grants** unless a standing grant is explicitly needed.
- **Monitor audit log** for unexpected patterns.
