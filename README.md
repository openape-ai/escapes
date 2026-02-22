# openape-sudo (`apes`)

Privilege elevation via OpenAPE grants. Like `sudo`, but every command requires human approval through a web UI before it executes.

## How It Works

1. Agent authenticates to the OpenAPE IdP via Ed25519 challenge-response
2. A grant request is created (includes the exact command + cryptographic hash)
3. A human approver reviews and approves/denies the request in the web UI
4. On approval, the agent receives a signed AuthZ-JWT, verifies it locally, then executes the command as root

## Build & Install

```bash
cargo build --release

# Install with setuid bit (required)
sudo make install
```

This installs the binary to `/usr/local/bin/apes` with the setuid bit set (`4755`), allowing any user to invoke it while the binary handles privilege escalation securely.

## Agent Enrollment

Enrollment is a two-step process: generate keys locally, then have an admin approve via web UI.

### Step 1: Generate Keys (on the server, as root)

```bash
sudo apes enroll --server https://id.example.com --agent-name prod-web-01
```

This creates:
- `/etc/apes/agent.key` — Ed25519 private key (mode `0600`)
- `/etc/apes/config.toml` — configuration with agent ID already set (mode `0600`)

The command prints an enrollment URL:

```
  Agent enrolled locally.

  Agent ID:    550e8400-e29b-41d4-a716-446655440000
  Agent Name:  prod-web-01
  Config:      /etc/apes/config.toml
  Key:         /etc/apes/agent.key
  Public Key:  ssh-ed25519 AAAA...

  Share this URL with your admin to complete enrollment:
  https://id.example.com/enroll?name=prod-web-01&key=ssh-ed25519%20AAAA...&id=550e8400-...

  The agent is ready to use once the admin approves.
```

### Step 2: Admin Approves (in the browser)

An admin opens the enrollment URL, logs into the IdP, and completes the form:

- **Name**, **Public Key**, and **Agent ID** are pre-filled from the URL
- **Owner** — email of the agent operator
- **Approver** — email of the person who will approve grant requests

On submit, the agent is registered and immediately active. No further steps needed on the server.

## Usage

```bash
# Run a command with grant-based approval
apes -- apt-get update

# Provide a reason (shown to the approver)
apes --reason "Deploy hotfix #123" -- systemctl restart nginx

# Override poll timeout (default: 300s)
apes --timeout 60 -- some-command

# Use a custom config path
apes --config /custom/config.toml -- some-command
```

The CLI blocks until the approver acts:

```
⏳ Waiting for approval… (grant 550e8400)
   Approve at: id.example.com
✅ Grant approved
```

## Configuration

`/etc/apes/config.toml`:

```toml
server_url = "https://id.example.com"
agent_id = "550e8400-e29b-41d4-a716-446655440000"
key_path = "/etc/apes/agent.key"
# target = "prod-web-01"    # default: hostname
# audit_log = "/var/log/apes/audit.log"

[poll]
interval_secs = 2
timeout_secs = 300
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command executed successfully |
| 1 | Config / HTTP / IO error |
| 2 | Auth failed / wrong key type |
| 3 | Grant denied |
| 4 | Poll timeout (no approval received) |
| 5 | JWT verification failed / cmd_hash mismatch |
| 126 | Exec / privilege error |
| 127 | Command not found |

## Security Model

- The binary runs with the **setuid bit** — it starts as root, reads the key file, then immediately drops to the invoking user's UID for all network I/O
- Privileges are only re-elevated after a valid, locally-verified AuthZ-JWT is received
- The JWT contains a `cmd_hash` (SHA-256 of the command) — if it doesn't match the locally computed hash, execution is aborted
- Environment is sanitized before exec: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES` etc. are removed, `PATH` is reset to system defaults
- All executions are logged to an audit log (JSONL)
