# openape-sudo — Agent Privilege Elevation via OpenApe Grants

Use `apes` to run commands with elevated (root) privileges. Instead of direct sudo access, agents authenticate through the OpenApe grant system: a human approves every privileged command before it executes.

## Prerequisites

Before using `apes`, verify the setup:

```bash
# Binary installed?
which apes

# Already enrolled? Check config exists and is valid
apes --help

# Full status check — loads config, verifies key match
apes --key ~/.apes/keys/deploy.key -- echo "ready"
```

Required files after enrollment:
- `/etc/apes/config.toml` — registered agents (public keys), poll settings (root-owned, `0644`)
- User's private key file (e.g. `~/.apes/keys/deploy.key`) — Ed25519 private key (user-owned, `0600`)

The `apes` binary is setuid-root (mode `4755`).

## Enrollment

Enrollment registers an agent keypair with the IdP. Multiple agents can be enrolled on the same machine.

```bash
sudo apes enroll \
  --server <OPENAPE_SERVER_URL> \
  --agent-email <EMAIL> \
  --agent-name <NAME> \
  --key <KEY_PATH>
```

| Flag | Required | Description |
|------|----------|-------------|
| `--server` | Yes | OpenApe IdP URL (e.g. `https://id.example.com`) |
| `--agent-email` | Yes | Agent identifier on the IdP |
| `--agent-name` | Yes | Agent display name |
| `--key` | Yes | Path to private key file (generated if it doesn't exist) |

**What happens:**
1. Drops privileges to real user
2. Generates Ed25519 keypair at `--key` path (if file doesn't exist) or loads existing key
3. Re-elevates to root, appends `[[agents]]` block to `/etc/apes/config.toml`
4. Prints an enrollment URL in the format:
   `<server>/enroll?email=<email>&name=<name>&key=<pubkey>&id=<agent_id>`

**After enrollment:** Share the printed URL with the admin. The agent is usable once the admin approves the enrollment on the IdP.

## Using Grants

Run a command with elevated privileges:

```bash
apes --key <KEY_PATH> [--reason <TEXT>] [--timeout <SECS>] -- <COMMAND> [ARGS...]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--key` | Yes | Path to agent's private key file |
| `--reason` | No | Human-readable justification for the request |
| `--timeout` | No | Poll timeout in seconds (overrides config, default: 300) |
| `--config` | No | Path to config file (default: `/etc/apes/config.toml`) |

**The `--` separator is mandatory** — everything after it is the command to execute.

### Examples

```bash
# Install a package
apes --key ~/.apes/keys/deploy.key --reason "dependency for build" -- apt-get install -y libssl-dev

# Restart a service
apes --key ~/.apes/keys/deploy.key --reason "deploy v2.3.1" -- systemctl restart myapp

# Quick file edit with shorter timeout
apes --key ~/.apes/keys/admin.key --timeout 60 -- cp /tmp/config.new /etc/myapp/config.toml
```

### What happens under the hood

1. **Load config** — reads `/etc/apes/config.toml` (as root)
2. **Drop privileges** — to real user's UID
3. **Load key** — reads private key from `--key` path (as the real user)
4. **Match agent** — derives public key, matches against registered agents in config
5. **Derive agent_id** — `sha256(public_key)` as 64-char hex
6. **Compute cmd_hash** — SHA-256 of the command + arguments
7. **Authenticate** — challenge-response against the matched agent's IdP
8. **Create grant** — sends command, cmd_hash, target hostname, and reason to the IdP
9. **Poll for approval** — polls every 2s (configurable), prints `waiting for approval…`
10. **Get authorization token** — fetches AuthZ-JWT from the IdP after approval
11. **Verify JWT** — checks signature and confirms cmd_hash matches locally
12. **Elevate + execute** — regains root, sanitizes environment, writes audit log, `exec`s the command

The command replaces the `apes` process (via `exec`), so the exit code is the command's exit code on success.

## Rules for Agents

1. **Never use `sudo` directly** — always use `apes` for privilege elevation
2. **Always provide `--key`** — specify which agent key to use
3. **Always provide `--reason`** — explain why the command needs root
4. **Respect denials** — if a grant is denied (exit code 3), do not retry the same command. Inform the user and ask for guidance
5. **Handle timeouts gracefully** — if approval times out (exit code 4), tell the user no approver responded and suggest next steps
6. **One command per grant** — each `apes` invocation creates a separate grant. Do not chain commands with `&&` or `;` inside a single `apes` call; use separate invocations
7. **Do not manage keys manually** — use enrollment to generate keys; do not copy or modify key files

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Config file not found: /etc/apes/config.toml` | Not enrolled or wrong path | Run `sudo apes enroll ...` or use `--config` |
| `--key <path> is required` | Missing `--key` flag | Add `--key` with path to your agent private key |
| `Key does not match any registered agent` | Key not enrolled in config | Enroll this key with `sudo apes enroll --key <path> ...` |
| `Legacy config format detected` | Old single-agent config | Migrate to `[[agents]]` format (see README.md) |
| `Wrong key type: expected Ed25519` | Key file contains non-Ed25519 key | Re-enroll with an Ed25519 key |
| `Auth failed` | Agent not approved on IdP, or key mismatch | Check enrollment status with admin |
| `Grant denied by <user>` | Human rejected the request | Do not retry — ask the user for guidance |
| `Timed out after <N>s` | No approver responded | Increase `--timeout` or contact an approver |
| `cmd_hash mismatch` | Server-side command tampering detected | Indicates a serious integrity issue — report to admin |
| `HTTP error` / connection errors | Network or IdP unreachable | Check connectivity to the server URL in config |
| `Exec failed` / `Command not found` | Target command missing or not executable | Verify the command exists and is in PATH |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran and exited 0) |
| 1 | Config error, HTTP error, I/O error, JSON parse error, no matching agent, or legacy config |
| 2 | Authentication failed or wrong key type |
| 3 | Grant denied |
| 4 | Grant timed out (no approval within timeout) |
| 5 | JWT verification failed, cmd_hash mismatch, or public key mismatch |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

On success, the exit code is that of the executed command (apes replaces itself via `exec`).

## Config Reference

`/etc/apes/config.toml`:

```toml
# target = "my-server"          # Override hostname
# audit_log = "/var/log/apes/audit.log"

[poll]
interval_secs = 2
timeout_secs = 300

[tls]
# ca_bundle = "/path/to/ca.pem"  # Custom CA for IdP connection

[[agents]]
name = "web-deploy"
public_key = "ssh-ed25519 AAAA..."
server_url = "https://id.example.com"

[[agents]]
name = "system-admin"
public_key = "ssh-ed25519 BBBB..."
server_url = "https://id2.example.com"
```

## Audit Log

All grant outcomes are logged to `/var/log/apes/audit.log` (JSONL format, configurable via `audit_log` in config). Entries include: user, command, cmd_hash, grant ID, agent_id, outcome (approved/denied/timeout/error).
