# apes — Privilege Elevation via OpenApe Grants

`apes` is a setuid-root binary that replaces traditional `sudo` with a grant-based approval workflow. Instead of a password, each privileged command requires real-time approval from an admin through an [OpenApe](https://docs.openape.at) Identity Provider (IdP).

```
User runs:  apes --key ~/.apes/keys/deploy.key -- systemctl restart nginx
                │
                ▼
         ┌─────────────┐     challenge/response      ┌────────────────┐
         │  apes agent  │ ◄─────────────────────────►│  OpenApe IdP   │
         │  (setuid)    │ ── create grant ──────────►│  (nuxt-grants) │
         │              │ ── poll status ───────────►│                │
         │              │ ◄── approved + JWT ────────│                │
         └──────┬───────┘                            └───────┬────────┘
                │ verify JWT, elevate, exec                  │
                ▼                                     Admin approves
         Command runs as root                         in browser UI
```

**Key properties:**

- **Multi-agent support** — multiple agents per machine, each with their own keypair and IdP
- Ed25519 challenge-response authentication (no passwords stored)
- Every command is individually approved or denied by an admin
- JWT-based authorization with cmd_hash integrity check
- **User-owned keys** — private keys belong to the user, not root
- Privileges are dropped *before* key loading; re-elevated only after verification
- Environment is sanitized before exec (LD_PRELOAD, PATH, etc.)
- Full audit log in JSONL format

### Security Model

Each agent is an Ed25519 keypair owned by the user who operates it. The user provides their key via `--key <path>` — possessing the key IS the authorization. Agent identity is derived at runtime: `agent_id = sha256(public_key)`.

The security boundaries are:

- **Enrollment requires human approval** — the agent's public key is registered in the config and an enrollment URL is generated, but an admin must confirm it on the IdP before the agent becomes active
- **Every privileged action requires a human-approved grant** — there is no way for the agent to approve its own requests
- **Zero administrative access to the IdP** — `apes` is a client that authenticates and requests grants; it cannot create users, manage agents, or modify the IdP configuration
- **User-owned keys** — private keys are stored by the user (e.g. `~/.apes/keys/`), not in root-owned paths. Privilege drop happens before key loading
- **Config is root-owned** — `/etc/apes/config.toml` lists registered agents (public keys only); only root can modify it

## Prerequisites

- **Rust toolchain** (stable, 1.70+) — install via [rustup](https://rustup.rs)
- **A running OpenApe IdP** with the `nuxt-grants` module — see [docs.openape.at](https://docs.openape.at)
- **Linux** (setuid + execvp; macOS works for development but is not recommended for production)

## Build

```bash
cargo build --release
```

The binary is at `target/release/apes`.

## Install

```bash
sudo make install
```

This installs `apes` to `/usr/local/bin/apes` with the setuid bit set (`mode 4755`, owner `root`). The setuid bit is required so that `apes` can elevate privileges after grant approval.

To install to a different prefix:

```bash
sudo make install PREFIX=/opt
```

### Manual install (without Make)

```bash
sudo install -m 4755 -o root target/release/apes /usr/local/bin/apes
```

## Enrollment

Enrollment registers an agent on this machine. Each agent is a keypair + config entry. You can enroll multiple agents on the same machine.

```bash
sudo apes enroll \
  --server https://id.example.com \
  --agent-email server01@example.com \
  --agent-name web-deploy \
  --key ~/.apes/keys/deploy.key
```

### What happens

1. `apes` drops privileges to the real user
2. If the key file doesn't exist: generates an Ed25519 keypair and writes it to the given path (as the user)
3. If the key file exists: loads it
4. Derives the public key from the private key
5. Re-elevates to root and appends an `[[agents]]` entry to `/etc/apes/config.toml`
6. Drops back to the real user
7. The output includes an enrollment URL:

```
  Agent enrolled locally.

  Agent Name:  web-deploy
  Agent ID:    a1b2c3d4e5f6...  (sha256 of public key)
  Config:      /etc/apes/config.toml
  Key:         /home/user/.apes/keys/deploy.key
  Public Key:  ssh-ed25519 AAAA...

  Share this URL with your admin to complete enrollment:
  https://id.example.com/enroll?email=server01@example.com&name=web-deploy&key=ssh-ed25519%20AAAA...&id=a1b2c3d4...

  The agent is ready to use once the admin approves.
```

8. Copy the enrollment URL and open it in a browser
9. An admin logs into the IdP and confirms the agent
10. The agent is now active and can request grants

### Enrolling multiple agents

```bash
# Web deployment agent
sudo apes enroll --server https://id.example.com --agent-email deploy@example.com --agent-name web-deploy --key ~/.apes/keys/deploy.key

# System admin agent (can point to a different IdP)
sudo apes enroll --server https://id2.example.com --agent-email admin@example.com --agent-name system-admin --key ~/.apes/keys/admin.key
```

Each enrollment appends a new `[[agents]]` block to the config.

## Usage

Run any command with privilege elevation:

```bash
apes --key ~/.apes/keys/deploy.key -- systemctl restart nginx
```

With a reason (visible to the admin in the approval UI):

```bash
apes --key ~/.apes/keys/deploy.key --reason "deploy v2.1" -- systemctl restart app
```

Override the poll timeout (in seconds):

```bash
apes --key ~/.apes/keys/deploy.key --timeout 60 -- apt update
```

Use a custom config file:

```bash
apes --config /path/to/config.toml --key ~/.apes/keys/deploy.key -- whoami
```

### What happens when you run a command

1. `apes` loads the config (as root — `/etc/apes/config.toml` is root-owned)
2. **Drops privileges** to the real user's UID
3. Loads the private key from `--key` (as the real user — key is user-owned)
4. Derives the public key from the private key
5. Matches the public key against registered agents in the config
6. If no match: error `NoMatchingAgent` (exit code 1)
7. Derives `agent_id = sha256(public_key)`
8. Computes a SHA-256 hash of the command
9. Authenticates with the matched agent's IdP via Ed25519 challenge-response
10. Creates a grant request (includes command, cmd_hash, target, optional reason)
11. Polls the IdP for approval:
    ```
    waiting for approval… (grant a1b2c3d4)
       approve at: id.example.com
    ```
12. On approval: receives a JWT containing the cmd_hash
13. Verifies the JWT locally and checks that the cmd_hash matches
14. **Re-elevates** to root
15. Sanitizes the environment (removes `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.; resets `PATH`)
16. Writes an audit log entry
17. Replaces the process with the command via `execvp`

If denied: `apes` prints `denied by <admin>` and exits with code 3.
If no response within the timeout: prints `timed out after <N>s` and exits with code 4.

## Configuration Reference

After enrollment, the config lives at `/etc/apes/config.toml` (permissions `0644`, owned by root).

```toml
# Optional — override hostname as the target identifier
# target = "server01"

# Optional — custom audit log path (default: /var/log/apes/audit.log)
# audit_log = "/var/log/apes/audit.log"

[poll]
# How often to check for grant approval (default: 2)
interval_secs = 2
# Maximum time to wait for approval (default: 300)
timeout_secs = 300

[tls]
# Custom CA bundle for self-signed certificates
# ca_bundle = "/etc/apes/ca.pem"

[[agents]]
name = "web-deploy"
public_key = "ssh-ed25519 AAAA..."
server_url = "https://id.example.com"

[[agents]]
name = "system-admin"
public_key = "ssh-ed25519 BBBB..."
server_url = "https://id2.example.com"
```

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `target` | no | hostname | Machine identifier shown in grant requests |
| `audit_log` | no | `/var/log/apes/audit.log` | Path to the JSONL audit log |
| `poll.interval_secs` | no | `2` | Poll interval in seconds |
| `poll.timeout_secs` | no | `300` | Poll timeout in seconds (5 minutes) |
| `tls.ca_bundle` | no | system default | Custom CA bundle path |
| `agents[].name` | yes | — | Agent display name |
| `agents[].public_key` | yes | — | Agent's public key (OpenSSH format) |
| `agents[].server_url` | yes | — | OpenApe IdP URL for this agent |

### Migrating from single-agent format

If you have an old config with top-level `server_url`, `agent_id`, and `key_path`, `apes` will detect it and print a `LegacyConfig` error with migration instructions. Convert your config to the new format:

**Old format:**
```toml
server_url = "https://id.example.com"
agent_id = "a1b2c3d4-..."
key_path = "/etc/apes/agent.key"
```

**New format:**
```toml
[[agents]]
name = "my-agent"
public_key = "ssh-ed25519 AAAA..."  # extract from old key file
server_url = "https://id.example.com"
```

## Connecting to a Local vs Remote IdP

For **development**, point at your local instance:

```bash
sudo apes enroll --server http://localhost:3000 --agent-email dev@localhost --agent-name dev --key ~/.apes/keys/dev.key
```

For **production**, use the HTTPS URL of your IdP:

```bash
sudo apes enroll --server https://id.example.com --agent-email server01@example.com --agent-name prod-deploy --key ~/.apes/keys/deploy.key
```

If your IdP uses a **self-signed certificate**, add the CA bundle to the config after enrollment:

```toml
[tls]
ca_bundle = "/etc/apes/ca.pem"
```

For IdP setup instructions, see [docs.openape.at](https://docs.openape.at).

## Audit Log

Every command execution, denial, timeout, and error is logged in JSONL format. Default location: `/var/log/apes/audit.log` (configurable via `audit_log` in config).

The directory is created automatically if it doesn't exist. The log is append-only. If writing fails, a warning is printed to stderr but the command still runs.

### Event types

**`run`** — command approved and executed:
```json
{"ts":"2026-01-15T10:30:00Z","event":"run","real_uid":1000,"command":["systemctl","restart","nginx"],"cmd_hash":"ab12...","grant_id":"...","grant_type":"once","agent_id":"sha256-derived-id","decided_by":"admin@example.com","target":"server01","cwd":"/home/user"}
```

**`denied`** — grant denied by admin:
```json
{"ts":"...","event":"denied","real_uid":1000,"command":["rm","-rf","/"],"cmd_hash":"...","grant_id":"...","agent_id":"...","decided_by":"admin@example.com","target":"server01"}
```

**`timeout`** — no response within timeout:
```json
{"ts":"...","event":"timeout","real_uid":1000,"command":["apt","update"],"cmd_hash":"...","grant_id":"...","agent_id":"...","target":"server01","timeout_secs":300}
```

**`error`** — unexpected failure:
```json
{"ts":"...","event":"error","real_uid":1000,"command":["..."],"agent_id":"...","target":"server01","message":"..."}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran) |
| 1 | Configuration error, HTTP error, I/O error, JSON parse error, no matching agent, or legacy config |
| 2 | Authentication failure or wrong key type |
| 3 | Grant denied |
| 4 | Grant timed out (no approval within timeout) |
| 5 | JWT verification failed, cmd_hash mismatch, or public key mismatch |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

## Uninstall

```bash
sudo make uninstall
```

This removes `/usr/local/bin/apes`. To also remove the agent config:

```bash
sudo rm -rf /etc/apes
```

## License

AGPL-3.0-or-later
