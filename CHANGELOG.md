# Changelog

All notable changes to `escapes` are documented here.

## [0.5.0] — 2026-04-23

### Added

- **`escapes trust` subcommand** — configure the trust boundary (allowed issuers + approvers) without hand-editing TOML. Validates the IdP by probing `/.well-known/openid-configuration` + the JWKS before writing `/etc/openape/config.toml` with mode `0600`.
  - `--idp <url>` and `--approvers <csv>` for scriptable setup.
  - Falls back to interactive prompts on a TTY when flags are omitted; errors cleanly in non-TTY context.
  - Merges with existing config by default; `--replace` overwrites both lists.
  - `--skip-validation` skips the network probes for airgapped bootstrap.
- **`escapes update` subcommand** — the new canonical form of the self-update command. The old `--update` flag still works but prints a deprecation notice.

### Changed

- CLI now uses a subcommand tree. Existing usage (`escapes --grant <jwt> -- <cmd>`) is unchanged — the grant-exec path is the default action when no subcommand is given.
- Closes [#8](https://github.com/openape-ai/escapes/issues/8).

## [0.4.0]

Previous release — see git history.
