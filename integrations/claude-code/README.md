# Dashlane plugin for Claude Code

Call APIs with tokens from your Dashlane vault. Claude never sees the secret: the Dashlane CLI adds it to the request.

## Install

1. Install the Dashlane CLI and log in once in a terminal: see [cli.dashlane.com/install](https://cli.dashlane.com/install), then run `dcli sync`.
2. In Claude Code:
   ```
   /plugin marketplace add Dashlane/dashlane-cli
   /plugin install dashlane@dashlane
   ```
3. Restart Claude Code. `/mcp` shows `dashlane`.

## What it adds

- **MCP server** `dashlane`: runs `dcli mcp` (search the vault, call APIs, sync, audit log).
- **Skill** `dashlane-vault`: tells Claude when and how to use the vault, and never to ask you to paste a secret.
- **Hooks**:
  - Blocks `dcli` commands in Claude's shell that can show secrets or change security settings (`dcli password`, `dcli secret`, `dcli read`, `dcli configure`…). Allowed: `sync`, `status`, `lock`, `mcp`, `help`. This is a guardrail, not a security boundary.
  - At startup, checks that `dcli` is installed and recent enough.

## Limits

- The hook needs `bash` (macOS, Linux, or Git Bash on Windows).
- Dev containers: `dcli` runs on your computer, not in the container. Use `dcli mcp --http` instead of this plugin (see the CLI docs).
