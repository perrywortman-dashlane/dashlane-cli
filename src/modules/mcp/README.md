# MCP Vault Server

The vault MCP server acts as a credential broker for AI agents. See the [full user documentation](https://cli.dashlane.com/integrations/vault-mcp) for setup and usage.

## Module structure

| Module                | Purpose                                          |
| --------------------- | ------------------------------------------------ |
| `sessionTokens.ts`    | AES-256-GCM encrypt/decrypt for opaque vault IDs |
| `urlValidation.ts`    | SSRF and DNS rebinding protection                |
| `authDetection.ts`    | Basic vs Bearer auto-detection                   |
| `credentialPolicy.ts` | Per-secret website rules (blocked by default)    |
| `vaultSearch.ts`      | Vault query, decrypt, and field allowlisting     |
| `apiCall.ts`          | HTTP execution, response processing, truncation  |
| `auditLog.ts`         | JSON Lines audit logging                         |
| `index.ts`            | Barrel export                                    |

The orchestrator lives at `src/command-handlers/vaultMcp.ts` — it handles MCP server setup, tool registration, and rate limit state.

## Developing locally

Build and connect to an MCP client without affecting your installed `dcli`:

```sh
# Build
yarn run build

# Add your local build to Claude Code (it starts the MCP server automatically)
claude mcp add --transport stdio dashlane-vault -- node /absolute/path/to/dashlane-cli/dist/index.cjs mcp
```

For watch mode during development:

```sh
yarn run watch          # Terminal 1 — recompiles on changes
node build/index.js mcp # Terminal 2 — run the server directly for debugging
```

Running the server directly with `node dist/index.cjs mcp` is useful for debugging but won't connect to an agent — use `claude mcp add` to wire it up.

## Running tests

Run all tests (includes crypto and MCP):

```sh
yarn test
```

Run only MCP tests:

```sh
yarn mocha src/modules/mcp/test.ts
```

Tests are in `src/modules/mcp/test.ts` and cover session tokens, URL validation, auth detection, response processing, and audit logging.
