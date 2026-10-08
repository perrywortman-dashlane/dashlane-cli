#!/usr/bin/env bash
# PreToolUse hook for the Bash tool.
# Blocks dcli commands that can print vault data or change Dashlane security settings,
# so the agent uses the Dashlane MCP tools instead (they never show credentials).
# This is a guardrail, not a security boundary: an agent with a shell may find other ways to run dcli.

input="$(cat)"

# dcli subcommands an agent may run. Everything else is blocked.
allowed=" sync s status lock mcp help "

# Find each "dcli <subcommand>" (optional flags before it, optional quotes around it), also when dcli is called by path.
subcommands="$(printf '%s' "$input" \
    | grep -oE '(^|[^A-Za-z0-9_.-])dcli([[:space:]]+-{1,2}[A-Za-z][A-Za-z-]*)*[[:space:]]+[\\"'"'"']*[A-Za-z][A-Za-z-]*' \
    | awk '{ print $NF }' \
    | tr -d '\\"'"'"'')"

for sub in $subcommands; do
    case "$allowed" in
        *" $sub "*) ;;
        *)
            echo "Blocked: \"dcli $sub\" can show vault data or change Dashlane security settings, so AI agents cannot run it." \
                "Use the Dashlane MCP tools instead (search_vault, call_api)." \
                "If the user really needs this command, ask them to run it in their own terminal." >&2
            exit 2
            ;;
    esac
done

exit 0
