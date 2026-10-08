#!/usr/bin/env bash
# SessionStart hook. Checks that the Dashlane CLI is installed and has the "mcp" command.
# Anything printed here is added to Claude's context, so it can explain the problem to the user.

if ! command -v dcli >/dev/null 2>&1; then
    echo "Dashlane plugin: the Dashlane CLI (dcli) is not installed, so the Dashlane vault tools will not work." \
        "Ask the user to install it: https://cli.dashlane.com/install"
    exit 0
fi

if ! dcli mcp --help >/dev/null 2>&1; then
    echo "Dashlane plugin: the installed Dashlane CLI is too old and has no \"mcp\" command." \
        "Ask the user to update it: https://cli.dashlane.com/install"
    exit 0
fi

exit 0
