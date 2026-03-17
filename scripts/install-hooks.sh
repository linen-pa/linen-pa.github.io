#!/bin/sh
# Linen — Install git hooks
# Run once after cloning: bash scripts/install-hooks.sh

HOOK_DIR=".git/hooks"
SCRIPT_DIR="scripts"

if [ ! -d "$HOOK_DIR" ]; then
    echo "Error: .git/hooks not found. Run this from the repo root."
    exit 1
fi

cp "$SCRIPT_DIR/pre-commit.sh" "$HOOK_DIR/pre-commit"
chmod +x "$HOOK_DIR/pre-commit"

echo "Pre-commit hook installed."
echo "JavaScript syntax will now be checked before every commit."
