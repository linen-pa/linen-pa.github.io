#!/bin/sh
# Linen — Pre-commit validation hook
# Checks JavaScript syntax before allowing the commit through.
# Install: bash scripts/install-hooks.sh

echo "Running pre-commit checks..."
echo ""

FAILED=0

check_js() {
    FILE=$1
    if [ -f "$FILE" ]; then
        printf "  %-35s" "$FILE"
        ERROR=$(node --check "$FILE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "OK"
        else
            echo "FAILED"
            echo ""
            echo "$ERROR" | sed 's/^/    /'
            echo ""
            FAILED=1
        fi
    fi
}

check_js "app.js"
check_js "service-worker.js"
check_js "vocabularyExpansion.js"

echo ""

if [ $FAILED -ne 0 ]; then
    echo "Commit blocked. Fix the errors above, then try again."
    echo ""
    exit 1
fi

echo "All checks passed."
exit 0
