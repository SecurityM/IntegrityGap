#!/bin/bash
# IntegrityGap v2.1.0 - Test Fixtures Builder
# Builds the three ELF test binaries needed by run_tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="/tmp"

echo "[Fixtures] Building test ELF binaries..."

gcc -O0 -o "$TARGET_DIR/test_simple.elf" "$SCRIPT_DIR/test_simple.c" -Wall -Wextra 2>/dev/null
echo "[Fixtures]   -> /tmp/test_simple.elf"

gcc -O0 -o "$TARGET_DIR/test_oob.elf" "$SCRIPT_DIR/test_oob.c" -Wall -Wextra 2>/dev/null
echo "[Fixtures]   -> /tmp/test_oob.elf"

gcc -O0 -o "$TARGET_DIR/test_crypto.elf" "$SCRIPT_DIR/test_crypto.c" -Wall -Wextra 2>/dev/null
echo "[Fixtures]   -> /tmp/test_crypto.elf"

echo "[Fixtures] All test binaries built successfully."
