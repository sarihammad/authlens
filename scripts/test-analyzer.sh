#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ANALYZER_BIN="$ROOT_DIR/analyzer/build/authlens"
TRACE="$ROOT_DIR/samples/traces/sample-trace.json"
GOLDEN="$ROOT_DIR/samples/reports/sample-report.json"

if [[ ! -x "$ANALYZER_BIN" ]]; then
  echo "Analyzer binary not found at $ANALYZER_BIN" >&2
  exit 1
fi

TMP_FILE=$(mktemp)
"$ANALYZER_BIN" analyze "$TRACE" --out "$TMP_FILE" >/dev/null

diff -u "$GOLDEN" "$TMP_FILE"

rm -f "$TMP_FILE"
