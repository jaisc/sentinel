#!/bin/bash
# Run every test that can run on this machine.
#   engine unit tests (any OS, Python 3.9+, offline)
#   extension runtime test (needs a Chromium/Brave binary + node 20+; set CHROME=...)
#   Swift build (macOS only)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
fail=0

echo "== engine unit tests"
(cd "$ROOT/engine" && "$PY" -m unittest discover -s tests 2>&1 >/dev/null | tail -n 3) || fail=1

echo "== extension JavaScript syntax"
for f in "$ROOT"/extension/*.js; do node --check "$f" || fail=1; done

if [ -z "${CHROME:-}" ] && [ "$(uname)" = "Darwin" ] && [ -x "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" ]; then
  CHROME="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
fi
if [ -n "${CHROME:-}" ]; then
  echo "== extension runtime test ($CHROME)"
  CHROME="$CHROME" node "$ROOT/scripts/test-extension.mjs" || fail=1
else
  echo "== extension runtime test skipped (set CHROME=/path/to/chromium-or-brave)"
fi

if [ "$(uname)" = "Darwin" ] && command -v swift >/dev/null; then
  echo "== swift build"
  (cd "$ROOT/macos" && swift build -c release 2>&1 | tail -n 5) || fail=1
else
  echo "== swift build skipped (macOS only)"
fi
exit $fail
