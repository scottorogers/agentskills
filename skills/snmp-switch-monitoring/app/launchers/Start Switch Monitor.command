#!/bin/bash
# macOS: double-click this file in Finder to start Switch Monitor.
cd "$(dirname "$0")" || exit 1

for PY in python3 python; do
  if command -v "$PY" >/dev/null 2>&1 && \
     "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    exec "$PY" netmon-app.py "$@"
  fi
done

echo
echo "Python 3.9 or newer is required, and was not found."
echo
echo "Install it from https://www.python.org/downloads/ and try again."
echo "(On macOS you can also run:  brew install python3)"
echo
read -r -p "Press Return to close this window."
exit 1
