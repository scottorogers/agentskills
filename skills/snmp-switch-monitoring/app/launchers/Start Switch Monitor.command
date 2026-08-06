#!/bin/bash
# macOS: double-click this file in Finder to start Switch Monitor.
cd "$(dirname "$0")" || exit 1

# Finder and the Dock launch processes with a minimal PATH that leaves out
# /opt/homebrew/bin and often /usr/local/bin, so a perfectly good Homebrew
# Python is invisible to `command -v`. Check the real locations directly.
CANDIDATES="
/opt/homebrew/bin/python3
/usr/local/bin/python3
/usr/bin/python3
python3
python
"

usable() {
    # /usr/bin/python3 on macOS is a stub: with the Xcode Command Line Tools
    # absent it pops a GUI installer dialog rather than running. Feeding it
    # /dev/null and checking the exit status stops that from being mistaken
    # for a working interpreter.
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
        </dev/null >/dev/null 2>&1
}

PY=""
for candidate in $CANDIDATES; do
    case "$candidate" in
        /*) [ -x "$candidate" ] || continue ;;
        *)  command -v "$candidate" >/dev/null 2>&1 || continue ;;
    esac
    if usable "$candidate"; then PY="$candidate"; break; fi
done

if [ -n "$PY" ]; then
    exec "$PY" netmon-app.py "$@"
fi

echo
echo "  Switch Monitor needs Python 3.9 or newer, and could not find it."
echo
if [ "$(uname -s)" = "Darwin" ]; then
    echo "  Recent macOS versions do not include Python. Install it either way:"
    echo
    echo "     https://www.python.org/downloads/     (simplest)"
    echo "     or in Terminal:  brew install python3"
    echo
    echo "  If Python IS installed and you still see this, start it from"
    echo "  Terminal instead:"
    echo
    echo "     cd \"$(pwd)\""
    echo "     python3 netmon-app.py"
else
    echo "  Install it from https://www.python.org/downloads/"
    echo "  or with your package manager, e.g.  sudo apt install python3"
fi
echo
read -r -p "  Press Return to close this window."
exit 1
