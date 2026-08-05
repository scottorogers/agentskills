#!/usr/bin/env bash
# Install the snmp-switch-monitoring skill for Claude Code.
#
#   ./install.sh              install for the current user (~/.claude/skills)
#   ./install.sh --project    install into ./.claude/skills for this repo only
#   ./install.sh --dir PATH   install into an explicit skills directory
#
# Only ever writes inside the chosen skills directory. Never uses sudo.

set -euo pipefail

SKILL_NAME="snmp-switch-monitoring"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_ROOT=""
RUN_TESTS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --project) TARGET_ROOT="$PWD/.claude/skills"; shift ;;
    --dir)     TARGET_ROOT="${2:?--dir needs a path}"; shift 2 ;;
    --no-test) RUN_TESTS=0; shift ;;
    -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET_ROOT" ] || TARGET_ROOT="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
TARGET="$TARGET_ROOT/$SKILL_NAME"

say()  { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- checks ---------------------------------------------------------------

[ -f "$SOURCE_DIR/SKILL.md" ] || fail "run this from the skill directory (SKILL.md not found next to install.sh)"

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  fail "need Python 3.9 or newer on PATH.
  macOS:   brew install python3
  Debian:  sudo apt install python3
  Windows: install from python.org, then use install.ps1 instead"
fi

say "Python:  $("$PYTHON" --version 2>&1) at $(command -v "$PYTHON")"
say "Source:  $SOURCE_DIR"
say "Target:  $TARGET"
say ""

# --- install --------------------------------------------------------------

if [ -e "$TARGET" ]; then
  # Back up *outside* the skills directory. A backup left alongside the skill
  # still contains a SKILL.md, so an agent scanning the directory would
  # discover it as a second, duplicate skill with the same name.
  BACKUP_ROOT="$(dirname "$TARGET_ROOT")/skill-backups"
  BACKUP="$BACKUP_ROOT/$SKILL_NAME-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_ROOT"
  say "An existing install is present. Moving it to:"
  say "  $BACKUP"
  mv "$TARGET" "$BACKUP"
fi

mkdir -p "$TARGET"
for item in SKILL.md README.md scripts references tests install.sh install.ps1; do
  [ -e "$SOURCE_DIR/$item" ] && cp -R "$SOURCE_DIR/$item" "$TARGET/"
done
find "$TARGET" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
chmod +x "$TARGET/scripts/"*.py 2>/dev/null || true

say "Installed $(find "$TARGET" -type f | wc -l | tr -d ' ') files."

# --- verify ---------------------------------------------------------------

if [ "$RUN_TESTS" -eq 1 ]; then
  say ""
  say "Running the test suite to confirm it works on this machine..."
  if (cd "$TARGET" && "$PYTHON" tests/test_netmon.py >/tmp/netmon-install-test.$$ 2>&1); then
    tail -3 /tmp/netmon-install-test.$$ | sed 's/^/  /'
    rm -f /tmp/netmon-install-test.$$
  else
    say "  tests FAILED -- output:"
    tail -20 /tmp/netmon-install-test.$$ | sed 's/^/  /'
    rm -f /tmp/netmon-install-test.$$
    fail "the skill was copied but its self-test did not pass; do not rely on it until this is resolved"
  fi
fi

# --- done -----------------------------------------------------------------

cat <<EOF

Done. Claude Code will pick the skill up on its next start.

Try it with no hardware:
  cd "$TARGET"
  $PYTHON scripts/mock_switch.py --port 11161 --flap 8 --errors 12 --saturate 3 &
  $PYTHON scripts/netmon.py check 127.0.0.1:11161

Or point it at a real switch:
  $PYTHON scripts/netmon.py check <switch-ip> -c <community-string>

In Claude Code, just ask in plain English:
  "check the switch at 192.168.1.254, the community string is public"
  "find every SNMP device on 10.0.0.0/24 and start monitoring them"

To uninstall:  rm -rf "$TARGET"
EOF
