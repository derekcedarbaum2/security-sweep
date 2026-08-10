#!/bin/bash
# security-sweep installer.
#   1. Seeds ~/.security-sweep/config.json from config.example.json (if absent)
#   2. macOS: installs a launchd job (default: Mondays 06:37 local)
#      Linux:  prints the crontab line to add
#   3. Claude Code users: optionally installs the skill into ~/.claude/skills
#
# Usage: ./scripts/install.sh [--hour H] [--minute M] [--weekday 1-7]

set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOUR=6; MINUTE=37; WEEKDAY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --hour) HOUR="$2"; shift 2;;
    --minute) MINUTE="$2"; shift 2;;
    --weekday) WEEKDAY="$2"; shift 2;;
    *) echo "unknown flag: $1"; exit 1;;
  esac
done

# 1. Config
CONFIG_DIR="$HOME/.security-sweep"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cp "$REPO/config.example.json" "$CONFIG_DIR/config.json"
  echo "Seeded $CONFIG_DIR/config.json — EDIT IT NOW: set your email and surfaces."
else
  echo "Config already exists at $CONFIG_DIR/config.json — leaving it alone."
fi

# 2. Scheduler
if [ "$(uname)" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/com.user.security-sweep.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.security-sweep</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$REPO/scripts/run-sweep.sh</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>$WEEKDAY</integer>
        <key>Hour</key>
        <integer>$HOUR</integer>
        <key>Minute</key>
        <integer>$MINUTE</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/com.user.security-sweep.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/com.user.security-sweep.err</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "launchd job installed: weekday $WEEKDAY at $HOUR:$(printf '%02d' "$MINUTE") (com.user.security-sweep)"
else
  echo "Linux detected. Add this line via 'crontab -e' (Monday $HOUR:$MINUTE):"
  echo "  $MINUTE $HOUR * * $WEEKDAY /bin/bash $REPO/scripts/run-sweep.sh"
  echo "Note: send_email.sh uses macOS Mail.app — set email_enabled:false in config, or swap in msmtp/mailx."
fi

# 3. Claude Code skill (optional)
if [ -d "$HOME/.claude/skills" ]; then
  SKILL_DIR="$HOME/.claude/skills/security-sweep"
  if [ ! -d "$SKILL_DIR" ]; then
    mkdir -p "$SKILL_DIR"
    sed "s|__REPO__|$REPO|g" "$REPO/skill/SKILL.md" > "$SKILL_DIR/SKILL.md"
    echo "Claude Code skill installed: /security-sweep"
  else
    echo "Claude Code skill dir already exists at $SKILL_DIR — not overwriting."
  fi
fi

echo
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/config.json (email, surfaces)"
echo "  2. Test run: bash $REPO/scripts/run-sweep.sh && cat ~/.security-sweep/last-run.log"
echo "  3. Read docs/walkthrough.md for the one-item-at-a-time remediation session"
