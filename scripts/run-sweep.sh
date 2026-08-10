#!/bin/bash
# security-sweep weekly runner — invoked by launchd/cron or by hand.
# Deterministic pipeline: scan -> report HTML -> PDF -> email -> log line.
# Report-only: never modifies, moves, or deletes scanned files.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${SECURITY_SWEEP_CONFIG:-$HOME/.security-sweep/config.json}"
LOCK="/tmp/security-sweep.lock"

cfg() { python3 -c "import json,os,sys; v=json.load(open('$CONFIG')).get('$1',$2); print(os.path.expanduser(v) if isinstance(v,str) else v)"; }

STATE=$(cfg state_dir "'~/.security-sweep'")
REPORTS=$(cfg report_dir "'~/.security-sweep/reports'")
CHROME=$(cfg chrome_path "'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'")
LOG_FILE=$(cfg log_file "None")
EMAIL_ENABLED=$(cfg email_enabled "True")
LOG="$STATE/last-run.log"

mkdir -p "$STATE"
exec >"$LOG" 2>&1
echo "=== security-sweep $(date '+%Y-%m-%d %H:%M:%S') ==="

fail() {
  echo "FAIL: $1"
  command -v osascript >/dev/null && osascript -e "display notification \"$1\" with title \"Security Sweep FAILED\"" 2>/dev/null || true
  rmdir "$LOCK" 2>/dev/null || true
  exit 1
}

# Lock (stale-clean after 2h)
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +120 2>/dev/null)" ]; then
    rmdir "$LOCK" && mkdir "$LOCK" || fail "stale lock could not be cleared"
  else
    echo "already running — exiting"; exit 0
  fi
fi

# Pre-flight: name the missing dependency (loud fail)
command -v python3 >/dev/null        || fail "python3 missing"
[ -f "$CONFIG" ]                     || fail "config missing at $CONFIG — copy config.example.json there"
[ -f "$REPO/scripts/scan.py" ]       || fail "scan.py missing"
mkdir -p "$REPORTS"

# 1. Scan
python3 "$REPO/scripts/scan.py" || fail "scan.py exited $?"

# 2. Report HTML
HTML=$(python3 "$REPO/scripts/build_report.py" --out "$REPORTS") || fail "build_report.py exited $?"

# 3. PDF (optional — falls back to HTML-only if Chrome is absent)
PDF="${HTML%.html}.pdf"
if [ -x "$CHROME" ]; then
  rm -f "$PDF"
  "$CHROME" --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$PDF" "$HTML" || fail "chrome render failed"
  [ -s "$PDF" ] || fail "PDF empty or missing after render"
else
  echo "NOTE: Chrome not found at $CHROME — skipping PDF, report is HTML-only"
  PDF="$HTML"
fi

# 4. Counts for the email subject
read -r CRIT HIGH MED NEW <<<"$(python3 - "$STATE" <<'EOF'
import json, sys, pathlib
d = json.loads((pathlib.Path(sys.argv[1])/"findings.json").read_text())
c = d["counts"]
print(c["by_severity"].get("CRITICAL",0), c["by_severity"].get("HIGH",0), c["by_severity"].get("MEDIUM",0), c["new"])
EOF
)" || fail "counts extraction failed"

# 5. Email (macOS Mail.app; disable via config email_enabled: false)
if [ "$EMAIL_ENABLED" = "True" ] || [ "$EMAIL_ENABLED" = "true" ]; then
  bash "$REPO/scripts/send_email.sh" "$PDF" "$CRIT" "$HIGH" "$MED" "$NEW" || fail "email send failed"
else
  echo "email disabled — report at $PDF"
fi

# 6. Optional log line (set log_file in config)
if [ "$LOG_FILE" != "None" ] && [ -n "$LOG_FILE" ]; then
  echo "$(date '+%Y-%m-%d') | security-sweep | $CRIT critical / $HIGH high / $MED medium ($NEW new) | $(basename "$PDF")" >> "$LOG_FILE"
fi

command -v osascript >/dev/null && osascript -e "display notification \"$CRIT critical / $HIGH high ($NEW new)\" with title \"Security Sweep complete\"" 2>/dev/null || true
echo "OK $(date '+%H:%M:%S')"
rmdir "$LOCK"
