#!/bin/bash
# security-sweep email delivery — sends the weekly report PDF via Mail.app (macOS).
# Uses the already-authenticated Mail account: zero new stored credentials.
# This is deliberate — a headless-browser or API-based Gmail sender would itself
# store a live credential, which is the exposure class this tool exists to kill.
# Usage: send_email.sh <pdf-path> <critical> <high> <medium> <new>

set -euo pipefail

PDF="$1"; CRIT="${2:-?}"; HIGH="${3:-?}"; MED="${4:-?}"; NEW="${5:-?}"
CONFIG="${SECURITY_SWEEP_CONFIG:-$HOME/.security-sweep/config.json}"

TO=$(python3 -c "import json,sys; print(json.load(open('$CONFIG'))['recipient_email'])") \
  || { echo "FATAL: recipient_email missing from $CONFIG" >&2; exit 2; }
STATE=$(python3 -c "import json,os; print(os.path.expanduser(json.load(open('$CONFIG')).get('state_dir','~/.security-sweep')))")

if [ ! -f "$PDF" ]; then
  echo "FATAL: PDF not found: $PDF" >&2
  exit 2
fi
# Freshness: refuse to mail a stale artifact
if [ -n "$(find "$PDF" -mmin +120)" ]; then
  echo "FATAL: PDF older than 2h — refusing to send stale report" >&2
  exit 3
fi

SUBJECT="Weekly Security Sweep — ${CRIT} critical / ${HIGH} high (${NEW} new)"
BODY="Weekly secrets & PII sweep attached.

Open findings: ${CRIT} critical, ${HIGH} high, ${MED} medium (${NEW} new since last week).
Full detail: ${STATE}/findings.md

Report-only — nothing was moved, changed, or deleted."

osascript <<EOF
tell application "Mail"
    set theMessage to make new outgoing message with properties {subject:"$SUBJECT", content:"$BODY" & return & return, visible:false}
    tell theMessage
        make new to recipient at end of to recipients with properties {address:"$TO"}
        make new attachment with properties {file name:(POSIX file "$PDF")} at after the last paragraph of content
    end tell
    delay 3
    send theMessage
end tell
EOF
echo "sent: $SUBJECT -> $TO"
