#!/usr/bin/env python3
"""
security-sweep report builder — findings.json → self-contained HTML.

Deterministic: no LLM in the loop. Render to PDF with headless Chrome
(run-sweep.sh does this) or just open the HTML.

Usage: build_report.py [--out DIR]
Writes: <out>/YYYY-MM-DD-security-sweep.html
"""

import argparse
import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path

HOME = Path.home()
CFG_PATH = Path(os.environ.get("SECURITY_SWEEP_CONFIG",
                               HOME / ".security-sweep/config.json"))
CFG = json.loads(CFG_PATH.read_text()) if CFG_PATH.exists() else {}
STATE = Path(os.path.expanduser(CFG.get("state_dir", "~/.security-sweep")))
FINDINGS = STATE / "findings.json"
BRAND_LINE = CFG.get("report_brand_line", "PERSONAL SECURITY SWEEP")

# Proposed disposition per rule family. Proposals only — the sweep never acts.
PROPOSALS = {
    "identity-doc": ("Quarantine", "Move into an encrypted container (encrypted disk image, Cryptomator vault, or VeraCrypt volume); delete the plaintext copy after verifying the encrypted copy opens."),
    "tax-doc": ("Quarantine", "Same encrypted container. Keep the last 7 years; delete anything older you'll never need — and empty the cloud trash."),
    "financial-doc": ("Quarantine", "Encrypted container with the tax docs."),
    "medical-doc": ("Quarantine", "Encrypted container, medical subfolder. Reference by path from notes instead of storing copies in agent-indexed folders."),
    "slack-token": ("Rotate + relocate", "Invalidate the session (sign out other sessions), re-extract, store in the OS keychain, inject via a wrapper script at launch."),
    "firecrawl-key": ("Rotate + relocate", "Rotate in the dashboard, store in the OS keychain, wrapper-inject at launch."),
    "google-api-key": ("Rotate", "Rotate in Google Cloud console; scrub whatever captured it. (If it appears in process dumps near DriveFS crashpad args, it's Google's own baked-in app key — allowlist it.)"),
    "openai-key": ("Rotate + relocate", "Rotate and move to the OS keychain."),
    "anthropic-key": ("Rotate + relocate", "Rotate and move to the OS keychain."),
    "aws-access-key": ("Rotate + relocate", "Rotate in IAM; move to the OS keychain or aws-vault."),
    "github-token": ("Rotate + relocate", "Rotate; use gh auth or the OS keychain."),
    "stripe-key": ("Rotate + relocate", "Rotate in the Stripe dashboard; OS keychain."),
    "linear-key": ("Rotate + relocate", "Rotate; OS keychain."),
    "generic-assignment": ("Review", "Confirm whether it's a live credential; if live, rotate and relocate to the OS keychain; if dead, delete the line."),
    "private-key-block": ("Relocate", "Private keys belong in ~/.ssh with a passphrase or in the OS keychain — never in synced storage."),
    "ssh-private": ("Verify", "Confirm passphrase protection (ssh-keygen -y will prompt if protected)."),
    "keyfile": ("Review", "Confirm the key is needed; relocate out of synced storage."),
    "env-file": ("Relocate", "Move values to the OS keychain or password-manager CLI; keep only a .env.example with placeholders."),
    "credential-file": ("Review", "Open it; if it holds real credentials, migrate to the password manager and delete."),
    "ssn": ("Redact/quarantine", "Remove the SSN from the text file; if the document must keep it, move the document to the encrypted container."),
    "ssn-formatted": ("Review", "Verify whether it's a real SSN or a placeholder; redact if real."),
    "credit-card": ("Redact", "Remove the card number; card numbers should live only in the password manager."),
    "routing-number": ("Redact", "Replace with a last-4 reference; full numbers live in the password manager."),
    "bank-account": ("Redact", "Replace with a last-4 reference; full numbers live in the password manager."),
    "dob": ("Accept or redact", "DOBs in medical/health docs are expected; quarantine the containing doc if it's identity-grade."),
    "passport": ("Quarantine", "Encrypted container."),
    "drivers-license": ("Quarantine", "Encrypted container."),
    "ein": ("Accept", "EINs are semi-public; low risk. No action unless paired with bank details."),
    "jwt": ("Expire-check", "Old JWTs from email links are usually expired; spot-check one, then redact or accept."),
}

SEV_COLOR = {"CRITICAL": "#9a3434", "HIGH": "#B8860B", "MEDIUM": "#505a70", "INFO": "#666666"}


def esc(s):
    return html.escape(str(s))


def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def findings_rows(fs, new_ids):
    rows = []
    for f in fs:
        badge = '<span class="new-badge">NEW</span> ' if f["id"] in new_ids else ""
        prop = PROPOSALS.get(f["rule"], ("Review", ""))[0]
        rows.append(
            f'<tr><td><span class="sev" style="color:{SEV_COLOR[f["severity"]]}">{f["severity"]}</span></td>'
            f'<td class="mono">{esc(f["surface"])}</td>'
            f'<td class="path">{badge}{esc(f["path"])}</td>'
            f'<td class="mono">{esc(f["rule"])}</td>'
            f'<td class="mono">{esc(f["match"])}{"" if f.get("count", 1) == 1 else " x" + str(f["count"])}</td>'
            f'<td>{prop}</td></tr>'
        )
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(STATE))
    args = ap.parse_args()

    if not FINDINGS.exists():
        print("FATAL: findings.json missing — run scan.py first", file=sys.stderr)
        sys.exit(2)
    data = json.loads(FINDINGS.read_text())
    age_hours = (datetime.now().timestamp() - datetime.fromisoformat(data["generated"]).timestamp()) / 3600
    if age_hours > 24:
        print(f"FATAL: findings.json is {age_hours:.0f}h old — stale input refused", file=sys.stderr)
        sys.exit(3)

    fs = data["findings"]
    counts = data["counts"]
    stats = data["stats"]
    new_ids = set()
    date_str = datetime.now().strftime("%Y-%m-%d")
    date_h = datetime.now().strftime("%B %d, %Y")

    crit_high = [f for f in fs if f["severity"] in ("CRITICAL", "HIGH")]
    med = [f for f in fs if f["severity"] == "MEDIUM"]

    files_total = sum(s.get("files", 0) for s in stats.values())

    # Group MEDIUM by rule for a compact digest instead of a 60-row table
    med_groups = {}
    for f in med:
        med_groups.setdefault(f["rule"], []).append(f)

    sheets = []

    # ---- Sheet 1: cover + summary
    sev_cards = "".join(
        f'<div class="stat-card"><div class="stat-num" style="color:{SEV_COLOR[s]}">{counts["by_severity"].get(s,0)}</div>'
        f'<div class="stat-label">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM")
    )
    surface_rows = "".join(
        f'<tr><td class="mono">{esc(n)}</td><td>{s.get("files",0):,}</td><td>{s.get("content_scanned",0):,}</td>'
        f'<td>{s.get("dataless",0)}</td></tr>'
        for n, s in stats.items()
    )
    sheets.append(f"""
<div class="sheet">
  <div class="stripe"></div>
  <div class="brand-line">{esc(BRAND_LINE)}</div>
  <h1>Weekly Security Sweep</h1>
  <div class="subtitle">Secrets &amp; PII exposure across storage surfaces and agent-facing configs</div>
  <div class="meta">{date_h} · REPORT-ONLY — NO FILES WERE MODIFIED, MOVED, OR DELETED</div>

  <div class="stat-row">{sev_cards}
    <div class="stat-card"><div class="stat-num">{files_total:,}</div><div class="stat-label">FILES SCANNED</div></div>
  </div>

  <h2>Coverage</h2>
  <table><thead><tr><th>Surface</th><th>Files</th><th>Content-scanned</th><th>Cloud placeholders skipped</th></tr></thead>
  <tbody>{surface_rows}</tbody></table>
  <p class="note">Placeholders are cloud-only files whose download the scanner refuses to force. Binary formats
  (PDF, images) are checked by filename, not content. Scan duration: {data["duration_sec"]}s.
  Allowlisted (accepted-risk) findings suppressed: {counts["suppressed_allowlist"]}.</p>
</div>""")

    # ---- Findings sheets (CRITICAL + HIGH), 16 rows per sheet
    rows = findings_rows(crit_high, new_ids)
    for i, batch in enumerate(chunk(rows, 16)):
        sheets.append(f"""
<div class="sheet">
  <h2>Critical &amp; High findings{" (cont.)" if i else ""}</h2>
  <table class="findings"><thead><tr><th>Sev</th><th>Surface</th><th>Path</th><th>Rule</th><th>Match (masked)</th><th>Proposed</th></tr></thead>
  <tbody>{''.join(batch)}</tbody></table>
</div>""")

    # ---- MEDIUM digest sheet
    med_rows = "".join(
        f'<tr><td class="mono">{esc(rule)}</td><td>{len(items)}</td>'
        f'<td class="path">{esc(items[0]["path"])}{f"<br><span class=note>… and {len(items)-1} more</span>" if len(items) > 1 else ""}</td>'
        f'<td>{PROPOSALS.get(rule, ("Review",""))[0]}</td></tr>'
        for rule, items in sorted(med_groups.items(), key=lambda kv: -len(kv[1]))
    )
    sheets.append(f"""
<div class="sheet">
  <h2>Medium findings — grouped</h2>
  <table><thead><tr><th>Rule</th><th>Count</th><th>Example path</th><th>Proposed</th></tr></thead>
  <tbody>{med_rows}</tbody></table>
  <p class="note">Full detail for every finding: <span class="mono">{esc(str(STATE))}/findings.md</span></p>
</div>""")

    # ---- Remediation + strategy sheets (curated, stable across weeks)
    sheets.append("""
<div class="sheet">
  <h2>Standing remediation plan</h2>
  <p>Every action below is a proposal. Nothing runs without your explicit go-ahead, and the sweep itself never
  touches a file. Work the phases in order — each one removes a whole class of findings.</p>

  <h3>Phase 1 — Rotate &amp; relocate live credentials (~1 hr)</h3>
  <div class="card"><ul>
    <li>Rotate every live credential the scan found in agent-readable configs or synced storage.</li>
    <li>Move tokens into the OS keychain; launch MCP servers and tools through wrapper scripts that pull secrets at runtime.</li>
    <li>Confirm SSH keys have passphrases; add them if not.</li>
  </ul></div>

  <h3>Phase 2 — Build the PII quarantine (~2 hrs)</h3>
  <div class="card"><ul>
    <li>Create one encrypted container (encrypted disk image, or a Cryptomator vault if it must sync through cloud storage).</li>
    <li>Move every identity, tax, medical, and financial document into it — SSN cards, birth certificates, licenses, tax returns, imaging folders.</li>
    <li>Verify the encrypted copies open, then delete the plaintext originals and empty the cloud trash.</li>
    <li>The quarantine stays outside every agent-indexed path.</li>
  </ul></div>

  <h3>Phase 3 — Scrub the corpora (~30 min)</h3>
  <div class="card"><ul>
    <li>Redact account numbers, SSN-shaped strings, and tokens from any text corpora your agents index.</li>
    <li>Scrub session transcripts and tool outputs that captured secrets.</li>
    <li>Add a redaction filter wherever transcripts get archived, so future ones are scrubbed at write time.</li>
  </ul></div>
</div>""")

    sheets.append("""
<div class="sheet">
  <h2>Hardening roadmap — beyond the file scan</h2>

  <h3>Accounts (highest ROI)</h3>
  <div class="card"><ul>
    <li><strong>Credit freezes for every family member, children included</strong> — free, permanent until lifted, kills new-account identity theft. If the scan found family identity documents in cloud storage, this is the single most important action on this page.</li>
    <li>Hardware-key 2FA (or Google Advanced Protection) on primary email accounts — email is the reset vector for everything else.</li>
    <li>A password manager for the whole household, with breach monitoring on.</li>
    <li>haveibeenpwned.com alerts on all email addresses.</li>
  </ul></div>

  <h3>Devices</h3>
  <div class="card"><ul>
    <li>Full-disk encryption on; auto-lock at 5 minutes or less.</li>
    <li>Audit which apps hold full-disk-access and screen-recording grants; remove anything unused.</li>
    <li>macOS: Objective-See's free tools — LuLu (outbound firewall), BlockBlock (persistence alerts), KnockKnock (one-shot audit).</li>
  </ul></div>

  <h3>Home network</h3>
  <div class="card"><ul>
    <li>Router: change the admin password, disable WAN administration, UPnP, and WPS; firmware auto-update on.</li>
    <li>Wi-Fi on WPA3 (or WPA2/WPA3 transition); guest network for every IoT device — TVs, cameras, assistants.</li>
    <li>DNS filtering at the router (NextDNS, Cloudflare families): malware/phishing blocking for every device at once.</li>
  </ul></div>

  <h3>AI-agent boundary</h3>
  <div class="card"><ul>
    <li>Deny-rule your agent harness out of reading SSH keys, .env files, key files, and its own token store (Claude Code: permissions.deny; other harnesses have equivalents).</li>
    <li>Deny rules are defense-in-depth, not a wall — the durable fix is the quarantine: agents can't leak what they can't reach.</li>
    <li>Never route a secret through an agent session in either direction — no pasting keys into chat, no unmasked prints. Transcripts get archived.</li>
    <li>Quarterly: audit MCP servers and connectors; disconnect anything not earning its access.</li>
  </ul></div>
</div>""")

    body = "\n".join(sheets)
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Sweep — {date_str}</title>
<style>
:root {{
  --charcoal:#1C1C1C; --text-body:#333333; --text-secondary:#666666;
  --accent:#505a70; --accent-light:#d0d8e8; --border:#E5E5E5;
  --bg:#FFFFFF; --bg-card:#F7F8FA; --teal:#3A6B8C; --emphasis:#9a3434;
}}
@page {{ size: letter; margin: 0; }}
html, body {{ background: var(--bg); margin:0; padding:0;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
  font-family:'Inter',-apple-system,sans-serif; }}
.sheet {{ padding: 0.75in; page-break-after: always; page-break-inside: avoid; box-sizing: border-box; }}
.sheet:last-child {{ page-break-after: auto; }}
body {{ font-size:11px; line-height:1.65; color:var(--text-body); }}
.stripe {{ height:4px; background:var(--accent); margin-bottom:14px; }}
.brand-line {{ font-family:'JetBrains Mono',monospace; font-size:9px; letter-spacing:4px; color:var(--text-secondary); text-transform:uppercase; margin-bottom:16px; }}
h1 {{ font-size:26px; font-weight:800; color:var(--charcoal); letter-spacing:-0.5px; margin:0 0 8px; }}
.subtitle {{ font-size:13px; color:var(--text-secondary); margin-bottom:4px; }}
.meta {{ font-family:'JetBrains Mono',monospace; font-size:9px; text-transform:uppercase; letter-spacing:2px; color:var(--text-secondary); margin-bottom:18px; }}
h2 {{ font-size:17px; font-weight:700; color:var(--charcoal); margin:26px 0 10px; border-left:3px solid var(--accent); padding-left:12px; line-height:1.3; }}
.sheet > h2:first-child {{ margin-top:0; }}
h3 {{ font-size:13px; font-weight:700; color:var(--charcoal); margin:16px 0 5px; }}
p {{ margin:7px 0; }}
.stat-row {{ display:flex; gap:10px; margin:18px 0; }}
.stat-card {{ flex:1; background:var(--bg-card); border:1px solid var(--border); border-top:2px solid var(--accent); border-radius:6px; padding:12px 14px; text-align:center; page-break-inside:avoid; }}
.stat-num {{ font-size:24px; font-weight:800; color:var(--charcoal); }}
.stat-label {{ font-family:'JetBrains Mono',monospace; font-size:8px; letter-spacing:1.5px; color:var(--text-secondary); margin-top:2px; }}
table {{ width:100%; border-collapse:collapse; margin:8px 0; }}
th {{ font-family:'JetBrains Mono',monospace; font-size:9px; text-transform:uppercase; letter-spacing:1px; color:var(--teal); text-align:left; padding:5px 7px; border-bottom:2px solid var(--accent); }}
td {{ padding:4px 7px; border-bottom:1px solid var(--border); vertical-align:top; font-size:10px; }}
tbody tr:nth-child(even) {{ background:#FCFCFC; }}
.mono {{ font-family:'JetBrains Mono',monospace; font-size:9px; }}
.path {{ word-break:break-all; font-size:9.5px; }}
.sev {{ font-family:'JetBrains Mono',monospace; font-size:9px; font-weight:700; }}
.new-badge {{ font-family:'JetBrains Mono',monospace; font-size:8px; background:var(--accent-light); color:var(--charcoal); padding:1px 4px; border-radius:3px; }}
.card {{ background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:10px 14px; margin:8px 0; page-break-inside:avoid; }}
.card ul {{ margin:4px 0; padding-left:18px; }}
.card li {{ margin:3px 0; }}
.note {{ font-size:9.5px; color:var(--text-secondary); }}
</style></head>
<body>
{body}
</body></html>"""

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{date_str}-security-sweep.html"
    if out.exists():
        out.unlink()
    out.write_text(page)
    print(str(out))


if __name__ == "__main__":
    main()
