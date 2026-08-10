---
name: security-sweep
description: Weekly secrets & PII exposure sweep across your storage surfaces (notes vault, cloud-drive mounts, agent configs, home-dir hotspots) plus a report emailed via Mail.app. Report-only. Never modifies, moves, or deletes scanned files. Runs weekly via the com.user.security-sweep launchd job, or on demand via "/security-sweep", "run the security sweep", "scan for secrets", "PII scan". Not for one-off code-repo secret scanning (use gitleaks directly) or OS hardening changes.
---

# security-sweep

Deterministic pipeline. The skill is a thin wrapper over scripts; no LLM judgment
in the cron path. Repo: __REPO__

## On-demand run

```bash
bash __REPO__/scripts/run-sweep.sh
```

That is the whole pipeline: scan, report HTML, PDF, email, log line.
Read `~/.security-sweep/last-run.log` afterward and relay the counts.

## Pieces (for partial runs / iteration)

| Script | Job |
|---|---|
| `scripts/scan.py` | Scan all configured surfaces into `~/.security-sweep/findings.{json,md}`. Masks every match. Skips cloud-placeholder (dataless) files rather than force-downloading. |
| `scripts/build_report.py --out DIR` | findings.json to self-contained HTML. Refuses findings older than 24h. |
| `scripts/send_email.sh <pdf> <crit> <high> <med> <new>` | Mail.app AppleScript send. Zero stored credentials. Refuses PDFs older than 2h. |

## Allowlist (false positives / accepted risk)

`~/.security-sweep/allowlist.json` takes two entry kinds:

- `"keys": ["<surface>|<path>|<rule>", ...]` is the preferred form. Stable across
  file edits; accepts this file for this rule.
- `"ids": ["<finding id>", ...]` takes exact finding ids from findings.json.
  Brittle: the id hashes the matched text, so any edit to the file mints a
  new id and the finding reappears.

Allowlisted findings are suppressed from future reports but still counted in
the summary.

## Rules of the house

- Report-only. The sweep proposes; the human disposes. Never wire
  auto-remediation into this pipeline.
- Never print an unmasked match: not in findings, logs, reports, or chat.
- Never route a secret through the session in either direction. No pasting
  keys into chat, no `!` bash-input containing a secret, no unmasked prints.
  Transcripts get archived. Secrets enter the machine via a terminal outside
  the agent session.
- Rule changes: tighten with anchored patterns, re-run, verify counts move the
  right way. Add unit tests for both should-match and should-not-match cases,
  and build test card numbers by string concatenation so the scanner doesn't
  flag its own test vectors in your session transcripts.
- For the remediation session, follow `docs/walkthrough.md` in the repo.
