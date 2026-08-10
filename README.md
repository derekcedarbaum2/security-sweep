# security-sweep

A weekly secrets-and-PII sweep for the age of AI agents. Deterministic scanner,
emailed report, and a one-item-at-a-time remediation session you run with
whatever coding agent you use. Report-only: it never touches your files.

## The problem

If you use AI agents seriously, your machine accumulates exposure fast: MCP
tokens in plaintext configs, tax returns and kids' birth certificates in
cloud-drive mounts your agents can read, session transcripts that captured an
API key, a medical PDF with a card number in it. Every one of those is
readable by the next agent session, and by anything else that gets onto the
machine. The first scan of a working setup typically finds dozens of these.

## What it does

1. **Scans** the surfaces you configure (notes vault, cloud-drive mounts,
   agent configs, Desktop/Documents/Downloads, shell history) with ~30
   deterministic rules: vendor API keys, tokens, JWTs, private keys, SSNs,
   card numbers (Luhn-gated), bank/routing numbers (checksum-gated),
   identity/tax/medical/financial documents by filename. Every match is
   masked, everywhere.
2. **Tracks each finding's age across runs and escalates the persistent ones.**
   A finding open 20 days reads differently from one found this morning. The
   report leads with anything unresolved past a threshold (default 14 days),
   and counts what you resolved since the last run. Age is the escalation
   signal, borrowed from the "PR open >12h → escalate" pattern.
3. **Reports** to a self-contained HTML/PDF: severity counts, persistent and
   resolved bands, per-surface coverage, a proposed disposition per finding, a
   standing remediation plan, and a hardening roadmap. Emails it to you weekly
   via Mail.app.
4. **Walks through remediation with you.** `docs/walkthrough.md` is the
   session playbook: your agent verifies each finding (masked), proposes a
   disposition, and waits for your call. Rotate, relocate to keychain,
   quarantine, redact, allowlist, or accept. Then `scan.py --verify` re-scans
   and confirms your fixes actually landed, without disturbing the weekly
   baseline. The next scan is the cheap oracle for "done."

No LLM in the scan path. No network calls. Nothing leaves your machine except
the email you send yourself.

## Install

```bash
git clone https://github.com/derekcedarbaum2/security-sweep.git
cd security-sweep
./scripts/install.sh            # seeds config, installs weekly launchd/cron job
$EDITOR ~/.security-sweep/config.json   # set your email + surfaces
bash scripts/run-sweep.sh       # first sweep
cat ~/.security-sweep/last-run.log
```

Requirements: python3 (stdlib only), macOS for email + PDF (Chrome). On Linux
the scan and HTML report work as-is; set `email_enabled: false` or swap in
your own sender.

If you use Claude Code, `install.sh` also registers a `/security-sweep` skill.
Any other harness: the scripts are plain Python and bash; point your agent at
`docs/walkthrough.md` for the remediation session.

## Configure

`~/.security-sweep/config.json`:

| Key | What |
|---|---|
| `surfaces` | Named roots to scan recursively. Point these at whatever your agents can read. |
| `extra_files` | Individual files worth checking (shell history, agent config JSON). |
| `recipient_email` | Where the weekly report goes. |
| `allow_path_patterns` | Extra regex fragments for paths where secret-looking content is expected. |
| `email_enabled`, `chrome_path`, `report_dir`, `state_dir`, `log_file` | Plumbing. |

False positives go in `~/.security-sweep/allowlist.json`, preferably as stable
`"surface|path|rule"` keys. See `skill/SKILL.md` for the format.

## The remediation session

The scan is the easy half. Read `docs/walkthrough.md` before your first
session. Short version: group findings into decisions, verify before
proposing, fix rules instead of allowlisting recurring false-positive
classes, never let a secret pass through the agent session in either
direction, and rotate anything that sat exposed because it is burned whether
or not anyone read it.

## Design

`docs/design-notes.md` covers the reasoning: why local-and-deterministic
instead of a cloud agent, why report-only is a hard line, why masking has no
thresholds, how cloud placeholders are skipped without forcing downloads, the
false-positive war stories behind the credit-card regex, and why email rides
Mail.app instead of storing a new credential.

## What this is not

- Not a code-repo scanner. Use gitleaks/trufflehog in CI for that; they are
  excellent and this tool deliberately overlaps them only a little.
- Not an autoremediation system. It proposes; you dispose.
- Not a guarantee. It is a weekly floor under your exposure, not a ceiling on
  an attacker.

MIT. Built with Claude Code; scanner and report are deterministic Python.
