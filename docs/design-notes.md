# Design notes

Why the tool is shaped the way it is.

## Local and deterministic, not a cloud agent

Scanning for secrets means reading every candidate secret. Shipping that
stream to a hosted service or an LLM is the exposure you are defending
against. So the scan path is plain Python with zero network calls and no
model in the loop. The LLM's job is the *remediation session* afterward,
where it only ever sees masked matches.

## Report-only is a hard line

The sweep proposes; the human disposes. An automation that deletes or moves
personal files on a schedule will eventually eat something irreplaceable.
Every disposition in the report is a proposal, and the walkthrough session
requires an explicit yes per item.

## Masking is unconditional

Every matched value is masked everywhere: findings, logs, report, chat. The
mask keeps first-4 and last-3 plus length, enough to recognize a value
without reproducing it. Do not add length thresholds to masking logic; a
short password will eventually slip through the gap.

## Cloud placeholders are skipped, loudly

macOS cloud mounts (Drive, iCloud) keep most files as dataless placeholders.
Reading one forces a download; a scanner that does that will pull gigabytes
weekly. Detection: the `SF_DATALESS` stat flag plus a zero-blocks heuristic.
Skipped counts appear in the report so coverage gaps stay visible instead of
silent.

## False-positive war stories (why the rules look overbuilt)

Every anchor in the credit-card rule exists because of a real false positive:

- PDF glyph-width arrays (`/W [0 [595 3 629 ...]`): space-separated digit
  runs that bridge into Luhn-valid sequences. Fix: separators only in real
  card groupings (4-4-4-4, Amex 4-6-5).
- Hex blobs (RTF-embedded PNGs, Gmail message ids, session UUIDs): 13+ digit
  runs bounded by hex letters. Fix: no adjacent `[0-9a-f]` on either side.
- URLs and decimals (`profile_images/3788…`, `716.6666666666667`). Fix: no
  leading `/` or `.`, no trailing `.digit`.
- The lookahead must NOT block a sentence-ending period, or cards at the end
  of sentences vanish. `(?![0-9a-fA-F-]|\.\d)` blocks decimals only.

Other classics: book titles matching "secret" in filename rules, dummy SSNs
(000-00-0000, 111-11-1111), Google's own API keys embedded in the Drive
client's crashpad args, loyalty-program numbers labeled "Account Number",
and the scanner flagging its own rule examples via the harness's file-history
copies. Keep a should-match / should-not-match unit-test list and grow it
with every false positive.

## Allowlist by key, not id

Finding ids hash the matched text, so editing the file changes the id and
the finding reappears as "new". The stable form is `surface|path|rule`:
"this file is accepted for this rule". Use ids only to accept one specific
match in a file where the same rule also catches things you care about.

## Email via Mail.app on purpose

A headless-browser Gmail sender or an SMTP script stores a live credential,
which is the exposure class this tool exists to eliminate. AppleScript
through Mail.app rides the existing authenticated session and stores
nothing. On Linux, disable email in config and read the report locally, or
swap in msmtp if you accept the stored-credential trade.

## Unattended-automation hygiene

The runner fails loudly: pre-flight names the missing dependency, a lockdir
with stale-cleanup prevents overlap, findings are delete-before-write with a
freshness assertion, the report builder refuses stale findings, and the
emailer refuses stale PDFs. Silence is reserved for success.
