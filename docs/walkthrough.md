# The remediation walkthrough

The scan is the easy half. The value is the session where you and your agent go
through the findings one item at a time and resolve as many as possible in one
sitting. This file is the playbook for that session, distilled from running it
for real. It works with any capable coding agent (Claude Code, Codex, or
similar) that can read files and run shell commands.

## The prompt

Open your agent in your home directory and paste:

> Read `~/.security-sweep/findings.md`. Group the findings into decision items
> (one problem repeated across files is one item). Then walk me through them one
> item at a time: for each, verify the finding is real by inspecting it with
> every matched value masked, tell me the risk in one paragraph, propose a
> disposition, and wait for my call before acting. Dispositions: rotate,
> relocate to OS keychain, quarantine to encrypted storage, redact in place,
> allowlist as false positive, or accept the risk. Rules: never print an
> unmasked secret; never ask me to paste a secret into this chat; anything
> destructive needs my explicit yes; verify every fix afterward.

## What a good session looks like

1. **Group first.** 86 raw findings collapse into about 10 decisions. A token
   that appears in three config files is one item, not three.
2. **Verify before proposing.** Half of a first scan is false positives:
   digit runs inside hex blobs, PDF font arrays, SVG coordinates, loyalty
   numbers labeled "account number", dummy SSNs like 111-11-1111, Google's own
   API keys baked into the Drive client. Make the agent inspect context
   (masked) before you spend a decision on it.
3. **Fix the rule, not just the finding.** A false-positive class that will
   recur (every future medical PDF, every session UUID) deserves a regex fix
   with unit tests, not an allowlist entry. Allowlist entries are for
   singletons.
4. **Prefer stable allowlist keys.** Use `surface|path|rule` keys, not finding
   ids. Ids hash the matched text and break when the file changes.
5. **One decision at a time.** The agent proposes, you dispose. Sessions where
   the agent batches ten fixes behind one approval are how mistakes ship.

## The credential playbook (the most common critical class)

Plaintext tokens in agent-readable config files (MCP server configs are the
usual offenders). The fix that sticks:

1. Store the secret in the OS keychain
   (`security add-generic-password -U -a $USER -s <name> -w '<value>'` on macOS).
2. Launch the server through a wrapper script that pulls the secret at spawn
   and exports it, so the config file holds no values.
3. Scrub the plaintext from configs AND their backups (redact in place, keep
   the backup).
4. Rotate the old credential. It sat exposed; treat it as burned. Session
   tokens mean signing out other sessions; API keys mean the provider
   dashboard.
5. Verify end to end: wrapper launches, authenticates, new key works, old key
   dead.

## Two rules that were learned the hard way

**Never route a secret through the agent session, in either direction.** Chat
transcripts get archived and indexed. Pasting a fresh key into the session to
"save time" burns it the moment it lands in the transcript, and a masking
script with a length threshold will eventually print a short password in the
clear. New secrets go into the keychain via a terminal window outside the
agent session. The agent verifies by comparing inside a script (prefix, length,
API status code), never by echoing the value.

**The scanner will catch its own tail.** Test vectors, rule examples in code
comments, and the agent's own session transcripts all trigger findings. Build
test card numbers by concatenation, write SSN-shaped examples as NNN-NN-NNNN,
and allowlist your harness's transcript directories for rules they
legitimately trip.

## Dispositions that need a human beyond the keyboard

Some fixes the agent cannot do and should hand you as steps:

- Signing out sessions and changing passwords (password managers, Slack,
  Google).
- Creating the encrypted quarantine passphrase. The agent stages the moves;
  you type the passphrase; it never touches the session.
- Emptying cloud-provider trash after deleting plaintext originals. Files
  are not gone until the trash is.
- Credit freezes, hardware keys, router settings: see the hardening sheet in
  the weekly report.
