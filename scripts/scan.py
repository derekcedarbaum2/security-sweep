#!/usr/bin/env python3
"""
security-sweep scanner — report-only secrets & PII detection.

Scans the storage surfaces defined in your config for credentials, PII, and
financial data. NEVER modifies, moves, or deletes a scanned file. Output is
findings only, with every matched value masked. Designed to run headless
(launchd/cron) or interactively.

Config: ~/.security-sweep/config.json (or $SECURITY_SWEEP_CONFIG).
See config.example.json in the repo root.

Outputs (delete-before-write, freshness-asserted):
  <state_dir>/findings.json
  <state_dir>/findings.md

Allowlist: <state_dir>/allowlist.json
  {"keys": ["<surface>|<path>|<rule>", ...],   # preferred: stable across edits
   "ids":  ["<finding id>", ...]}              # exact ids from findings.json
Allowlisted findings are counted but not re-reported.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()


def load_config():
    cfg_path = Path(os.environ.get("SECURITY_SWEEP_CONFIG",
                                   HOME / ".security-sweep/config.json"))
    if not cfg_path.exists():
        print(f"FATAL: config not found at {cfg_path}.\n"
              f"Copy config.example.json to ~/.security-sweep/config.json and edit it.",
              file=sys.stderr)
        sys.exit(2)
    cfg = json.loads(cfg_path.read_text())
    for req in ("surfaces",):
        if req not in cfg:
            print(f"FATAL: config missing required key: {req}", file=sys.stderr)
            sys.exit(2)
    return cfg


CFG = load_config()
STATE = Path(os.path.expanduser(CFG.get("state_dir", "~/.security-sweep")))
FINDINGS_JSON = STATE / "findings.json"
FINDINGS_MD = STATE / "findings.md"
ALLOWLIST = STATE / "allowlist.json"

SURFACES = {name: Path(os.path.expanduser(p)) for name, p in CFG["surfaces"].items()}
EXTRA_FILES = [Path(os.path.expanduser(p)) for p in CFG.get("extra_files", [])]

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".Trash",
    ".obsidian", "Photos", ".tmp.drivedownload", ".file-revisions-by-id",
    ".shortcut-targets-by-id", ".DS_Store",
} | set(CFG.get("skip_dirs", []))

# Content-scannable extensions (text-ish). Everything else: filename rules only.
TEXT_EXT = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".xml", ".html",
    ".htm", ".js", ".mjs", ".ts", ".py", ".sh", ".zsh", ".rb", ".env", ".ini",
    ".cfg", ".conf", ".toml", ".plist", ".sql", ".log", ".pem", ".key", ".crt",
    ".pub", ".rtf", ".tex", "",
}
MAX_CONTENT_BYTES = 5 * 1024 * 1024  # skip content scan above 5 MB
SF_DATALESS = 0x40000000  # macOS: file content not materialized locally


def is_dataless(p: Path) -> bool:
    """True if the file is a cloud placeholder — reading it would force a download."""
    try:
        st = os.stat(p, follow_symlinks=False)
    except OSError:
        return True
    if getattr(st, "st_flags", 0) & SF_DATALESS:
        return True
    # Sparse heuristic: nonzero size but zero blocks on disk
    if st.st_size > 0 and getattr(st, "st_blocks", 1) == 0:
        return True
    return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def aba_ok(digits: str) -> bool:
    """ABA routing number checksum."""
    if len(digits) != 9:
        return False
    w = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    return sum(int(d) * m for d, m in zip(digits, w)) % 10 == 0


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}…{v[-3:]} ({len(v)} chars)"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# (rule_id, severity, compiled regex, needs_entropy>bits or None)
SECRET_RULES = [
    ("aws-access-key", "CRITICAL", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("openai-key", "CRITICAL", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 3.5),
    ("anthropic-key", "CRITICAL", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), None),
    ("github-token", "CRITICAL", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), None),
    ("slack-token", "CRITICAL", re.compile(r"\bxox[bcdeprs]-[A-Za-z0-9-]{10,}\b"), None),
    ("google-api-key", "HIGH", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), None),
    ("stripe-key", "CRITICAL", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b"), None),
    ("private-key-block", "CRITICAL", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----"), None),
    ("firecrawl-key", "HIGH", re.compile(r"\bfc-[a-f0-9]{24,}\b"), None),
    ("linear-key", "HIGH", re.compile(r"\blin_api_[A-Za-z0-9]{20,}\b"), None),
    ("jwt", "MEDIUM", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), None),
    ("generic-assignment", "HIGH", re.compile(
        r"""(?ix)\b(api[_-]?key|apikey|secret|token|passwd|password|client[_-]?secret|access[_-]?key)\b
            \s*[:=]\s*["']?([A-Za-z0-9+/_\-\.]{16,80})["']?"""), 3.8),
]

PII_RULES = [
    # SSN requires context within the line to cut false positives
    ("ssn", "CRITICAL",
     re.compile(r"(?i)\b(ssn|social security|soc\.? sec)\b[^\n]{0,40}?\b(\d{3}-\d{2}-\d{4}|\d{9})\b"), None),
    ("ssn-formatted", "HIGH", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    # Luhn-gated below. Anchors: no adjacent hex letters/digits/dot/slash (kills
    # URLs, decimals, UUIDs, and digit runs inside hex blobs like RTF-embedded
    # PNGs or Gmail message ids), and separators only in real card groupings
    # (4-4-4-4 or Amex 4-6-5) so space-separated numeric arrays (PDF /W glyph
    # widths) can't bridge.
    ("credit-card", "CRITICAL",
     re.compile(r"(?<![0-9a-fA-F./])(?:\d{13,19}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}|\d{4}[ -]\d{6}[ -]\d{5})(?![0-9a-fA-F-]|\.\d)"), None),
    ("routing-number", "HIGH",
     re.compile(r"(?i)\b(routing|aba)\b[^\n]{0,30}?\b(\d{9})\b"), None),
    ("bank-account", "HIGH",
     re.compile(r"(?i)\b(account\s*(?:number|no\.?|#))\s*[:=]?\s*(\d{6,17})\b"), None),
    ("dob", "MEDIUM",
     re.compile(r"(?i)\b(dob|date of birth|birthdate)\b[^\n]{0,25}?\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"), None),
    ("passport", "HIGH",
     re.compile(r"(?i)\b(passport)\s*(?:number|no\.?|#)?\s*[:=]?\s*([A-Z0-9]{6,9})\b"), None),
    ("drivers-license", "MEDIUM",
     re.compile(r"(?i)\b(driver'?s?\s*license|dl)\s*(?:number|no\.?|#)\s*[:=]?\s*([A-Z0-9]{5,13})\b"), None),
    ("ein", "MEDIUM", re.compile(r"(?i)\b(ein|employer identification)\b[^\n]{0,25}?\b(\d{2}-\d{7})\b"), None),
]

FILENAME_RULES = [
    ("keyfile", "HIGH", re.compile(r"(?i)\.(pem|p12|pfx|key|keystore|jks|asc)$")),
    ("env-file", "HIGH", re.compile(r"(?i)(^|/)\.env(\.|$)")),
    ("credential-file", "HIGH", re.compile(r"(?i)((credentials?|passwords?|api.?keys?|logins?)[^/]*\.(json|txt|csv|yaml|yml)|(^|/)secrets?\.(json|yaml|yml|txt|env))$")),
    ("ssh-private", "CRITICAL", re.compile(r"(?i)(^|/)id_(rsa|ed25519|ecdsa|dsa)$")),
    ("tax-doc", "MEDIUM", re.compile(r"(?i)(?<![a-z0-9])(w-?2c?s?(?![a-z0-9])|1099|1040|tax.?returns?|schedule[ _-][ck](?![a-z]))[^/]*\.(pdf|jpg|jpeg|png|heic|docx?)$")),
    ("financial-doc", "MEDIUM", re.compile(r"(?i)(bank.?statement|statement.*(chase|bofa|wells|schwab|fidelity|vanguard)|(chase|bofa|wells|schwab|fidelity|vanguard).*statement|voided.?check|wire.?instructions)[^/]*\.\w+$")),
    ("identity-doc", "HIGH", re.compile(r"(?i)(passport|ssn|social.?security|birth.?certificate|drivers?.?license|green.?card|i-?9\b)[^/]*\.(pdf|jpg|jpeg|png|heic|docx?)$")),
    ("medical-doc", "MEDIUM", re.compile(r"(?i)(medical.?record|diagnosis|lab.?result|imaging.?report|mri|x-?ray.?report)[^/]*\.(pdf|jpg|jpeg|png|heic|docx?)$")),
]

# Paths where "secret-looking" content is expected and not a finding
# (this tool's own rules and state, test fixtures, vendored/minified code,
# app bundles). Extend via config "allow_path_patterns".
_allow_parts = [
    r"security-sweep", r"\.test\.(ts|js|tsx|py)", r"\.app/Contents/", r"\.min\.js$",
] + CFG.get("allow_path_patterns", [])
PATH_ALLOW_RE = re.compile("(?i)(" + "|".join(_allow_parts) + ")")

# Known-false-positive contexts for generic-assignment
FP_CONTEXT_RE = re.compile(
    r"(?i)(placeholder|example|your[_-]?api[_-]?key|xxx+|<[^>]+>|\$\{|\benv\b\.|process\.env|os\.environ)"
)


def finding_id(surface, path, rule, masked):
    h = hashlib.sha1(f"{path}|{rule}|{masked}".encode()).hexdigest()[:12]
    return h


def scan_content(path: Path, rel: str, surface: str, findings: list):
    try:
        if path.stat().st_size > MAX_CONTENT_BYTES:
            return
        text = path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return

    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for rule_id, sev, rx, min_entropy in SECRET_RULES:
            for m in rx.finditer(line):
                value = m.group(2) if rule_id == "generic-assignment" else m.group(0)
                if min_entropy and entropy(value) < min_entropy:
                    continue
                if rule_id == "generic-assignment" and FP_CONTEXT_RE.search(line):
                    continue
                add(findings, surface, rel, rule_id, sev, lineno, value)
        for rule_id, sev, rx, _ in PII_RULES:
            for m in rx.finditer(line):
                if rule_id == "credit-card":
                    digits = re.sub(r"[ -]", "", m.group(0))
                    if not (13 <= len(digits) <= 19 and luhn_ok(digits) and digits[0] in "3456"):
                        continue
                    value = digits
                elif rule_id == "routing-number":
                    if not aba_ok(m.group(2)):
                        continue
                    value = m.group(2)
                elif rule_id == "ssn-formatted":
                    # skip if the with-context rule already fired on this line
                    if PII_RULES[0][2].search(line):
                        continue
                    # all-same-digit dummies (000-00-0000 etc.) are placeholders
                    digits = re.sub(r"\D", "", m.group(0))
                    if len(set(digits)) == 1:
                        continue
                    value = m.group(0)
                else:
                    value = m.group(m.lastindex or 0)
                add(findings, surface, rel, rule_id, sev, lineno, value)


def add(findings, surface, rel, rule_id, sev, lineno, value):
    masked = mask(value)
    findings.append({
        "id": finding_id(surface, rel, rule_id, masked),
        "surface": surface,
        "path": rel,
        "rule": rule_id,
        "severity": sev,
        "line": lineno,
        "match": masked,
    })


def scan_file(path: Path, root: Path, surface: str, findings: list, stats: dict):
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)
    # Filename rules always run (even for dataless / binary files)
    for rule_id, sev, rx in FILENAME_RULES:
        if rx.search(str(path)):
            add(findings, surface, rel, rule_id, sev, 0, path.name)
    if PATH_ALLOW_RE.search(str(path)):
        return
    if is_dataless(path):
        stats["dataless"] += 1
        return
    if path.suffix.lower() in TEXT_EXT:
        stats["content_scanned"] += 1
        scan_content(path, rel, surface, findings)
    else:
        stats["filename_only"] += 1


def walk_surface(name: str, root: Path, findings: list, stats_all: dict):
    stats = {"files": 0, "dataless": 0, "content_scanned": 0, "filename_only": 0}
    if not root.exists():
        stats["error"] = "missing"
        stats_all[name] = stats
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn == ".DS_Store":
                continue
            stats["files"] += 1
            scan_file(Path(dirpath) / fn, root, name, findings, stats)
    stats_all[name] = stats


SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
ESCALATE_AFTER_DAYS = int(CFG.get("escalate_after_days", 14))


def fkey(f):
    """Stable cross-run identity for a finding (survives edits to the matched text)."""
    return f"{f['surface']}|{f['path']}|{f['rule']}"


def collect():
    """Walk every surface and return (deduped findings, stats, suppressed count)."""
    # Pre-flight: loud fail on missing surfaces
    missing = [n for n, p in SURFACES.items() if not p.exists()]
    if missing:
        print(f"PRE-FLIGHT WARNING: missing surfaces: {missing}", file=sys.stderr)
        if len(missing) == len(SURFACES):
            print("FATAL: every configured surface is missing — check config paths/mounts. Aborting.",
                  file=sys.stderr)
            sys.exit(2)

    findings, stats_all = [], {}
    for name, root in SURFACES.items():
        walk_surface(name, root, findings, stats_all)

    extra_stats = {"files": 0, "dataless": 0, "content_scanned": 0, "filename_only": 0}
    for f in EXTRA_FILES:
        if f.exists():
            extra_stats["files"] += 1
            scan_file(f, HOME, "extra-files", findings, extra_stats)
    stats_all["extra-files"] = extra_stats

    # Allowlist filter. Two entry kinds:
    #   ids:  exact finding ids (brittle — id hashes the matched text, so file
    #         edits mint a new id and the finding reappears)
    #   keys: "surface|path|rule" (stable — accepts this file for this rule)
    allow_ids, allow_keys = set(), set()
    if ALLOWLIST.exists():
        try:
            al = json.loads(ALLOWLIST.read_text())
            allow_ids = set(al.get("ids", []))
            allow_keys = set(al.get("keys", []))
        except json.JSONDecodeError:
            print("WARNING: allowlist.json unreadable — ignoring", file=sys.stderr)
    active = [f for f in findings
              if f["id"] not in allow_ids and fkey(f) not in allow_keys]
    suppressed = len(findings) - len(active)

    # Dedupe (same file+rule keeps first line, counts occurrences)
    deduped, seen = [], {}
    for f in active:
        key = (f["surface"], f["path"], f["rule"])
        if key in seen:
            seen[key]["count"] += 1
        else:
            f["count"] = 1
            seen[key] = f
            deduped.append(f)

    deduped.sort(key=lambda f: (SEV_RANK[f["severity"]], f["surface"], f["path"]))
    return deduped, stats_all, suppressed


def load_prev():
    """Previous findings list (empty on first run or unreadable state)."""
    if FINDINGS_JSON.exists():
        try:
            return json.loads(FINDINGS_JSON.read_text()).get("findings", [])
        except (json.JSONDecodeError, KeyError):
            pass
    return []


def main():
    ap = argparse.ArgumentParser(description="security-sweep scanner")
    ap.add_argument("--verify", action="store_true",
                    help="Re-scan and report what changed vs the last saved findings, "
                         "WITHOUT overwriting them. Use mid-remediation to confirm fixes landed.")
    args = ap.parse_args()

    t0 = time.time()
    STATE.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).date()

    deduped, stats_all, suppressed = collect()
    prev = load_prev()
    prev_by_key = {}
    for pf in prev:
        # keep the earliest first_seen if a key somehow appears twice
        k = fkey(pf)
        fs = pf.get("first_seen")
        if k not in prev_by_key or (fs and fs < prev_by_key[k]):
            prev_by_key[k] = fs or None
    prev_keys = set(prev_by_key)
    prev_ids = {pf["id"] for pf in prev}

    # Carry first_seen forward; stamp age
    cur_keys = set()
    for f in deduped:
        k = fkey(f)
        cur_keys.add(k)
        first = prev_by_key.get(k) or today.isoformat()
        f["first_seen"] = first
        try:
            f["age_days"] = (today - datetime.fromisoformat(first).date()).days
        except ValueError:
            f["age_days"] = 0

    new_ids = {f["id"] for f in deduped} - prev_ids
    resolved = [pf for pf in prev if fkey(pf) not in cur_keys]
    persistent = [f for f in deduped if f["age_days"] >= ESCALATE_AFTER_DAYS]

    if args.verify:
        # Non-destructive: report the diff against the saved baseline, write nothing.
        print(f"VERIFY vs {FINDINGS_JSON} (baseline left untouched)")
        print(f"  resolved since baseline: {len(resolved)}")
        for pf in resolved:
            print(f"    - [{pf['severity']}] {pf['surface']}/{pf['path']} ({pf['rule']})")
        print(f"  still open: {len(deduped)}  |  newly appeared: {len(new_ids)}")
        for f in deduped:
            if f["id"] in new_ids:
                print(f"    + [{f['severity']}] {f['surface']}/{f['path']} ({f['rule']})")
        sys.exit(0)

    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(time.time() - t0, 1),
        "stats": stats_all,
        "counts": {
            "total": len(deduped),
            "new": len(new_ids),
            "resolved": len(resolved),
            "persistent": len(persistent),
            "suppressed_allowlist": suppressed,
            "by_severity": {s: sum(1 for f in deduped if f["severity"] == s) for s in SEV_RANK},
        },
        "delta": {
            "new_ids": sorted(new_ids),
            "resolved": [{"surface": pf["surface"], "path": pf["path"], "rule": pf["rule"],
                          "severity": pf["severity"]} for pf in resolved],
        },
        "findings": deduped,
    }

    # Delete-before-write + freshness assertion
    for out in (FINDINGS_JSON, FINDINGS_MD):
        if out.exists():
            out.unlink()
    FINDINGS_JSON.write_text(json.dumps(result, indent=2))

    lines = [
        f"# Security sweep findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"Scanned {sum(s.get('files', 0) for s in stats_all.values())} files in {result['duration_sec']}s. "
        f"{result['counts']['total']} open findings ({result['counts']['new']} new, "
        f"{result['counts']['resolved']} resolved since last run, "
        f"{result['counts']['persistent']} persistent ≥{ESCALATE_AFTER_DAYS}d, {suppressed} allowlisted). "
        f"Dataless cloud placeholders skipped: {sum(s.get('dataless', 0) for s in stats_all.values())}.",
        "",
        "| Sev | Age | Surface | Path | Rule | Line | Match | × |",
        "|-----|-----|---------|------|------|------|-------|---|",
    ]
    for f in deduped:
        flag = " NEW" if f["id"] in new_ids else (" ‼" if f["age_days"] >= ESCALATE_AFTER_DAYS else "")
        age = "new" if f["age_days"] == 0 else f"{f['age_days']}d"
        lines.append(
            f"| {f['severity']}{flag} | {age} | {f['surface']} | {f['path']} | {f['rule']} | "
            f"{f['line']} | `{f['match']}` | {f['count']} |")
    if resolved:
        lines += ["", f"## Resolved since last run ({len(resolved)})", ""]
        for pf in resolved:
            lines.append(f"- [{pf['severity']}] {pf['surface']}/{pf['path']} ({pf['rule']})")
    FINDINGS_MD.write_text("\n".join(lines) + "\n")

    if not FINDINGS_JSON.exists() or time.time() - FINDINGS_JSON.stat().st_mtime > 60:
        print("FATAL: freshness assertion failed on findings.json", file=sys.stderr)
        sys.exit(3)

    print(json.dumps(result["counts"], indent=2))
    print(f"stats: {json.dumps(stats_all)}")
    print(f"wrote {FINDINGS_JSON} and {FINDINGS_MD}")


if __name__ == "__main__":
    main()
