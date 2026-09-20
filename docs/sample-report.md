# Fictional security sweep report

This example contains invented paths and masked synthetic values. It illustrates the report format; it is not a scan of a real machine.

Scanned 3 files. Two open findings, both new. No cloud placeholders skipped.

| Severity | Age | Location | Rule | Masked match | Count |
|---|---|---|---|---|---|
| CRITICAL | New | demo/notes.txt | github-token | `ghp_…7r8 (40 chars)` | 2 |
| MEDIUM | New | demo/medical-record.pdf | medical-doc | `medi…pdf (18 chars)` | 1 |

The scanner proposes reviewing the credential and moving sensitive documents into protected storage. It changes no source files. The operator reviews findings and performs any remediation.

Run `python3 -m unittest discover -s tests -v` to verify detection, masking, false-positive handling, and preservation of the saved baseline during verification. All test input lives in temporary folders.
