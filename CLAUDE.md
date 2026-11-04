# soc-lab: working rules for Claude

SOC Level 1 homelab: Wazuh 4.14.7, Suricata 8.0.7, Sysmon, Shuffle, TheHive 5.8.0.
Evidence lives in `evidence/`; scenario docs in `docs/scenarios/` own their claims.

## Evidence rules
- Before editing a claim, run `git grep -n -i '<claim>'` and
  `python3 tools/check_regressions.py tools/regressions.tsv`. Work only from those hits,
  never from memory of where a claim appears.
- Every new factual sentence cites its source in the same file: artifact path + line,
  or URL + quoted phrase. A commit message is not a source.
- No source: write "observed; cause not determined", or remove the claim.
  Prefer narrowing a claim over adding a new explanation.
- Never edit machine-captured evidence (evidence/**/*.json, *.png, raw command output).
  Hand-written annotation in evidence/*.txt may be corrected, marked "revised <date>".
  If a later change makes evidence out of date, add a note beside the citation.
- docs/decisions.md entries change only with new evidence quoted in a new entry.
  If a request contradicts an entry, stop and say so; do not edit.
- One finding per commit. Add the fixed wrong wording to tools/regressions.tsv in the
  same commit. Patterns target the wrong claim, never a true fact.
- Update docs/claims.md in the same commit: claim, evidence, status, where it appears.
