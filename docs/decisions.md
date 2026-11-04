# Decisions log

A decision is superseded only by new evidence, quoted in the new entry. A reviewer
disagreeing is not new evidence. Superseded entries are kept and marked, never deleted.

Format (after Michael Nygard, *Documenting Architecture Decisions*, 2011):

```
## D-NNN Title
Status: proposed | accepted <date> | superseded by D-NNN
Context: what forced the decision (finding ID, the conflicting text)
Decision: what the repo will say or do
Evidence: quotes with file:line or URL
Consequences: what a future change must bring to overturn it
```

This file is excluded from tools/check_regressions.py because it quotes old wording on purpose.
