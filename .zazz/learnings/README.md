# Learnings

What the project has learned from research, probes and experiments, kept so that a later session can read it cold. These
are learnings, not specifications: nothing here approves work. Each topic has its own directory with a `README.md` that
states the verdicts first.

| Topic | Read it for |
|---|---|
| [Detection generalization](detection-generalization/README.md) | Finding vulnerabilities without a hand-written analyzer per driver, ORM, validator and version: what to record, what to send the judge, what to ask, and which strategies were accepted |

## How to add to this

- **A new topic gets a directory** named for the goal, in lower case with hyphens, and a `README.md` that opens with what
  was accepted and what was not. Where a specification series exists for the goal, use its name:
  `.zazz/specifications/detection-generalization/` and this topic share one.
- **A finding gets its own page** when a later decision will turn on it and it is longer than a table row. State the finding
  first, then the evidence, then what is not measured. Other pages link to it and do not repeat its tables.
- **Evidence stays where it is owned.** Tables of runs belong in `.zazz/evaluation/`; a learnings page links to them and gives
  the reading.
- **Say how firm a statement is**: how many runs, which model, which application, and whether the application was read
  during development.
- Working logs of a session belong in `.zazz/ephemeral/` and are not committed. Summarize them here when the work ends.
