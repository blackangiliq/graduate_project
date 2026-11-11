# Your rules

This folder holds everything about rules that belongs to this installation. The files are
created when they are first needed.

| File | Content | Written by |
|---|---|---|
| `rules.yaml` | rules proposed by the AI, validated automatically and approved by you | Learning tab, `python -m sca rules approve` |
| `custom.yaml` | rules you wrote yourself | Rules tab, `python -m sca rules new` |
| `edits.yaml` | your changes to rules that ship with the tool, including switching one off | Rules tab, `python -m sca rules edit / disable` |
| `overrides.yaml` | approved exclusions that silence a false positive of a rule | Learning tab |

All four are plain YAML: you can read them, edit them by hand, delete entries, and commit
them to share your rule set. A broken entry is skipped; it can never stop a scan. The rules
that ship with the tool are in `sca/rules/` and are not changed by anything you do here.

Candidates that are still waiting for approval are not here. They are in the local database
(`data/sca.db`) and never take part in a scan.
