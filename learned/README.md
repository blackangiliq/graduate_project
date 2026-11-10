# Learned rules

This folder holds the rules the tool has learned on this installation.

- `rules.yaml` - new rules proposed by the AI, validated automatically and approved by you.
- `overrides.yaml` - approved exclusions that silence a false positive of an existing rule.

Both files are created the first time you approve a candidate (Learning tab, or
`python -m sca rules approve <id>`). They are plain YAML: you can read them, edit them, delete
entries, and commit them to share what your installation has learned.

Candidates that are still waiting for approval are not here. They are in the local database
(`data/sca.db`) and never take part in a scan.
