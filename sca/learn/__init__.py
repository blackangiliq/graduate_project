"""Rule learning: the AI proposes rules, the tool validates them, a human approves them.

    propose.py   asks the LLM to write a rule (or an exclusion) as strict JSON
    sandbox.py   runs an untrusted regular expression in a separate process with a timeout
    validate.py  the automatic checks every candidate must pass
    store.py     learned/rules.yaml and learned/overrides.yaml (the approved rules)
    feedback.py  reviewer verdicts -> rule statistics, adjusted confidence, quarantine
    loop.py      the learning loop itself
"""
