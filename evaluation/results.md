# Evaluation results

Samples: `samples/vulnerable_app` (71 labelled vulnerabilities, 5 of them marked hard, 21 safe decoy lines) and `samples/safe_app` (no vulnerabilities).

These samples were written together with the tool. The numbers show that the pipeline works end to end; they are not an unbiased benchmark.

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Bandit only (Python baseline) | 15 | 4 | 56 | 0.789 | 0.211 | 0.333 |
| Pattern rules + secrets | 48 | 3 | 23 | 0.941 | 0.676 | 0.787 |
| + Python AST taint engine | 66 | 3 | 5 | 0.957 | 0.930 | 0.943 |
| All static engines | 66 | 7 | 5 | 0.904 | 0.930 | 0.917 |
| All static, strict mode (confirmed only) | 43 | 0 | 28 | 1.000 | 0.606 | 0.754 |

## Missed (All static engines)

- `app.py:142` CWE-639 (hard): missing ownership check (IDOR) - a logic flaw
- `index.php:4` CWE-798 (hard): password passed as a positional argument: no variable name to recognize
- `parser.c:36` CWE-120 (hard): memcpy with an unchecked length
- `parser.c:40` CWE-190 (hard): integer overflow in the allocation size
- `server.js:72` CWE-1321 (hard): prototype pollution in a recursive merge

## False positives (All static engines)

- `safe_app/index.php:17` CWE-98 File inclusion using a variable path (engines: rules)
- `safe_app/app.py:116` CWE-78 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell (engines: bandit)
- `safe_app/app.py:25` CWE-798 Possible hardcoded password: 'Enter your password' (engines: bandit)
- `safe_app/app.py:26` CWE-798 Possible hardcoded password: 'https://auth.example.com/oauth/token' (engines: bandit)
- `safe_app/index.php:23` CWE-327 Weak hash function (MD5 / SHA-1) (engines: rules)
- `safe_app/safe.c:34` CWE-338 rand() is not suitable for security values (engines: rules)
- `app.py:131` CWE-338 Standard pseudo-random generators are not suitable for security/cryptographic purposes. (engines: bandit)
