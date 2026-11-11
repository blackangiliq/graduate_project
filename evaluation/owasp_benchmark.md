# Results on the OWASP Benchmark

Measured with `python evaluation/owasp_benchmark.py` (static engines only, no AI provider), tool version 1.3.0. These test cases were not written with the tool. A test case counts as flagged when the tool reports an open finding of the case's own category in its file. `score = TPR - FPR`: 0 is no better than guessing, 1 is perfect.

How to read the history: `owasp_benchmark_baseline.md` holds the first run (version 1.2.0), made before anything in the tool had been written with these cases in view. The Benchmark then showed which weakness types the tool did not know at all. Version 1.3 added them (sink rules for Java; LDAP, XPath, XXE, cookie and session sinks and dead-branch folding for Python) while looking at the odd-numbered cases only. The even-numbered cases were never looked at; their score is reported separately below each table. The cases of one category are generated from shared templates, so the two halves are similar and the even half is a weaker check than a different benchmark would be.

## BenchmarkJava

2740 test cases (expectedresults-1.2.csv, commit db99977 2026-11-09), 281,009 lines, scanned in 17 s. Over all cases in the default mode: 1200 real cases flagged and 215 missed, 522 safe cases flagged and 803 left alone (precision 0.70, recall 0.85).

| Category | Real | Safe | TPR | FPR | Score | Strict: TPR | Strict: FPR | Strict: score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Command injection | 126 | 125 | 70% | 50% | +0.20 | 70% | 50% | +0.20 |
| Weak encryption | 130 | 116 | 100% | 0% | +1.00 | 0% | 0% | +0.00 |
| Weak hash | 129 | 107 | 69% | 0% | +0.69 | 0% | 0% | +0.00 |
| LDAP injection | 27 | 32 | 85% | 56% | +0.29 | 85% | 56% | +0.29 |
| Path traversal | 133 | 135 | 68% | 61% | +0.06 | 68% | 61% | +0.06 |
| Insecure cookie | 36 | 31 | 100% | 0% | +1.00 | 100% | 0% | +1.00 |
| SQL injection | 272 | 232 | 92% | 91% | +0.01 | 82% | 57% | +0.25 |
| Trust boundary violation | 83 | 43 | 75% | 63% | +0.12 | 75% | 63% | +0.12 |
| Weak randomness | 218 | 275 | 100% | 0% | +1.00 | 0% | 0% | +0.00 |
| XPath injection | 15 | 20 | 87% | 65% | +0.22 | 87% | 65% | +0.22 |
| Cross-site scripting | 246 | 209 | 82% | 52% | +0.30 | 80% | 50% | +0.30 |
| **Average over categories** | 1415 | 1325 | **84%** | **40%** | **+0.44** | **59%** | **37%** | **+0.22** |

Average score by half of the test cases (the rules added in version 1.3 were written looking at the odd-numbered cases only):

| Cases | Default: TPR | FPR | score | Strict: TPR | FPR | score |
|---|---:|---:|---:|---:|---:|---:|
| Odd-numbered (seen during development) | 82% | 39% | +0.42 | 56% | 37% | +0.19 |
| Even-numbered (never looked at) | 86% | 40% | +0.46 | 61% | 37% | +0.24 |

## BenchmarkPython

1230 test cases (expectedresults-0.1.csv, commit f129148 2026-05-19), 78,161 lines, scanned in 7 s. Over all cases in the default mode: 346 real cases flagged and 106 missed, 159 safe cases flagged and 619 left alone (precision 0.69, recall 0.77).

| Category | Real | Safe | TPR | FPR | Score | Strict: TPR | Strict: FPR | Strict: score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Command injection | 13 | 7 | 54% | 100% | -0.46 | 54% | 14% | +0.40 |
| Code injection | 20 | 33 | 100% | 100% | +0.00 | 55% | 48% | +0.07 |
| Insecure deserialization | 18 | 36 | 100% | 33% | +0.67 | 72% | 11% | +0.61 |
| Weak hash | 71 | 80 | 100% | 0% | +1.00 | 100% | 0% | +1.00 |
| LDAP injection | 16 | 13 | 75% | 23% | +0.52 | 75% | 23% | +0.52 |
| Path traversal | 65 | 103 | 54% | 20% | +0.33 | 54% | 20% | +0.33 |
| Open redirect | 13 | 21 | 85% | 33% | +0.51 | 85% | 33% | +0.51 |
| Insecure cookie | 24 | 15 | 100% | 0% | +1.00 | 0% | 0% | +0.00 |
| SQL injection | 5 | 11 | 100% | 100% | +0.00 | 40% | 0% | +0.40 |
| Trust boundary violation | 18 | 19 | 56% | 32% | +0.24 | 0% | 0% | +0.00 |
| Weak randomness | 99 | 227 | 78% | 0% | +0.78 | 0% | 0% | +0.00 |
| XPath injection | 51 | 135 | 53% | 32% | +0.21 | 53% | 32% | +0.21 |
| Cross-site scripting | 31 | 58 | 68% | 16% | +0.52 | 68% | 16% | +0.52 |
| XML external entity | 8 | 20 | 100% | 35% | +0.65 | 0% | 0% | +0.00 |
| **Average over categories** | 452 | 778 | **80%** | **37%** | **+0.43** | **47%** | **14%** | **+0.33** |

Average score by half of the test cases (the rules added in version 1.3 were written looking at the odd-numbered cases only):

| Cases | Default: TPR | FPR | score | Strict: TPR | FPR | score |
|---|---:|---:|---:|---:|---:|---:|
| Odd-numbered (seen during development) | 82% | 37% | +0.45 | 50% | 11% | +0.40 |
| Even-numbered (never looked at) | 80% | 38% | +0.42 | 45% | 17% | +0.28 |
