# Results on the OWASP Benchmark

Measured with `python evaluation/owasp_benchmark.py` (static engines only, no AI provider), tool version 1.2.0. These test cases were not written with the tool and no rule was tuned on them. A test case counts as flagged when the tool reports an open finding of the case's own category in its file. `score = TPR - FPR`: 0 is no better than guessing, 1 is perfect.

## BenchmarkJava

2740 test cases (expectedresults-1.2.csv, commit db99977 2026-11-09), 281,009 lines, scanned in 13 s. Over all cases in the default mode: 473 real cases flagged and 942 missed, 213 safe cases flagged and 1112 left alone (precision 0.69, recall 0.33).

| Category | Real | Safe | TPR | FPR | Score | Strict: TPR | Strict: FPR | Strict: score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Command injection | 126 | 125 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Weak encryption | 130 | 116 | 100% | 0% | +1.00 | 0% | 0% | +0.00 |
| Weak hash | 129 | 107 | 69% | 0% | +0.69 | 0% | 0% | +0.00 |
| LDAP injection | 27 | 32 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Path traversal | 133 | 135 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Insecure cookie | 36 | 31 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| SQL injection | 272 | 232 | 89% | 89% | -0.00 | 51% | 36% | +0.16 |
| Trust boundary violation | 83 | 43 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Weak randomness | 218 | 275 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| XPath injection | 15 | 20 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Cross-site scripting | 246 | 209 | 5% | 3% | +0.02 | 4% | 1% | +0.02 |
| **Average over categories** | 1415 | 1325 | **24%** | **8%** | **+0.16** | **5%** | **3%** | **+0.02** |

## BenchmarkPython

1230 test cases (expectedresults-0.1.csv, commit f129148 2026-05-19), 78,161 lines, scanned in 6 s. Over all cases in the default mode: 265 real cases flagged and 187 missed, 115 safe cases flagged and 663 left alone (precision 0.70, recall 0.59).

| Category | Real | Safe | TPR | FPR | Score | Strict: TPR | Strict: FPR | Strict: score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Command injection | 13 | 7 | 54% | 100% | -0.46 | 54% | 14% | +0.40 |
| Code injection | 20 | 33 | 100% | 100% | +0.00 | 55% | 55% | +0.00 |
| Insecure deserialization | 18 | 36 | 100% | 33% | +0.67 | 72% | 17% | +0.56 |
| Weak hash | 71 | 80 | 100% | 0% | +1.00 | 100% | 0% | +1.00 |
| LDAP injection | 16 | 13 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Path traversal | 65 | 103 | 54% | 29% | +0.25 | 54% | 29% | +0.25 |
| Open redirect | 13 | 21 | 85% | 43% | +0.42 | 85% | 43% | +0.42 |
| Insecure cookie | 24 | 15 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| SQL injection | 5 | 11 | 100% | 100% | +0.00 | 40% | 0% | +0.40 |
| Trust boundary violation | 18 | 19 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Weak randomness | 99 | 227 | 78% | 0% | +0.78 | 0% | 0% | +0.00 |
| XPath injection | 51 | 135 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| Cross-site scripting | 31 | 58 | 68% | 22% | +0.45 | 68% | 22% | +0.45 |
| XML external entity | 8 | 20 | 0% | 0% | +0.00 | 0% | 0% | +0.00 |
| **Average over categories** | 452 | 778 | **53%** | **31%** | **+0.22** | **38%** | **13%** | **+0.25** |
