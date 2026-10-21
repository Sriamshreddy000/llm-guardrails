# Results: ollama:llama3.2:3b  (2026-10-21)

Test set: 245 attacks, 154 benign. 95% Wilson intervals. ASR = attack success rate (lower is better). FPR = benign requests wrongly blocked (lower is better).

| Configuration | ASR % | ASR 95% CI | FPR % | FPR 95% CI | Mean latency (s) | p95 (s) | Judge calls / request |
|---|---|---|---|---|---|---|---|
| No defense | 10.6 | 7.3-15.1 | 0.0 | 0.0-2.4 | 3.63 | 8.54 | 0.00 |
| Structural prompt (datamark + reminder) | 11.8 | 8.4-16.5 | 0.0 | 0.0-2.4 | 4.86 | 9.17 | 0.00 |
| Rules (input) | 1.6 | 0.6-4.1 | 1.9 | 0.7-5.6 | 3.58 | 8.54 | 0.00 |
| Classifier (input) | 2.0 | 0.9-4.7 | 3.2 | 1.4-7.4 | 3.52 | 8.54 | 0.00 |
| LLM judge (input) | 6.5 | 4.1-10.3 | 0.0 | 0.0-2.4 | 4.65 | 9.57 | 1.16 |
| Rules (output) | 1.6 | 0.6-4.1 | 0.6 | 0.1-3.6 | 3.63 | 8.54 | 0.00 |
| Canary check (output) | 6.1 | 3.7-9.9 | 0.0 | 0.0-2.4 | 3.63 | 8.54 | 0.00 |
| Rules (input + output) | 0.0 | 0.0-1.5 | 2.6 | 1.0-6.5 | 3.58 | 8.54 | 0.00 |
| Cascade: rules, classifier | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 3.47 | 8.54 | 0.00 |
| Cascade: rules, classifier, judge | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 3.54 | 8.54 | 0.03 |
| Full (no canary) | 0.0 | 0.0-1.5 | 5.8 | 3.1-10.7 | 3.54 | 8.54 | 0.03 |
| Full (+ canary) | 0.0 | 0.0-1.5 | 5.8 | 3.1-10.7 | 3.54 | 8.54 | 0.03 |
| Full (no canary) + structural | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 4.73 | 9.17 | 0.03 |
| Full (+ canary) + structural | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 4.73 | 9.17 | 0.03 |

## ASR % by attack family

| Family | n | No defense | Rules (input) | Classifier (input) | LLM judge (input) | Full (no canary) | Full (+ canary) |
|---|---|---|---|---|---|---|---|
| delimiter | 23 | 13.0 | 0.0 | 0.0 | 8.7 | 0.0 | 0.0 |
| extraction | 22 | 22.7 | 0.0 | 0.0 | 18.2 | 0.0 | 0.0 |
| indirect | 32 | 15.6 | 0.0 | 15.6 | 9.4 | 0.0 | 0.0 |
| multilingual | 22 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| obfuscation | 25 | 4.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| override | 32 | 9.4 | 3.1 | 0.0 | 3.1 | 0.0 | 0.0 |
| payload_split | 25 | 8.0 | 8.0 | 0.0 | 4.0 | 0.0 | 0.0 |
| roleplay | 32 | 12.5 | 0.0 | 0.0 | 9.4 | 0.0 | 0.0 |
| social | 32 | 9.4 | 3.1 | 0.0 | 6.2 | 0.0 | 0.0 |

## Generalisation to attack types never seen in training (leave-one-family-out)

| Held-out family | n | Rules detect % | Classifier detect % | Classifier FPR % |
|---|---|---|---|---|
| delimiter | 48 | 89.6 | 100.0 | 3.2 |
| extraction | 51 | 74.5 | 78.4 | 5.2 |
| indirect | 64 | 93.8 | 1.6 | 4.5 |
| multilingual | 45 | 62.2 | 66.7 | 1.9 |
| obfuscation | 53 | 94.3 | 64.2 | 3.2 |
| override | 64 | 79.7 | 100.0 | 2.6 |
| payload_split | 53 | 71.7 | 100.0 | 5.2 |
| roleplay | 64 | 95.3 | 100.0 | 1.9 |
| social | 64 | 60.9 | 93.8 | 3.9 |
