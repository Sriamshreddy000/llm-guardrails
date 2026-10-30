# Results: ollama:qwen2.5:3b  (2026-10-29)

Test set: 245 attacks, 154 benign. 95% Wilson intervals. ASR = attack success rate (lower is better). FPR = benign requests wrongly blocked (lower is better).

| Configuration | ASR % | ASR 95% CI | FPR % | FPR 95% CI | Mean latency (s) | p95 (s) | Judge calls / request |
|---|---|---|---|---|---|---|---|
| No defense | 61.6 | 55.4-67.5 | 0.0 | 0.0-2.4 | 2.32 | 4.76 | 0.00 |
| Structural prompt (datamark + reminder) | 63.3 | 57.1-69.1 | 0.0 | 0.0-2.4 | 3.66 | 6.98 | 0.00 |
| Rules (input) | 6.5 | 4.1-10.3 | 1.9 | 0.7-5.6 | 2.27 | 4.76 | 0.00 |
| Classifier (input) | 4.9 | 2.8-8.4 | 2.6 | 1.0-6.5 | 2.23 | 4.76 | 0.00 |
| LLM judge (input) | 0.8 | 0.2-2.9 | 5.8 | 3.1-10.7 | 3.59 | 7.67 | 1.16 |
| Rules (output) | 26.9 | 21.8-32.8 | 0.0 | 0.0-2.4 | 2.32 | 4.76 | 0.00 |
| Canary check (output) | 24.5 | 19.5-30.2 | 0.0 | 0.0-2.4 | 2.32 | 4.76 | 0.00 |
| Rules (input + output) | 3.3 | 1.7-6.3 | 1.9 | 0.7-5.6 | 2.27 | 4.76 | 0.00 |
| Cascade: rules, classifier | 0.0 | 0.0-1.5 | 4.5 | 2.2-9.1 | 2.19 | 4.76 | 0.00 |
| Cascade: rules, classifier, judge | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 2.29 | 5.25 | 0.03 |
| Full (no canary) | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 2.29 | 5.25 | 0.03 |
| Full (+ canary) | 0.0 | 0.0-1.5 | 5.2 | 2.7-9.9 | 2.29 | 5.26 | 0.03 |
| Full (no canary) + structural | 0.0 | 0.0-1.5 | 6.5 | 3.6-11.5 | 3.55 | 6.98 | 0.03 |
| Full (+ canary) + structural | 0.0 | 0.0-1.5 | 6.5 | 3.6-11.5 | 3.55 | 6.98 | 0.03 |
| Scope check (output) | 3.3 | 1.7-6.3 | 10.4 | 6.5-16.2 | 4.12 | 6.89 | 1.00 |
| Full (no canary) + scope check | 0.0 | 0.0-1.5 | 13.6 | 9.1-19.9 | 3.90 | 6.90 | 0.38 |
| Full (+ canary) + scope check | 0.0 | 0.0-1.5 | 13.6 | 9.1-19.9 | 3.90 | 6.90 | 0.38 |

## ASR % by attack family

| Family | n | No defense | Rules (input) | Classifier (input) | LLM judge (input) | Full (no canary) | Full (+ canary) | Scope check (output) | Full (no canary) + scope check |
|---|---|---|---|---|---|---|---|---|---|
| delimiter | 23 | 87.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| extraction | 22 | 36.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| indirect | 32 | 56.2 | 0.0 | 37.5 | 3.1 | 0.0 | 0.0 | 0.0 | 0.0 |
| multilingual | 22 | 59.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| obfuscation | 25 | 32.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| override | 32 | 84.4 | 12.5 | 0.0 | 0.0 | 0.0 | 0.0 | 12.5 | 0.0 |
| payload_split | 25 | 60.0 | 16.0 | 0.0 | 0.0 | 0.0 | 0.0 | 4.0 | 0.0 |
| roleplay | 32 | 65.6 | 6.2 | 0.0 | 3.1 | 0.0 | 0.0 | 6.2 | 0.0 |
| social | 32 | 65.6 | 18.8 | 0.0 | 0.0 | 0.0 | 0.0 | 3.1 | 0.0 |

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
