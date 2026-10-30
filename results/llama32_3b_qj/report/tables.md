# Results: ollama:llama3.2:3b  (2026-10-29)

Test set: 245 attacks, 154 benign. 95% Wilson intervals. ASR = attack success rate (lower is better). FPR = benign requests wrongly blocked (lower is better).

| Configuration | ASR % | ASR 95% CI | FPR % | FPR 95% CI | Mean latency (s) | p95 (s) | Judge calls / request |
|---|---|---|---|---|---|---|---|
| No defense | 10.6 | 7.3-15.1 | 0.0 | 0.0-2.4 | 3.63 | 8.54 | 0.00 |
| LLM judge (input) | 0.8 | 0.2-2.9 | 4.5 | 2.2-9.1 | 4.72 | 9.86 | 1.16 |
| Cascade: rules, classifier, judge | 0.0 | 0.0-1.5 | 5.8 | 3.1-10.7 | 3.56 | 8.66 | 0.03 |
| Full (no canary) | 0.0 | 0.0-1.5 | 6.5 | 3.6-11.5 | 3.56 | 8.66 | 0.03 |
| Full (+ canary) | 0.0 | 0.0-1.5 | 6.5 | 3.6-11.5 | 3.56 | 8.66 | 0.03 |
| Scope check (output) | 1.2 | 0.4-3.5 | 11.7 | 7.5-17.7 | 5.75 | 11.76 | 1.00 |
| Full (no canary) + scope check | 0.0 | 0.0-1.5 | 17.5 | 12.3-24.3 | 5.52 | 11.91 | 0.39 |
| Full (+ canary) + scope check | 0.0 | 0.0-1.5 | 17.5 | 12.3-24.3 | 5.49 | 11.91 | 0.38 |

## ASR % by attack family

| Family | n | No defense | LLM judge (input) | Full (no canary) | Full (+ canary) | Scope check (output) | Full (no canary) + scope check |
|---|---|---|---|---|---|---|---|
| delimiter | 23 | 13.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| extraction | 22 | 22.7 | 4.5 | 0.0 | 0.0 | 0.0 | 0.0 |
| indirect | 32 | 15.6 | 3.1 | 0.0 | 0.0 | 3.1 | 0.0 |
| multilingual | 22 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| obfuscation | 25 | 4.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| override | 32 | 9.4 | 0.0 | 0.0 | 0.0 | 3.1 | 0.0 |
| payload_split | 25 | 8.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| roleplay | 32 | 12.5 | 0.0 | 0.0 | 0.0 | 3.1 | 0.0 |
| social | 32 | 9.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

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
