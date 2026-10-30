Runs compared (llama32_3b: target ollama:llama3.2:3b, judge ollama:llama3.2:3b, 245 attacks / 154 benign; llama32_3b_qj: target ollama:llama3.2:3b, judge ollama:qwen2.5:7b, 245 attacks / 154 benign; qwen25_3b: target ollama:qwen2.5:3b, judge ollama:qwen2.5:7b, 245 attacks / 154 benign). 95% Wilson intervals.

| Configuration | llama32_3b ASR % [CI] | llama32_3b_qj ASR % [CI] | qwen25_3b ASR % [CI] | llama32_3b FPR % [CI] | llama32_3b_qj FPR % [CI] | qwen25_3b FPR % [CI] |
|---|---|---|---|---|---|---|
| No defense | 10.6 [7-15] | 10.6 [7-15] | 61.6 [55-67] | 0.0 [0-2] | 0.0 [0-2] | 0.0 [0-2] |
| Structural prompt | 11.8 [8-16] | - | 63.3 [57-69] | 0.0 [0-2] | - | 0.0 [0-2] |
| Rules | 1.6 [1-4] | - | 6.5 [4-10] | 1.9 [1-6] | - | 1.9 [1-6] |
| Classifier | 2.0 [1-5] | - | 4.9 [3-8] | 3.2 [1-7] | - | 2.6 [1-6] |
| LLM judge | 6.5 [4-10] | 0.8 [0-3] | 0.8 [0-3] | 0.0 [0-2] | 4.5 [2-9] | 5.8 [3-11] |
| Rules in+out | 0.0 [0-2] | - | 3.3 [2-6] | 2.6 [1-6] | - | 1.9 [1-6] |
| Cascade (input) | 0.0 [0-2] | 0.0 [0-2] | 0.0 [0-2] | 5.2 [3-10] | 5.8 [3-11] | 5.2 [3-10] |
| Full (no canary) | 0.0 [0-2] | 0.0 [0-2] | 0.0 [0-2] | 5.8 [3-11] | 6.5 [4-12] | 5.2 [3-10] |
| Full (+ canary) | 0.0 [0-2] | 0.0 [0-2] | 0.0 [0-2] | 5.8 [3-11] | 6.5 [4-12] | 5.2 [3-10] |
| Scope check alone | - | 1.2 [0-4] | 3.3 [2-6] | - | 11.7 [8-18] | 10.4 [6-16] |
| Full (no canary) + scope | - | 0.0 [0-2] | 0.0 [0-2] | - | 17.5 [12-24] | 13.6 [9-20] |
