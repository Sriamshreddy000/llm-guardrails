Adaptive attacks on ollama:llama3.2:3b  (64 direct attacks x 8 variants; 95% Wilson CIs; benign n=154)

| Defense | Static ASR (original wording) | Adaptive ASR (best of 8 rewrites) | Broken by held-out styles only | Mean rewrite # to break | Normal requests blocked |
|---|---|---|---|---|---|
| baseline (no defense) |   7.8% [3-17] |  40.6% [29-53] |   3.1% [1-11] | 1.9 | - |
| rules |   0.0% [0-6] |  17.2% [10-28] |   1.6% [0-8] | 2.4 | - |
| classifier |   0.0% [0-6] |  20.3% [12-32] |   0.0% [0-6] | 3.8 | 3.2% |
| LLM judge |   7.8% [3-17] |  35.9% [25-48] |   3.1% [1-11] | 2.0 | - |
| cascade (rules+clf+judge) |   0.0% [0-6] |   9.4% [4-19] |   0.0% [0-6] | 4.0 | 5.2% |
| full (cascade + output checks) |   0.0% [0-6] |   0.0% [0-6] |   0.0% [0-6] | nan | - |
| R2 classifier |   0.0% [0-6] |   0.0% [0-6] |   0.0% [0-6] | nan | 3.9% |
| R2 cascade |   0.0% [0-6] |   0.0% [0-6] |   0.0% [0-6] | nan | 5.8% |
| R2 full |   0.0% [0-6] |   0.0% [0-6] |   0.0% [0-6] | nan | - |
