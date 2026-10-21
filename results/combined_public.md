Public TEST split: 60 injections, 56 benign.  Judge: qwen2.5:7b.  95% Wilson CIs.

| Stack | Injections caught | Normal prompts wrongly flagged |
|---|---|---|
| classifier (our data only) |  68.3% [56-79] |  33.9% [23-47] |
| rules + classifier + judge (our data only) |  76.7% [65-86] |  33.9% [23-47] |
| classifier (our data + public train) |  76.7% [65-86] |   0.0% [0-6] |
| rules + classifier + judge (our data + public train) |  81.7% [70-89] |   0.0% [0-6] |
| classifier (public train only) |  70.0% [57-80] |   0.0% [0-6] |
| rules + classifier + judge (public train only) |  76.7% [65-86] |   0.0% [0-6] |
| judge alone |  40.0% [29-53] |   0.0% [0-6] |
| rules OR adapted classifier OR judge (always ask judge) |  81.7% [70-89] |   0.0% [0-6] |
