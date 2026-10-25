Benign requests blocked by the classifier, by wrapper style (n=124 each; 95% Wilson CI)

| Wrapper style | Round-1 classifier | Round-2 classifier | In round-2 training? |
|---|---|---|---|
| original |   3.2% [1-8] |   4.8% [2-10] | - |
| soften |   2.4% [1-7] |   4.8% [2-10] | yes |
| polite |   4.0% [2-9] |  47.6% [39-56] | yes |
| soften_polite |   3.2% [1-8] |  46.8% [38-56] | yes |
| pad |   0.0% [0-3] | 100.0% [97-100] | yes |
| quote |   0.8% [0-4] |  77.4% [69-84] | yes |
| story |  23.4% [17-32] |  41.9% [34-51] | no (held out) |
| story_pad |   0.0% [0-3] | 100.0% [97-100] | no (held out) |

Benign requests blocked, adaptive_search.py retraining (n=124 each; 95% Wilson CI); round-2 block threshold 0.719

| Wrapper | Original classifier | Retrained classifier (adversarial + augmented benign) |
|---|---|---|
| (unwrapped) |   3.2% [1-8] |   0.0% [0-3] |
| homoglyph |   3.2% [1-8] |   0.8% [0-4] |
| judge_note |  24.2% [18-32] |  80.6% [73-87] |
| pad |   0.0% [0-3] |   8.1% [4-14] |
| soften |   5.6% [3-11] |   0.0% [0-3] |
| story |  29.0% [22-38] |   0.0% [0-3] |
| synonyms |   2.4% [1-7] |   0.0% [0-3] |
| random 1-3 operators |  16.1% [11-24] |  24.2% [18-32] |
