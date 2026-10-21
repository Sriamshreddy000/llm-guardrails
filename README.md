# llm-guardrails

Layered defenses against prompt injection for LLM apps, with an honest measurement of what they cost.

A fictional support bot ("Aria") holds fake secrets. We attack it with nine families of prompt injection
(direct, indirect via documents, obfuscated, multilingual, social-engineering, ...), put guardrails in
front of it, and measure **attack success rate (ASR)**, **false-positive rate (FPR)**, **latency**, and
**how often the expensive LLM judge is needed**. The paper in `paper/` is a work-in-progress draft (sections marked `\todo{}` are unwritten).

```
attack ──► [ rules ] ─► [ classifier ] ─► [ LLM judge (only if unsure) ] ──► Aria (LLM) ──► [ output checks ] ──► reply
              cheap          cheap                 costly                                      PII / prompt overlap / canary
```

## Setup (Mac, Apple Silicon)

```bash
# 1. a local model (free, no API key needed)
brew install ollama            # or install the app from ollama.com
ollama serve &                 # skip if the Ollama app is already running
ollama pull llama3.2:3b        # ~2 GB, fine for an M1 Air with 8 GB RAM

# 2. python deps
cd llm-guardrails
pip install -r requirements.txt

# 3. sanity checks (no model needed)
python tests/test_basic.py
python data/build_dataset.py   # regenerates data/dataset.jsonl (already included)
```

## Run

```bash
# 0. one-minute check that the LLM-judge layer answers cleanly (UNPARSED should be 0)
python eval/check_judge.py --backend ollama --model llama3.2:3b --host http://127.0.0.1:11434

# 1. full run (roughly 1-2 hours on an M1 Air). Everything is cached on disk, so you can stop with
#    Ctrl-C and re-run the same command to resume. caffeinate keeps the Mac awake.
mkdir -p results/llama32_3b && cp results/trial/llm_cache.jsonl results/llama32_3b/ 2>/dev/null   # reuse earlier answers
caffeinate -i python eval/run_eval.py --backend ollama --model llama3.2:3b --host http://127.0.0.1:11434 --out llama32_3b

# 2. tables + figure + paper numbers
python eval/make_report.py llama32_3b          # -> results/llama32_3b/report/ and paper/generated/

# 3. transfer to a public dataset (answers "you wrote the attacks yourself")
python data/fetch_public.py
python eval/eval_public.py --backend ollama --model llama3.2:3b
```

`--per-family N` caps the number of ATTACKS per family (normal requests are never capped) if you want a faster, rougher run.

Use a laptop on power, and keep it cool: long runs on a fanless Air can throttle.


## Results so far (Llama 3.2 3B, one seed; work in progress)

On our own generated benchmark (245 attacks, 154 normal requests), rules + classifier + judge stop all attacks
(0 of 245; 95% CI 0-1.5%) at a 3.9% false-positive rate; with no defense 10.6% of attacks succeed.
**This does not transfer.** On an independent public dataset ([deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections),
263 injections, 399 benign), the same guards catch far fewer injections:

| Guard | Injections caught | Normal prompts wrongly flagged |
|---|---|---|
| Rules | 8.4% | 0.0% |
| Classifier | 60.5% | 29.6% |
| LLM judge (Llama 3.2 3B) | 39.5% | 0.8% |
| Full cascade | 71.1% | 29.6% |

Retraining the classifier with public training data removes the false alarms (23% to 0% on the public test split)
but recall stays near 70%. Full tables: `results/llama32_3b/report/tables.md` and `results/public_analysis.md`.
Limitations: self-authored attacks, non-adaptive attacks, one small model, small public test split. Check the dataset license before reuse.

## Test pipeline with the fake model (not findings)

`--backend mock` uses a deterministic fake LLM so you can check the code without Ollama. **Its numbers mean nothing.**
`make_report.py` refuses to write mock results into the paper unless you pass `--allow-mock`, and then stamps a red banner on it.

## Layout

| Path | What |
|---|---|
| `guardrails/target_app.py` | the bot, its fake secrets, the structural (datamark + reminder) defense |
| `guardrails/rules.py` | input rules, generic output checks, canary output check |
| `guardrails/classifier.py` | TF-IDF + logistic regression, threshold calibration from out-of-fold scores |
| `guardrails/judge.py` | LLM-as-judge layer |
| `guardrails/pipeline.py` | `GuardedBot` and the rules → classifier → judge `Cascade` |
| `guardrails/llm.py` | backends: Ollama, Anthropic (API key), Mock; on-disk cache |
| `data/build_dataset.py` | attack and benign generator; split by template; hard negatives |
| `eval/oracle.py` | decides attack success by string checks (no LLM grading itself) |
| `eval/run_eval.py` | runs 14 configurations, writes `results/<run>/summary.json` and `samples.jsonl` |
| `eval/make_report.py` | markdown + LaTeX tables, trade-off figure, paper macros |
| `eval/eval_public.py` | detection on a public prompt-injection dataset |
| `paper/main.tex` | the paper; `\todo{}` marks what you must write after seeing results |

## Compile the paper

```bash
cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main
```
(or upload the `paper/` folder to Overleaf). Numbers come from `paper/generated/`, written by `make_report.py`.

## What is honest about this setup, and what is not

- Attacks and rules were written by the same author, so rules may look better than they would on someone else's attacks.
  Mitigations: split by template, leave-one-family-out, and the public-dataset transfer test. Run it.
- Attacks are non-adaptive. A real attacker probing the guardrail would do better.
- One small model, one app, one seed. Say so in the paper, and consider adding a second model with `--model`.
- Verify every entry in `paper/references.bib` against its source before submitting anything.
- Never present `--backend mock` output as a result.
