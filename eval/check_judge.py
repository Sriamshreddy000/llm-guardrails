"""One-minute sanity check of the LLM-judge layer before a long run.

    python eval/check_judge.py --backend ollama --model llama3.2:3b --host http://127.0.0.1:11434

Shows what the judge says about a few attacks and a few normal requests. Look for:
  * UNPARSED = 0   (every answer is a clean ATTACK / SAFE verdict)
  * most attacks flagged, few normal requests flagged
"""
import argparse, json, random, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guardrails.judge import JudgeLayer  # noqa: E402
from guardrails.llm import MockBackend, OllamaBackend  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--backend", choices=["mock", "ollama"], default="ollama")
ap.add_argument("--model", default="llama3.2:3b")
ap.add_argument("--host", default="http://localhost:11434")
ap.add_argument("--n", type=int, default=12)
a = ap.parse_args()

rows = [json.loads(l) for l in (ROOT / "data" / "dataset.jsonl").read_text().splitlines() if l.strip()]
test = [r for r in rows if r["split"] == "test"]
rng = random.Random(0)
atk, ben = [r for r in test if r["label"] == 1], [r for r in test if r["label"] == 0]
pick = rng.sample(atk, a.n) + rng.sample(ben, a.n)
judge = JudgeLayer(MockBackend() if a.backend == "mock" else OllamaBackend(a.model, a.host))
hit = {1: 0, 0: 0}
for r in pick:
    part = r["doc"] or r["text"]
    v = judge.check(part)
    hit[r["label"]] += v.flagged
    print(f"{'ATTACK' if r['label'] else 'normal':6s} -> judge says {v.reason:8s} | {r['family']:13s} | {part[:70]!r}")
print(f"\nattacks flagged: {hit[1]}/{a.n}   normal requests wrongly flagged: {hit[0]}/{a.n}   judge answers: {dict(judge.stats)}")
