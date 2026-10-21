"""A calibrated stack on the public set: domain-adapted classifier + rules + LLM judge, evaluated on the public TEST split.

Uses cached judge answers when available (run eval_public.py with the same --model first), otherwise calls Ollama.

    python eval/combined_public.py --model qwen2.5:7b --host http://127.0.0.1:11434 --cache public_qwen7b
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_eval import fit_calibrated, load_rows, wilson  # noqa: E402
from guardrails.judge import JudgeLayer  # noqa: E402
from guardrails.llm import CachedBackend, OllamaBackend  # noqa: E402
from guardrails.pipeline import Cascade  # noqa: E402
from guardrails.rules import InputRules  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="qwen2.5:7b")
ap.add_argument("--host", default="http://localhost:11434")
ap.add_argument("--cache", default="public_qwen7b", help="results/<cache>/llm_cache.jsonl from eval_public.py")
a = ap.parse_args()

pub = [json.loads(l) for l in (ROOT / "data" / "public.jsonl").read_text().splitlines() if l.strip()]
ptrain = [r for r in pub if r["source"].endswith("train")]
ptest = [r for r in pub if r["source"].endswith("test")]
ours = [r for r in load_rows() if r["split"] == "train"]


def as_rows(items):
    return [{"text": r["text"], "doc": None, "label": r["label"], "template": "pub::" + hashlib.sha1(r["text"].encode()).hexdigest()[:12],
             "base": "pub::" + hashlib.sha1(r["text"].encode()).hexdigest()[:12], "family": "public", "split": "train"} for r in items]


rules = InputRules()
judge = JudgeLayer(CachedBackend(OllamaBackend(a.model, a.host), ROOT / "results" / a.cache / "llm_cache.jsonl"))
atk = [r for r in ptest if r["label"] == 1]
ben = [r for r in ptest if r["label"] == 0]


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f}% [{100 * lo:.0f}-{100 * hi:.0f}]"


lines = [f"Public TEST split: {len(atk)} injections, {len(ben)} benign.  Judge: {a.model}.  95% Wilson CIs.\n",
         "| Stack | Injections caught | Normal prompts wrongly flagged |", "|---|---|---|"]
res = {}
for name, train in [("our data only", ours), ("our data + public train", ours + as_rows(ptrain)),
                    ("public train only", as_rows(ptrain))]:
    clf, hi, lo = fit_calibrated(train)
    print(f"[operating point] {name}: block>={hi:.4f} pass<={lo:.4f}", file=sys.stderr)
    stacks = {f"classifier ({name})": clf,
              f"rules + classifier + judge ({name})": Cascade(rules, clf, judge, lo=lo, hi=hi)}
    for sname, g in stacks.items():
        tp = sum(g.check(r["text"]).flagged for r in atk)
        fp = sum(g.check(r["text"]).flagged for r in ben)
        lines.append(f"| {sname} | {pct(tp, len(atk))} | {pct(fp, len(ben))} |")
        res[sname] = {"tp": tp, "fp": fp}
# judge on every prompt (no gating), as a reference
tp = sum(judge.check(r["text"]).flagged for r in atk)
fp = sum(judge.check(r["text"]).flagged for r in ben)
lines.append(f"| judge alone | {pct(tp, len(atk))} | {pct(fp, len(ben))} |")
# union: block if classifier(adapted) OR judge flags
clf, hi, lo = fit_calibrated(ours + as_rows(ptrain))
union = lambda t: clf.check(t).flagged or judge.check(t).flagged or rules.check(t).flagged  # noqa: E731
tp = sum(union(r["text"]) for r in atk)
fp = sum(union(r["text"]) for r in ben)
lines.append(f"| rules OR adapted classifier OR judge (always ask judge) | {pct(tp, len(atk))} | {pct(fp, len(ben))} |")
text = "\n".join(lines)
print(text)
(ROOT / "results" / "combined_public.md").write_text(text + "\n")
