"""Transfer test: guards fitted on OUR data, evaluated on a PUBLIC prompt-injection dataset.

Only detection can be measured here (public prompts don't target our secrets), so we report
recall on injections and false-positive rate on benign prompts, with 95% Wilson intervals.

    python eval/eval_public.py                         # rules + classifier (no model needed)
    python eval/eval_public.py --backend ollama --model llama3.2:3b   # adds the LLM judge
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_eval import fit_calibrated, load_rows, wilson  # noqa: E402
from guardrails.judge import JudgeLayer  # noqa: E402
from guardrails.llm import CachedBackend, OllamaBackend  # noqa: E402
from guardrails.pipeline import Cascade  # noqa: E402
from guardrails.rules import InputRules  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--file", default=str(ROOT / "data" / "public.jsonl"))
ap.add_argument("--backend", choices=["none", "ollama"], default="none")
ap.add_argument("--model", default="llama3.2:3b")
ap.add_argument("--host", default="http://localhost:11434")
ap.add_argument("--out", default="public_transfer")
a = ap.parse_args()

pub = [json.loads(l) for l in Path(a.file).read_text().splitlines() if l.strip()]
train = [r for r in load_rows() if r["split"] == "train"]
clf, hi, lo = fit_calibrated(train)
rules = InputRules()
guards = {"rules": rules, "classifier": clf, "cascade_rules_clf": Cascade(rules, clf, None, lo=lo, hi=hi)}
if a.backend == "ollama":
    out = ROOT / "results" / a.out
    out.mkdir(parents=True, exist_ok=True)
    judge = JudgeLayer(CachedBackend(OllamaBackend(a.model, a.host), out / "llm_cache.jsonl"))
    guards["judge"] = judge
    guards["cascade_full"] = Cascade(rules, clf, judge, lo=lo, hi=hi)

atk = [r for r in pub if r["label"] == 1]
ben = [r for r in pub if r["label"] == 0]
res = {}
for name, g in guards.items():
    tp = sum(g.check(r["text"]).flagged for r in atk)
    fp = sum(g.check(r["text"]).flagged for r in ben)
    res[name] = {"recall": tp / len(atk), "recall_ci": wilson(tp, len(atk)), "fpr": fp / max(1, len(ben)),
                 "fpr_ci": wilson(fp, len(ben)), "n_attack": len(atk), "n_benign": len(ben)}
    print(f"{name:20s} recall {100*res[name]['recall']:5.1f}%  FPR {100*res[name]['fpr']:5.1f}%   (n={len(atk)} attacks, {len(ben)} benign)")
Path(ROOT / "results").mkdir(exist_ok=True)
(ROOT / "results" / "public_transfer.json").write_text(json.dumps(res, indent=2))
