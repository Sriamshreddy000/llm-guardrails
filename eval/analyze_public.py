"""Deeper look at the public-dataset transfer result (no new model calls: judge answers come from the cache).

  A. recall / FPR by language (the public set is partly German) and by guard
  B. does adding public TRAIN data to the classifier fix the transfer gap? (evaluated on the public TEST split only)

    python eval/analyze_public.py
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_eval import fit_calibrated, load_rows, wilson  # noqa: E402
from guardrails.classifier import ClassifierLayer  # noqa: E402
from guardrails.judge import JudgeLayer  # noqa: E402
from guardrails.llm import CachedBackend, OllamaBackend  # noqa: E402
from guardrails.pipeline import Cascade  # noqa: E402
from guardrails.rules import InputRules  # noqa: E402

DE = set("der die das und ist nicht ein eine zu den mit für auf sie ich wie was wer warum wann wo kann bitte von im dem es sich auch als oder wenn aber haben hat sind wird werden".split())


def lang(t):
    w = re.findall(r"[a-zäöüß]+", t.lower())
    hits = sum(x in DE for x in w)
    return "de" if (hits >= 2 and hits / max(1, len(w)) > 0.12) or re.search(r"[äöüß]", t.lower()) and hits >= 1 else "en"


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / max(1, n):5.1f}% [{100 * lo:.0f}-{100 * hi:.0f}] (n={n})"


pub = [json.loads(l) for l in (ROOT / "data" / "public.jsonl").read_text().splitlines() if l.strip()]
for r in pub:
    r["lang"] = lang(r["text"])
ours_train = [r for r in load_rows() if r["split"] == "train"]
clf, hi, lo = fit_calibrated(ours_train)
rules = InputRules()
backend = CachedBackend(OllamaBackend("llama3.2:3b", "http://127.0.0.1:1"), ROOT / "results" / "public_transfer" / "llm_cache.jsonl")
judge = JudgeLayer(backend)
guards = {"rules": rules, "classifier": clf, "judge": judge, "cascade_full": Cascade(rules, clf, judge, lo=lo, hi=hi)}

flag = {n: [g.check(r["text"]).flagged for r in pub] for n, g in guards.items()}
out = ["# A. Public-set results by language (guards fitted on our data only)\n"]
out.append("Language counts: " + ", ".join(f"{L}: {sum(r['lang'] == L and r['label'] == 1 for r in pub)} attacks / "
                                          f"{sum(r['lang'] == L and r['label'] == 0 for r in pub)} benign" for L in ("en", "de")) + "\n")
out.append("| Guard | Language | Recall (CI) | False-positive rate (CI) |\n|---|---|---|---|")
for n in guards:
    for L in ("en", "de", "all"):
        idx = [i for i, r in enumerate(pub) if L == "all" or r["lang"] == L]
        a = [i for i in idx if pub[i]["label"] == 1]
        b = [i for i in idx if pub[i]["label"] == 0]
        out.append(f"| {n} | {L} | {pct(sum(flag[n][i] for i in a), len(a))} | {pct(sum(flag[n][i] for i in b), len(b))} |")

# B. domain adaptation: train on ours (+ public TRAIN), test on public TEST only
ptrain = [r for r in pub if r["source"].endswith("train")]
ptest = [r for r in pub if r["source"].endswith("test")]


def as_rows(items):
    return [{"text": r["text"], "doc": None, "label": r["label"], "template": f"pub::{hash(r['text'])}",
             "base": f"pub::{hash(r['text'])}", "family": "public", "split": "train"} for r in items]


def evaluate(name, train_rows, use_rules_cascade=False):
    c, h, l = fit_calibrated(train_rows)
    a = [r for r in ptest if r["label"] == 1]
    b = [r for r in ptest if r["label"] == 0]
    tp = sum(c.check(r["text"]).flagged for r in a)
    fp = sum(c.check(r["text"]).flagged for r in b)
    return f"| {name} | {pct(tp, len(a))} | {pct(fp, len(b))} | {h:.2f} |"


out += ["\n# B. Does adding public TRAIN data fix the classifier? (evaluated on public TEST only)\n",
        "| Classifier trained on | Recall (CI) | False-positive rate (CI) | block threshold |\n|---|---|---|---|"]
out.append(evaluate("our data only", ours_train))
out.append(evaluate("public train only", as_rows(ptrain)))
out.append(evaluate("our data + public train", ours_train + as_rows(ptrain)))
# judge on the same test split for reference
a = [i for i, r in enumerate(pub) if r["source"].endswith("test") and r["label"] == 1]
b = [i for i, r in enumerate(pub) if r["source"].endswith("test") and r["label"] == 0]
out.append(f"| (reference) LLM judge, no training | {pct(sum(flag['judge'][i] for i in a), len(a))} | {pct(sum(flag['judge'][i] for i in b), len(b))} | - |")

# misses worth looking at
miss = [r["text"][:110].replace("\n", " ") for i, r in enumerate(pub) if r["label"] == 1 and not flag["cascade_full"][i]]
out += ["\n# C. A few injections the full cascade missed\n"] + [f"- {m}" for m in miss[:10]]

text = "\n".join(out)
print(text)
(ROOT / "results" / "public_analysis.md").write_text(text + "\n")
