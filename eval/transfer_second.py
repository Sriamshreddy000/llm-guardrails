"""Transfer test on any public prompt-injection file (JSONL: text, label, source "<name>/train|test").

Same protocol as the first public dataset, in one script:
  A. guards fitted on OUR data only, evaluated on the whole file (rules, classifier, LLM judge, cascade)
  B. does adding the file's TRAIN split to the classifier fix false alarms? (evaluated on its TEST split only)
If the file has no train/test labels in `source`, a fixed 70/30 split by SHA-1 of the text is used.
Large files are subsampled deterministically (--max-n) so the LLM judge stays affordable.

    python eval/transfer_second.py --file data/public2.jsonl --name safeguard --max-n 1500 \
        --model qwen2.5:7b --host http://127.0.0.1:11434
    python eval/transfer_second.py --file data/public2.jsonl --name safeguard --no-judge     # rules + classifier only

Writes results/transfer_<name>.md and results/transfer_<name>/llm_cache.jsonl (judge answers, resumable).
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
from guardrails.llm import CachedBackend, MockBackend, OllamaBackend  # noqa: E402
from guardrails.pipeline import Cascade  # noqa: E402
from guardrails.rules import InputRules  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--file", required=True)
ap.add_argument("--name", required=True, help="short name used for output files")
ap.add_argument("--max-n", type=int, default=1500, help="subsample size (0 = all)")
ap.add_argument("--judge-n", type=int, default=300, help="items on which the judge is run on EVERY prompt (gating-free reference)")
ap.add_argument("--no-judge", action="store_true")
ap.add_argument("--backend", choices=["ollama", "mock"], default="ollama", help="mock = offline plumbing test, numbers are NOT findings")
ap.add_argument("--model", default="qwen2.5:7b")
ap.add_argument("--host", default="http://localhost:11434")
a = ap.parse_args()


def sha(t):
    return hashlib.sha1(t.encode()).hexdigest()


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / max(1, n):5.1f}% [{100 * lo:.0f}-{100 * hi:.0f}] (n={n})"


def as_rows(items):
    return [{"text": r["text"], "doc": None, "label": r["label"], "template": "pub::" + sha(r["text"])[:12],
             "base": "pub::" + sha(r["text"])[:12], "family": "public", "split": "train"} for r in items]


pub = [json.loads(l) for l in Path(a.file).read_text().splitlines() if l.strip()]
seen, uniq = set(), []
for r in pub:                                    # drop exact duplicates (they would leak between train and test)
    if r["text"] not in seen:
        seen.add(r["text"])
        uniq.append(r)
pub = uniq
if a.max_n and len(pub) > a.max_n:               # deterministic subsample, stratified by label
    pub = sorted(pub, key=lambda r: sha(r["text"]))
    half = a.max_n // 2
    pos = [r for r in pub if r["label"] == 1][:half]
    neg = [r for r in pub if r["label"] == 0][:a.max_n - len(pos)]
    pub = pos + neg
has_split = all(r.get("source", "").endswith(("/train", "/test")) for r in pub)
for r in pub:
    r["part"] = r["source"].rsplit("/", 1)[1] if has_split else ("train" if int(sha(r["text"])[:8], 16) % 10 < 7 else "test")
ptrain = [r for r in pub if r["part"] == "train"]
ptest = [r for r in pub if r["part"] == "test"]
ours = [r for r in load_rows() if r["split"] == "train"]

rules = InputRules()
clf, hi, lo = fit_calibrated(ours)
guards = {"rules": rules, "classifier": clf, "cascade (rules+clf)": Cascade(rules, clf, None, lo=lo, hi=hi)}
judge = None
if not a.no_judge:
    cache = ROOT / "results" / f"transfer_{a.name}"
    cache.mkdir(parents=True, exist_ok=True)
    inner = MockBackend() if a.backend == "mock" else OllamaBackend(a.model, a.host)
    judge = JudgeLayer(CachedBackend(inner, cache / "llm_cache.jsonl"))
    guards["cascade (rules+clf+judge)"] = Cascade(rules, clf, judge, lo=lo, hi=hi)

atk = [r for r in pub if r["label"] == 1]
ben = [r for r in pub if r["label"] == 0]
L = [("**MOCK BACKEND: NOT FINDINGS**\n\n" if a.backend == "mock" else "") + f"# Transfer test: {a.name}  ({len(atk)} injections, {len(ben)} benign after de-duplication and subsampling; "
     f"split: {'from file' if has_split else '70/30 by SHA-1'}; train {len(ptrain)} / test {len(ptest)})\n",
     "## A. Guards fitted on our data only, evaluated on the whole file\n",
     "| Guard | Injections caught | Benign wrongly flagged |", "|---|---|---|"]
for name, g in guards.items():
    tp = sum(g.check(r["text"]).flagged for r in atk)
    fp = sum(g.check(r["text"]).flagged for r in ben)
    L.append(f"| {name} | {pct(tp, len(atk))} | {pct(fp, len(ben))} |")
    print(L[-1], flush=True)
if judge is not None:
    sub = sorted(pub, key=lambda r: sha("j" + r["text"]))[:a.judge_n]
    sa, sb = [r for r in sub if r["label"] == 1], [r for r in sub if r["label"] == 0]
    tp = sum(judge.check(r["text"]).flagged for r in sa)
    fp = sum(judge.check(r["text"]).flagged for r in sb)
    L.append(f"| LLM judge alone ({a.model}, random subset of {len(sub)}) | {pct(tp, len(sa))} | {pct(fp, len(sb))} |")
    print(L[-1], flush=True)

tatk = [r for r in ptest if r["label"] == 1]
tben = [r for r in ptest if r["label"] == 0]
L += ["", "## B. Adding this file's TRAIN split to the classifier (evaluated on its TEST split only)\n",
      "| Classifier trained on | Injections caught | Benign wrongly flagged | block threshold |", "|---|---|---|---|"]
for name, tr in [("our data only", ours), ("our data + this file's train", ours + as_rows(ptrain)),
                 ("this file's train only", as_rows(ptrain))]:
    c, h, _l = fit_calibrated(tr)
    tp = sum(c.check(r["text"]).flagged for r in tatk)
    fp = sum(c.check(r["text"]).flagged for r in tben)
    L.append(f"| {name} | {pct(tp, len(tatk))} | {pct(fp, len(tben))} | {h:.2f} |")
    print(L[-1], flush=True)
(ROOT / "results").mkdir(exist_ok=True)
(ROOT / "results" / f"transfer_{a.name}.md").write_text("\n".join(L) + "\n")
print(f"\nsaved -> results/transfer_{a.name}.md")
