"""Control for the round-2 (retrained) classifier in eval/adaptive.py.

Round 2 retrains the classifier on REWRITTEN ATTACKS only. A classifier trained that way may simply learn that polite
openers, filler sentences and "write a scene where Sam answers" wrappers mean "attack", which would drive the attack
success rate to zero while blocking ordinary customers who write politely. eval/adaptive.py measures false positives only
on plain benign requests, so it cannot see this. Here we wrap the SAME benign test requests in the same rewrite styles and
count how many each classifier blocks.

    python eval/benign_wrapped.py
"""
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.adaptive import HELD_OUT, variants  # noqa: E402
from eval.run_eval import fit_calibrated, load_rows, wilson  # noqa: E402

rows = load_rows()
train = [r for r in rows if r["split"] == "train"]
test = [r for r in rows if r["split"] == "test"]
benign = [r for r in test if r["label"] == 0 and not r["doc"]]

# same round-2 training set as eval/adaptive.py
extra = []
for r in train:
    if r["label"] == 1 and not r["doc"]:
        for name, t in variants(r["text"])[1:]:
            if name not in HELD_OUT:
                extra.append({**r, "text": t})
clf1, hi1, _ = fit_calibrated(train)
clf2, hi2, _ = fit_calibrated(train + extra)
print(f"round 1: block>={hi1:.3f}   round 2 (+{len(extra)} attack rewrites): block>={hi2:.3f}   benign test requests: {len(benign)}\n")

blocked = {1: defaultdict(int), 2: defaultdict(int)}
styles = [n for n, _ in variants("x")]
for r in benign:
    for name, text in variants(r["text"]):
        blocked[1][name] += clf1.check(text).flagged
        blocked[2][name] += clf2.check(text).flagged

n = len(benign)
lines = [f"Benign requests blocked by the classifier, by wrapper style (n={n} each; 95% Wilson CI)\n",
         "| Wrapper style | Round-1 classifier | Round-2 classifier | In round-2 training? |", "|---|---|---|---|"]
for s in styles:
    cells = []
    for k in (1, 2):
        lo, hi = wilson(blocked[k][s], n)
        cells.append(f"{100 * blocked[k][s] / n:5.1f}% [{100 * lo:.0f}-{100 * hi:.0f}]")
    lines.append(f"| {s} | {cells[0]} | {cells[1]} | {'no (held out)' if s in HELD_OUT else ('-' if s == 'original' else 'yes')} |")
text = "\n".join(lines)
print(text)
(ROOT / "results").mkdir(exist_ok=True)
(ROOT / "results" / "benign_wrapped.md").write_text(text + "\n")


# ---- same control for the retrained classifier in eval/adaptive_search.py (which also trains on wrapped BENIGN text)
import random  # noqa: E402

from eval.adaptive_search import OPS, adversarial_classifier, mutate  # noqa: E402

clfB, hiB, _loB, n_adv = adversarial_classifier(train, 12, 20, 0, lambda m: print(m))
benign_all = [r for r in test if r["label"] == 0 and not r["doc"]]
nb = len(benign_all)
rows_out = []
for name in ["(unwrapped)"] + sorted(OPS) + ["random 1-3 operators"]:
    f1 = fB = 0
    for i, r in enumerate(benign_all):
        t = r["text"]
        if name == "random 1-3 operators":
            t = mutate(t, random.Random(f"ctl:{i}"))[0]
        elif name != "(unwrapped)":
            t = OPS[name](t, random.Random(f"ctl:{name}:{i}"))
        f1 += clf1.check(t).flagged
        fB += clfB.check(t).flagged
    rows_out.append((name, f1, fB))
lines2 = [f"\nBenign requests blocked, adaptive_search.py retraining (n={nb} each; 95% Wilson CI); round-2 block threshold {hiB:.3f}\n",
          "| Wrapper | Original classifier | Retrained classifier (adversarial + augmented benign) |", "|---|---|---|"]
for name, a, b in rows_out:
    la, ha = wilson(a, nb)
    lb, hb = wilson(b, nb)
    lines2.append(f"| {name} | {100 * a / nb:5.1f}% [{100 * la:.0f}-{100 * ha:.0f}] | {100 * b / nb:5.1f}% [{100 * lb:.0f}-{100 * hb:.0f}] |")
text2 = "\n".join(lines2)
print(text2)
(ROOT / "results" / "benign_wrapped.md").write_text(text + "\n" + text2 + "\n")
