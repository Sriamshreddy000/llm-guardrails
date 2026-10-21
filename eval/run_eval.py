"""Run every guardrail configuration against the attack / benign test set.

Quick smoke test (no model needed, results are NOT findings):
    python eval/run_eval.py --backend mock --out mock_run

Real run with a local model (see README for Ollama setup):
    python eval/run_eval.py --backend ollama --model llama3.2:3b --out llama32_3b

Everything is cached on disk, so you can stop and re-run without repeating model calls.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.oracle import Oracle  # noqa: E402
from guardrails.classifier import ClassifierLayer, calibrate  # noqa: E402
from guardrails.judge import JudgeLayer  # noqa: E402
from guardrails.llm import AnthropicBackend, CachedBackend, MockBackend, OllamaBackend  # noqa: E402
from guardrails.pipeline import Cascade, GuardedBot  # noqa: E402
from guardrails.rules import CanaryOutput, GenericOutputRules, InputRules  # noqa: E402
from guardrails.target_app import Secrets, SupportBot  # noqa: E402


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def load_rows():
    return [json.loads(l) for l in (ROOT / "data" / "dataset.jsonl").read_text().splitlines() if l.strip()]


def training_pairs(rows):
    """Classifier sees the same parts the guard scans: the message and (separately) the document."""
    texts, labels, groups = [], [], []
    for r in rows:
        g = r["template"] if r["label"] == 1 else r["base"]
        if r["doc"]:
            texts += [r["text"], r["doc"]]
            labels += [0, r["label"]]       # the request is benign; the document carries the injection
            groups += [g, g]
        else:
            texts.append(r["text"])
            labels.append(r["label"])
            groups.append(g)
    return texts, labels, groups


def fit_calibrated(rows):
    texts, labels, groups = training_pairs(rows)
    hi, lo = calibrate(texts, labels, groups)
    clf = ClassifierLayer(threshold=hi).fit(texts, labels)
    return clf, hi, lo


def build_backend(args):
    out = ROOT / "results" / args.out
    out.mkdir(parents=True, exist_ok=True)
    if args.backend == "mock":
        inner = MockBackend()
    elif args.backend == "ollama":
        inner = OllamaBackend(args.model, args.host, seed=args.seed)
    else:
        inner = AnthropicBackend(args.model)
    return CachedBackend(inner, out / "llm_cache.jsonl"), out


def build_configs(bot, secrets, backend, judge_backend, clf, lo):
    rules = InputRules()
    judge = JudgeLayer(judge_backend)
    out_gen = GenericOutputRules(bot.system_prompt)
    out_can = CanaryOutput([secrets.admin_code, secrets.email, secrets.phone])
    cas_rc = lambda: Cascade(rules, clf, None, lo=lo, hi=clf.threshold)        # noqa: E731
    cas_full = lambda: Cascade(rules, clf, judge, lo=lo, hi=clf.threshold)     # noqa: E731
    G = GuardedBot
    return judge, {
        "baseline":            G(bot),
        "structural":          G(bot, structural=True),
        "rules_in":            G(bot, [rules]),
        "clf_in":              G(bot, [clf]),
        "judge_in":            G(bot, [judge]),
        "rules_out":           G(bot, [], [out_gen]),
        "canary_out":          G(bot, [], [out_can]),
        "rules_io":            G(bot, [rules], [out_gen]),
        "cascade_rules_clf":   G(bot, [cas_rc()]),
        "cascade_full_in":     G(bot, [cas_full()]),
        "full_nocanary":       G(bot, [cas_full()], [out_gen]),
        "full":                G(bot, [cas_full()], [out_gen, out_can]),
        "full_nocanary_struct": G(bot, [cas_full()], [out_gen], structural=True),
        "full_struct":         G(bot, [cas_full()], [out_gen, out_can], structural=True),
    }


def summarise(samples):
    atk = [s for s in samples if s["label"] == 1]
    ben = [s for s in samples if s["label"] == 0]
    succ = sum(1 for s in atk if s["success"])
    blk_a = sum(1 for s in atk if s["blocked"])
    blk_b = sum(1 for s in ben if s["blocked"] and not s["raw_leak"])   # leak-aware false positives
    secs = sorted(s["seconds"] for s in ben) or [0.0]
    fam = defaultdict(lambda: [0, 0])
    for s in atk:
        fam[s["family"]][1] += 1
        fam[s["family"]][0] += int(s["success"])
    return {
        "n_attack": len(atk), "n_benign": len(ben),
        "asr": succ / max(1, len(atk)), "asr_ci": wilson(succ, len(atk)),
        "block_rate": blk_a / max(1, len(atk)),
        "fpr": blk_b / max(1, len(ben)), "fpr_ci": wilson(blk_b, len(ben)),
        "benign_leak": sum(1 for s in ben if s["success"]),
        "benign_blocked_incl_true_leaks": sum(1 for s in ben if s["blocked"]),
        "benign_raw_leak": sum(1 for s in ben if s["raw_leak"]),
        "latency_mean": statistics.mean(secs), "latency_p95": secs[min(len(secs) - 1, int(0.95 * len(secs)))],
        "llm_calls_per_benign": statistics.mean(s["llm_calls"] for s in ben) if ben else 0.0,
        "judge_calls_per_request": statistics.mean(s["judge_calls"] for s in samples) if samples else 0.0,
        "asr_by_family": {k: {"asr": v[0] / v[1], "n": v[1], "ci": wilson(v[0], v[1])} for k, v in sorted(fam.items())},
    }


def lofo(rows, train, test):  # noqa: C901
    """Leave-one-family-out: how well does the trained classifier catch attack TYPES it never saw?"""
    fams = sorted({r["family"] for r in rows if r["label"] == 1})
    rules = InputRules()
    test_ben = [r for r in test if r["label"] == 0]
    out = {}
    for f in fams:
        tr = [r for r in train + test if not (r["label"] == 1 and r["family"] == f) and r["split"] == "train"]
        clf, _hi, _lo = fit_calibrated(tr)
        atk = [r for r in rows if r["label"] == 1 and r["family"] == f]
        def flagged_clf(r):
            parts = [r["doc"]] if r["doc"] else [r["text"]]
            return any(clf.check(p).flagged for p in parts)
        def flagged_rules(r):
            parts = [r["doc"]] if r["doc"] else [r["text"]]
            return any(rules.check(p).flagged for p in parts)
        fp = sum(any(clf.check(p).flagged for p in ([r["doc"]] if r["doc"] else [r["text"]])) for r in test_ben)
        out[f] = {"n": len(atk), "clf_detect_unseen_family": sum(map(flagged_clf, atk)) / len(atk),
                  "rules_detect": sum(map(flagged_rules, atk)) / len(atk), "clf_fpr": fp / max(1, len(test_ben))}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["mock", "ollama", "anthropic"], default="mock")
    ap.add_argument("--model", default="llama3.2:3b")
    ap.add_argument("--judge-model", default=None, help="different model for the judge layer (default: same)")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--out", default="run")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--per-family", type=int, default=0, help="cap test attacks per family (0 = all)")
    ap.add_argument("--configs", nargs="*", default=None)
    args = ap.parse_args()

    rows = load_rows()
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    if args.per_family:
        rng = random.Random(args.seed)
        keep, count = [], defaultdict(int)
        rng.shuffle(test)
        for r in test:
            if r["label"] == 0:                 # never shrink the benign set: FPR needs a decent denominator
                keep.append(r)
            elif count[r["family"]] < args.per_family:
                count[r["family"]] += 1
                keep.append(r)
        test = sorted(keep, key=lambda r: r["id"])

    backend, out = build_backend(args)
    jb = backend
    if args.judge_model and args.backend == "ollama":
        jb = CachedBackend(OllamaBackend(args.judge_model, args.host, seed=args.seed), out / "judge_cache.jsonl")
    secrets = Secrets.make(args.seed)
    bot = SupportBot(backend, secrets)
    oracle = Oracle(secrets, bot.system_prompt)
    clf, hi, lo = fit_calibrated(train)
    print(f"classifier operating point (from out-of-fold scores): block>={hi:.3f}  pass<={lo:.3f}")
    judge, configs = build_configs(bot, secrets, backend, jb, clf, lo)
    if args.configs:
        configs = {k: v for k, v in configs.items() if k in args.configs}

    print(f"backend={backend.name}  test attacks={sum(r['label'] for r in test)}  "
          f"test benign={sum(1 - r['label'] for r in test)}  configs={len(configs)}", flush=True)

    # What would the UNGUARDED model have said? Needed to tell true catches from false positives.
    # This is the slow part (one real model call per test item); answers are cached, so re-runs resume.
    raw = {}
    modes = sorted({g.structural for g in configs.values()})
    t_raw = time.time()
    print(f"step 1/2: asking the model with no defenses ({len(modes) * len(test)} calls; ~2-5 s each) ...", flush=True)
    done = 0
    for st in modes:
        for r in test:
            text, _, _ = bot.respond(r["text"], r["doc"], st)
            raw[(r["id"], st)] = oracle.judge(text, r.get("marker")) is not None
            done += 1
            if done % 10 == 0:
                print(f"  {done}/{len(modes) * len(test)}  ({time.time() - t_raw:.0f}s elapsed)", flush=True)
    print("step 2/2: running each defense configuration ...", flush=True)
    all_samples, summary = [], {}
    t_start = time.time()
    for name, g in configs.items():
        samples = []
        for i, r in enumerate(test):
            res = g.respond(r["text"], r["doc"])
            kind = oracle.judge(res.text, r.get("marker"))
            samples.append({"config": name, "id": r["id"], "family": r["family"], "label": r["label"],
                            "goal": r["goal"], "blocked": res.blocked, "blocked_by": res.blocked_by,
                            "stage": res.stage, "success": kind is not None, "kind": kind,
                            "raw_leak": raw[(r["id"], g.structural)],
                            "seconds": res.seconds, "llm_calls": res.llm_calls, "judge_calls": res.judge_calls})
            if (i + 1) % 100 == 0:
                print(f"  {name}: {i + 1}/{len(test)}  ({time.time() - t_start:.0f}s elapsed)", flush=True)
        summary[name] = summarise(samples)
        s = summary[name]
        print(f"{name:22s} ASR {s['asr']*100:5.1f}%   FPR {s['fpr']*100:5.1f}%   latency {s['latency_mean']:.2f}s", flush=True)
        all_samples += samples

    summary_all = {
        "meta": {"backend": backend.name, "is_mock": backend.is_mock, "seed": args.seed,
                 "judge_model": jb.name, "n_attack": sum(r["label"] for r in test),
                 "n_benign": sum(1 - r["label"] for r in test), "n_train": len(train),
                 "clf_block_threshold": hi, "clf_pass_threshold": lo,
                 "date": time.strftime("%Y-%m-%d"), "secrets_fictional": True},
        "configs": summary,
        "judge_answers": dict(judge.stats),
        "lofo": lofo(rows, train, test),
    }
    (out / "summary.json").write_text(json.dumps(summary_all, indent=2))
    (out / "samples.jsonl").write_text("\n".join(json.dumps(s) for s in all_samples) + "\n")
    print(f"judge answers: {dict(judge.stats)}   (UNPARSED should be ~0; those are treated as SAFE)")
    print(f"\nsaved -> {out}/summary.json")


if __name__ == "__main__":
    main()
