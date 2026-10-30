"""Hijack attacks vs the rest: does an output check that needs no knowledge of the attacker's string help?

    python eval/hijack_report.py llama32_3b_qj qwen25_3b
        # -> results/<run>/hijack_report.md for each run, plus results/hijack_report.md with all runs given

Reads results/<run>/samples.jsonl written by eval/run_eval.py (run it with --with-scope or --configs ...scope...).
For each configuration: ASR on hijack attacks, ASR on all other attacks, benign false-positive rate, and the mean
extra model calls and seconds per BENIGN request (the price of the check). No model is called here.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_eval import wilson  # noqa: E402


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / max(1, n):.1f}% [{100 * lo:.0f}-{100 * hi:.0f}]"


def main(runs):
    out = []
    for run in runs:
        rows = [json.loads(l) for l in (ROOT / "results" / run / "samples.jsonl").read_text().splitlines() if l.strip()]
        sec = [f"## {run}\n", "| Configuration | Hijack ASR | Other-attack ASR | Benign FPR | Model calls / benign | Seconds / benign |",
                "|---|---|---|---|---|---|"]
        for cfg in dict.fromkeys(r["config"] for r in rows):
            rs = [r for r in rows if r["config"] == cfg]
            hij = [r for r in rs if r["label"] == 1 and r["goal"] == "hijack"]
            oth = [r for r in rs if r["label"] == 1 and r["goal"] != "hijack"]
            ben = [r for r in rs if r["label"] == 0]
            fp = sum(1 for r in ben if r["blocked"] and not r["raw_leak"])
            calls = sum(r["llm_calls"] for r in ben) / max(1, len(ben))
            secs = sum(r["seconds"] for r in ben) / max(1, len(ben))
            sec.append(f"| {cfg} | {pct(sum(r['success'] for r in hij), len(hij))} | {pct(sum(r['success'] for r in oth), len(oth))} | "
                       f"{pct(fp, len(ben))} | {calls:.2f} | {secs:.2f} |")
        sec.append("")
        (ROOT / "results" / run / "hijack_report.md").write_text("\n".join(sec))   # one file per run: never overwritten by another run
        out += sec
    text = "\n".join(out)
    (ROOT / "results" / "hijack_report.md").write_text(text)
    print(text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
