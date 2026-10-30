"""Side-by-side table of several runs (e.g. two target models) for the configurations that matter.

    python eval/compare_runs.py llama32_3b qwen25_3b            # -> results/compare_runs.md

Reads results/<run>/summary.json (written by eval/run_eval.py). Nothing here calls a model.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = [("baseline", "No defense"), ("structural", "Structural prompt"), ("rules_in", "Rules"), ("clf_in", "Classifier"),
       ("judge_in", "LLM judge"), ("rules_io", "Rules in+out"), ("cascade_full_in", "Cascade (input)"),
       ("full_nocanary", "Full (no canary)"), ("full", "Full (+ canary)"), ("scope_out", "Scope check alone"),
       ("full_nocanary_scope", "Full (no canary) + scope")]


def cell(v, key):
    lo, hi = v[f"{key}_ci"]
    return f"{100 * v[key]:.1f} [{100 * lo:.0f}-{100 * hi:.0f}]"


def main(runs):
    S = {r: json.loads((ROOT / "results" / r / "summary.json").read_text()) for r in runs}
    head = ["Configuration"] + [f"{r} ASR % [CI]" for r in runs] + [f"{r} FPR % [CI]" for r in runs]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for k, label in KEY:
        if not any(k in S[r]["configs"] for r in runs):
            continue
        cells = [cell(S[r]["configs"][k], "asr") if k in S[r]["configs"] else "-" for r in runs]
        cells += [cell(S[r]["configs"][k], "fpr") if k in S[r]["configs"] else "-" for r in runs]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    meta = "; ".join(f"{r}: target {S[r]['meta']['backend']}, judge {S[r]['meta']['judge_model']}, {S[r]['meta']['n_attack']} attacks / {S[r]['meta']['n_benign']} benign" for r in runs)
    text = f"Runs compared ({meta}). 95% Wilson intervals.\n\n" + "\n".join(lines)
    (ROOT / "results" / "compare_runs.md").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
