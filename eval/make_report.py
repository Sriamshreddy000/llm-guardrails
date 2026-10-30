"""Turn results/<run>/summary.json into markdown tables, LaTeX tables, paper macros, and the trade-off figure.

    python eval/make_report.py llama32_3b          # writes results/llama32_3b/report/ AND paper/generated/
    python eval/make_report.py mock_run --allow-mock   # pipeline test only: paper numbers are stamped MOCK

Mock-model results are refused for the paper unless --allow-mock is given, and are then
stamped with a red banner so they can never be mistaken for findings.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LABELS = {
    "baseline": "No defense", "structural": "Structural prompt (datamark + reminder)",
    "rules_in": "Rules (input)", "clf_in": "Classifier (input)", "judge_in": "LLM judge (input)",
    "rules_out": "Rules (output)", "canary_out": "Canary check (output)", "rules_io": "Rules (input + output)",
    "cascade_rules_clf": "Cascade: rules, classifier", "cascade_full_in": "Cascade: rules, classifier, judge",
    "full_nocanary": "Full (no canary)", "full": "Full (+ canary)",
    "full_nocanary_struct": "Full (no canary) + structural", "full_struct": "Full (+ canary) + structural",
    "scope_out": "Scope check (output)", "full_nocanary_scope": "Full (no canary) + scope check",
    "full_scope": "Full (+ canary) + scope check",
}
GROUP = {"baseline": "none", "structural": "structural",
         "rules_in": "single", "clf_in": "single", "judge_in": "single", "rules_out": "single", "canary_out": "single",
         "rules_io": "combined", "cascade_rules_clf": "combined", "cascade_full_in": "combined",
         "full_nocanary": "combined", "full": "combined", "full_nocanary_struct": "combined", "full_struct": "combined",
         "scope_out": "single", "full_nocanary_scope": "combined", "full_scope": "combined"}
FAM_COLS = ["baseline", "rules_in", "clf_in", "judge_in", "full_nocanary", "full", "scope_out", "full_nocanary_scope"]
# Okabe-Ito colour-blind-safe palette; marker SHAPE also encodes the group, so colour is never the only cue
STYLE = {"none": ("#000000", "s"), "structural": ("#E69F00", "D"), "single": ("#0072B2", "o"), "combined": ("#D55E00", "^")}


def pct(x: float) -> str:
    return f"{100 * x:.1f}"


def ci(c) -> str:
    return f"{100 * c[0]:.1f}-{100 * c[1]:.1f}"


def tex(s: str) -> str:
    return (s.replace("&", r"\&").replace("%", r"\%").replace("_", r"\_").replace("#", r"\#"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--allow-mock", action="store_true")
    ap.add_argument("--no-paper", action="store_true",
                    help="write only results/<run>/report/; never touch paper/generated (use for extra models and extra runs)")
    a = ap.parse_args()
    run_dir = ROOT / "results" / a.run
    S = json.loads((run_dir / "summary.json").read_text())
    meta, C = S["meta"], S["configs"]
    mock = meta["is_mock"]
    to_paper = (not mock) or a.allow_mock
    if a.no_paper:
        to_paper = False
    if a.no_paper:
        print("NOTE: --no-paper given. Writing the local report only; paper/ is untouched.")
    elif mock and not a.allow_mock:
        print("NOTE: this run used the MOCK model. Writing local report only; paper/ is untouched.")

    rep = run_dir / "report"
    rep.mkdir(exist_ok=True)
    gen = ROOT / "paper" / "generated"
    gen.mkdir(parents=True, exist_ok=True)
    order = [k for k in LABELS if k in C]

    # ------------------------------------------------------------------ markdown
    md = [f"# Results: {meta['backend']}  ({meta['date']}){'  **MOCK - NOT FINDINGS**' if mock else ''}\n",
          f"Test set: {meta['n_attack']} attacks, {meta['n_benign']} benign. 95% Wilson intervals. "
          f"ASR = attack success rate (lower is better). FPR = benign requests wrongly blocked (lower is better).\n",
          "| Configuration | ASR % | ASR 95% CI | FPR % | FPR 95% CI | Mean latency (s) | p95 (s) | Judge calls / request |",
          "|---|---|---|---|---|---|---|---|"]
    for k in order:
        v = C[k]
        md.append(f"| {LABELS[k]} | {pct(v['asr'])} | {ci(v['asr_ci'])} | {pct(v['fpr'])} | {ci(v['fpr_ci'])} | "
                  f"{v['latency_mean']:.2f} | {v['latency_p95']:.2f} | {v['judge_calls_per_request']:.2f} |")
    fams = sorted(next(iter(C.values()))["asr_by_family"])
    cols = [c for c in FAM_COLS if c in C]
    md += ["\n## ASR % by attack family\n", "| Family | n | " + " | ".join(LABELS[c] for c in cols) + " |",
           "|---|---|" + "---|" * len(cols)]
    for f in fams:
        n = C[cols[0]]["asr_by_family"][f]["n"]
        md.append(f"| {f} | {n} | " + " | ".join(pct(C[c]["asr_by_family"][f]["asr"]) for c in cols) + " |")
    md += ["\n## Generalisation to attack types never seen in training (leave-one-family-out)\n",
           "| Held-out family | n | Rules detect % | Classifier detect % | Classifier FPR % |", "|---|---|---|---|---|"]
    for f, v in S["lofo"].items():
        md.append(f"| {f} | {v['n']} | {pct(v['rules_detect'])} | {pct(v['clf_detect_unseen_family'])} | {pct(v['clf_fpr'])} |")
    (rep / "tables.md").write_text("\n".join(md) + "\n")

    # ------------------------------------------------------------------ figure
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "pdf.fonttype": 42})
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    ax.grid(True, color="#dddddd", lw=0.6)
    ax.set_axisbelow(True)
    shown = set()
    for k in order:
        v = C[k]
        col, mk = STYLE[GROUP[k]]
        x, y = 100 * v["fpr"], 100 * v["asr"]
        # clamp at 0: Wilson bounds can sit a hair above a 0% point estimate (rounding), which matplotlib rejects
        ax.errorbar(x, y, xerr=[[max(0.0, x - 100 * v["fpr_ci"][0])], [max(0.0, 100 * v["fpr_ci"][1] - x)]],
                    yerr=[[max(0.0, y - 100 * v["asr_ci"][0])], [max(0.0, 100 * v["asr_ci"][1] - y)]],
                    fmt=mk, color=col, ms=7, mec="white", mew=0.8, elinewidth=0.7, capsize=0, alpha=0.9, ecolor=col + '55',
                    label=None if GROUP[k] in shown else {"none": "No defense", "structural": "Structural prompt",
                                                         "single": "Single layer", "combined": "Combined layers"}[GROUP[k]])
        shown.add(GROUP[k])
    short = {"baseline": "No defense", "structural": "Structural", "rules_in": "Rules", "clf_in": "Classifier",
             "judge_in": "LLM judge", "full": "Full (with or without canary)", "full_nocanary": "Full (no canary)",
             "canary_out": "Canary (output)"}
    offs = {"baseline": (9, -12), "structural": (9, 4), "rules_in": (-6, 9), "clf_in": (8, 6), "judge_in": (9, 5),
            "full": (8, 10), "canary_out": (9, -11)}
    for k, (dx, dy) in offs.items():
        if k in C:
            ax.annotate(short[k], (100 * C[k]["fpr"], 100 * C[k]["asr"]), xytext=(dx, dy),
                        textcoords="offset points", fontsize=7.5, color="#333333")
    ax.set_xlabel("False-positive rate on benign requests (%)  - lower is better")
    ax.set_ylabel("Attack success rate (%)  - lower is better")
    ax.set_xlim(left=-0.4)
    ax.set_ylim(bottom=-0.6)
    ax.legend(frameon=False, loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(rep / "fig_tradeoff.png", dpi=200)
    fig.savefig(rep / "fig_tradeoff.pdf")
    plt.close(fig)

    if not to_paper:
        print(f"wrote {rep}/")
        return

    # ------------------------------------------------------------------ LaTeX
    stamp = "MOCK DATA" if mock else meta["backend"]
    rows = []
    for k in order:
        v = C[k]
        rows.append(f"{tex(LABELS[k])} & {pct(v['asr'])} & {{\\scriptsize[{ci(v['asr_ci'])}]}} & {pct(v['fpr'])} & "
                    f"{{\\scriptsize[{ci(v['fpr_ci'])}]}} & {v['latency_mean']:.2f} & {v['judge_calls_per_request']:.2f} \\\\")
    (gen / "tab_main.tex").write_text(
        "\\begin{tabular}{lrlrlrr}\n\\toprule\nConfiguration & ASR\\,\\% & 95\\% CI & FPR\\,\\% & 95\\% CI & Latency (s) & Judge calls/req \\\\\n"
        "\\midrule\n" + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
    frows = []
    for f in fams:
        n = C[cols[0]]["asr_by_family"][f]["n"]
        frows.append(f"{tex(f)} & {n} & " + " & ".join(pct(C[c]["asr_by_family"][f]["asr"]) for c in cols) + " \\\\")
    heads = {"baseline": "None", "rules_in": "Rules", "clf_in": "Clf.", "judge_in": "Judge",
             "full_nocanary": "Full", "full": "Full+C.", "scope_out": "Scope", "full_nocanary_scope": "Full+Sc."}
    (gen / "tab_family.tex").write_text(
        "\\begin{tabular}{lr" + "r" * len(cols) + "}\n\\toprule\nFamily & $n$ & " + " & ".join(heads[c] for c in cols) +
        " \\\\\n\\midrule\n" + "\n".join(frows) + "\n\\bottomrule\n\\end{tabular}\n")
    lrows = [f"{tex(f)} & {v['n']} & {pct(v['rules_detect'])} & {pct(v['clf_detect_unseen_family'])} & {pct(v['clf_fpr'])} \\\\"
             for f, v in S["lofo"].items()]
    (gen / "tab_lofo.tex").write_text(
        "\\begin{tabular}{lrrrr}\n\\toprule\nHeld-out family & $n$ & Rules detect\\,\\% & Clf. detect\\,\\% & Clf. FPR\\,\\% \\\\\n"
        "\\midrule\n" + "\n".join(lrows) + "\n\\bottomrule\n\\end{tabular}\n")
    import shutil
    shutil.copy(rep / "fig_tradeoff.pdf", gen / "fig_tradeoff.pdf")

    def m(name, val):
        return f"\\newcommand{{\\{name}}}{{{val}}}\n"
    g = lambda k, f: pct(C[k][f]) if k in C else "n/a"  # noqa: E731
    nums = "".join([
        m("resultModel", tex(meta["backend"])), m("resultJudge", tex(meta["judge_model"])),
        m("resultDate", meta["date"]), m("nAttack", meta["n_attack"]), m("nBenign", meta["n_benign"]),
        m("nTrain", meta["n_train"]),
        m("asrBase", g("baseline", "asr")), m("asrStruct", g("structural", "asr")),
        m("asrRules", g("rules_in", "asr")), m("fprRules", g("rules_in", "fpr")),
        m("asrClf", g("clf_in", "asr")), m("fprClf", g("clf_in", "fpr")),
        m("asrJudge", g("judge_in", "asr")), m("fprJudge", g("judge_in", "fpr")),
        m("asrFull", g("full", "asr")), m("fprFull", g("full", "fpr")),
        m("asrFullNC", g("full_nocanary", "asr")), m("fprFullNC", g("full_nocanary", "fpr")),
        m("asrFullStruct", g("full_struct", "asr")), m("fprFullStruct", g("full_struct", "fpr")),
        m("judgeFrac", f"{100 * C['full']['judge_calls_per_request']:.0f}" if "full" in C else "n/a"),
        m("clfHi", f"{meta['clf_block_threshold']:.2f}"), m("clfLo", f"{meta['clf_pass_threshold']:.2f}"),
        "\\newif\\ifmock\\mock" + ("true" if mock else "false") + "\n",
    ])
    (gen / "numbers.tex").write_text(nums)
    print(f"wrote {rep}/ and {gen}/  (source: {stamp})")


if __name__ == "__main__":
    sys.exit(main())
