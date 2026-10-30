#!/usr/bin/env bash
# Extra experiments. Every step is cached and resumable: press Ctrl-C and run the same command again.
#
#   ./scripts/run_extra.sh A      same Llama target, Qwen judge everywhere + the hijack (scope) check   (~1-2 h)
#   ./scripts/run_extra.sh B      second target model, full run + adaptive attacker                      (~3-6 h)
#   ./scripts/run_extra.sh C      second public dataset (read the licence first, see below)              (~1 h)
#   ./scripts/run_extra.sh D      side-by-side comparison table (no model calls)
#   ./scripts/run_extra.sh all    A, B and D
#
# Nothing here touches paper/generated: make_report.py is always called with --no-paper.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${HOST:-http://127.0.0.1:11434}"
TARGET1="${TARGET1:-llama3.2:3b}"
TARGET2="${TARGET2:-qwen2.5:3b}"
JUDGE="${JUDGE:-qwen2.5:7b}"
step="${1:-}"

copy_cache() {   # copy_cache <from-dir> <to-dir> <file>   (never overwrites)
  [ -f "results/$1/$3" ] && mkdir -p "results/$2" && cp -n "results/$1/$3" "results/$2/" || true
}

stepA() {
  echo "== A: $TARGET1 target, $JUDGE judge, hijack check =="
  ollama pull "$JUDGE"
  copy_cache llama32_3b llama32_3b_qj llm_cache.jsonl              # target answers already computed
  copy_cache llama32_3b_nocanary llama32_3b_qj judge_cache.jsonl   # Qwen judge answers already computed
  caffeinate -i python eval/run_eval.py --backend ollama --model "$TARGET1" --judge-model "$JUDGE" --host "$HOST" \
    --out llama32_3b_qj \
    --configs baseline judge_in cascade_full_in full_nocanary full scope_out full_nocanary_scope full_scope
  python eval/make_report.py llama32_3b_qj --no-paper
  python eval/hijack_report.py llama32_3b_qj
}

stepB() {
  echo "== B: second target $TARGET2 (judge $JUDGE) =="
  ollama pull "$TARGET2"; ollama pull "$JUDGE"
  copy_cache llama32_3b_qj qwen25_3b judge_cache.jsonl
  caffeinate -i python eval/run_eval.py --backend ollama --model "$TARGET2" --judge-model "$JUDGE" --host "$HOST" \
    --out qwen25_3b --with-scope
  python eval/make_report.py qwen25_3b --no-paper
  python eval/hijack_report.py qwen25_3b
  caffeinate -i python eval/adaptive_search.py --backend ollama --model "$TARGET2" --judge-model "$JUDGE" --host "$HOST" \
    --out qwen25_3b --per-family 6 --budget 20 \
    --configs baseline rules_in clf_in cascade_rules_clf cascade_full_in full_nocanary full full_nocanary_scope
}

stepC() {
  echo "== C: second public dataset =="
  echo "Check the licence and label meaning of the dataset on its Hugging Face page BEFORE using it in the paper."
  python data/fetch_public.py --dataset xTRam1/safe-guard-prompt-injection --text-col text --label-col label \
    --injection-label 1 --source-name safeguard --out data/public2.jsonl
  caffeinate -i python eval/transfer_second.py --file data/public2.jsonl --name safeguard --max-n 1500 \
    --model "$JUDGE" --host "$HOST"
}

stepD() {
  python eval/compare_runs.py llama32_3b llama32_3b_qj qwen25_3b
}

case "$step" in
  A) stepA ;; B) stepB ;; C) stepC ;; D) stepD ;;
  all) stepA; stepB; stepD ;;
  *) sed -n 2,11p "$0"; exit 1 ;;
esac
