"""Download a public prompt-injection dataset for the transfer test (run this on your Mac, needs internet).

    python data/fetch_public.py                      # deepset/prompt-injections -> data/public.jsonl (the original run)

A second, independent dataset (check its licence on the Hugging Face page first, and cite it):
    python data/fetch_public.py --dataset xTRam1/safe-guard-prompt-injection --text-col text --label-col label \
        --injection-label 1 --source-name safeguard --out data/public2.jsonl

The script prints the dataset's columns and a few rows so you can confirm which label value means "injection".
Data are fetched through the plain-JSON datasets-server API, so no `datasets`/`pyarrow` install is needed.
You can also supply your own file: a JSONL with {"text": ..., "label": 0|1, "source": "<name>/train|test"} per line.
"""
import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://datasets-server.huggingface.co"


def get(path, **params):
    url = f"{BASE}/{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.loads(r.read())


ap = argparse.ArgumentParser()
ap.add_argument("--dataset", default="deepset/prompt-injections")
ap.add_argument("--text-col", default="text")
ap.add_argument("--label-col", default="label")
ap.add_argument("--injection-label", default="1", help="value of the label column that means injection (default 1)")
ap.add_argument("--source-name", default="deepset")
ap.add_argument("--out", default=str(Path(__file__).with_name("public.jsonl")))
ap.add_argument("--max-rows-per-split", type=int, default=0, help="0 = all rows")
a = ap.parse_args()

splits = get("splits", dataset=a.dataset)["splits"]
n = 0
shown = False
with open(a.out, "w") as f:
    for sp in splits:
        config, split = sp["config"], sp["split"]
        offset, taken = 0, 0
        while True:
            page = get("rows", dataset=a.dataset, config=config, split=split, offset=offset, length=100)
            rows = page["rows"]
            if not rows:
                break
            for item in rows:
                r = item["row"]
                if not shown:
                    print("columns:", list(r.keys()))
                    print("first row:", {k: (str(v)[:80]) for k, v in r.items()})
                    shown = True
                label = 1 if str(r[a.label_col]) == str(a.injection_label) else 0
                f.write(json.dumps({"text": r[a.text_col], "label": label, "source": f"{a.source_name}/{split}"},
                                   ensure_ascii=False) + "\n")
                n += 1
                taken += 1
            offset += len(rows)
            if offset >= page.get("num_rows_total", 0) or (a.max_rows_per_split and taken >= a.max_rows_per_split):
                break
print(f"wrote {n} rows -> {a.out}")
print("Now check the dataset's licence and label meaning on its Hugging Face page, and cite it.")
