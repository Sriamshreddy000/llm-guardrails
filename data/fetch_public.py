"""Download a public prompt-injection dataset for the transfer test (run this on your Mac, needs internet).

    python data/fetch_public.py                      # -> data/public.jsonl

Uses deepset/prompt-injections from Hugging Face (columns: text, label; label 1 = injection),
fetched through the plain-JSON datasets-server API, so no `datasets`/`pyarrow` install is needed.
CHECK ITS LICENSE AND CITE IT before using it in the paper. You can also supply your own file:
a JSONL with {"text": ..., "label": 0|1} per line, saved as data/public.jsonl.
"""
import json
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://datasets-server.huggingface.co"
NAME = "deepset/prompt-injections"


def get(path, **params):
    url = f"{BASE}/{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.loads(r.read())


splits = get("splits", dataset=NAME)["splits"]
out = Path(__file__).with_name("public.jsonl")
n = 0
with out.open("w") as f:
    for sp in splits:
        config, split = sp["config"], sp["split"]
        offset = 0
        while True:
            page = get("rows", dataset=NAME, config=config, split=split, offset=offset, length=100)
            rows = page["rows"]
            if not rows:
                break
            for item in rows:
                r = item["row"]
                f.write(json.dumps({"text": r["text"], "label": int(r["label"]), "source": f"deepset/{split}"},
                                   ensure_ascii=False) + "\n")
                n += 1
            offset += len(rows)
            if offset >= page.get("num_rows_total", 0):
                break
print(f"wrote {n} rows -> {out}")
