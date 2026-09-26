"""Prints a readable summary of `seredina-agent inventory` output (used by CI)."""
import json
import sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
for key, value in d.items():
    if isinstance(value, list):
        print(f"{key}: {len(value)}")
        for item in value[:4]:
            print("   ", json.dumps(item, ensure_ascii=False)[:300])
    else:
        print(f"{key}: {json.dumps(value, ensure_ascii=False)[:1500]}")
print(f"size: {len(json.dumps(d))} bytes")
