"""Summarises a difftest run (tests/results/merged.json): counts per outcome, and every skipped function
grouped by the reason it was skipped, so each group can be given another way of testing or a written reason
(plan check F0.3).

  skip_report.py <merged.json> [--list]      (--list prints every function in each group)
"""
import argparse
import collections
import json
import re


def reason_class(why):
    """Collapses a skip reason to its kind: addresses and counts are dropped."""
    w = re.sub(r"\b[0-9a-f]{8}\b", "ADDR", why or "")
    w = re.sub(r"\(\d+\)", "(N)", w)
    return w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("merged")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    d = json.load(open(a.merged))
    print("outcomes: " + "  ".join(f"{k}={len(v)}" for k, v in d.items()))
    groups = collections.defaultdict(list)
    for entry, name, why in d.get("skip", []):
        groups[reason_class(why)].append((entry, name, why))
    print(f"\nskipped functions by reason ({len(d.get('skip', []))} total):")
    for k, v in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(v):6d}  {k}")
        if a.list:
            for entry, name, why in sorted(v):
                print(f"            {entry} {name}: {why}")


if __name__ == "__main__":
    main()
