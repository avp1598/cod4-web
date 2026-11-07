#!/bin/sh
# Runs the differential tester in N parallel shards and merges the results.
# Usage: tests/run_difftest.sh <game.exe> <functions.json> [N] [extra difftest.py args...]
# (use out_all/functions_translated.json to cover every translated function, see difftest.py)
# (build.sh must have built build/librecomp.dylib from the same executable)
R=$(cd "$(dirname "$0")/.." && pwd)
PY=${PY:-python3}
EXE=${1:?usage: run_difftest.sh <game.exe> <functions.json> [N]}; FUNCS=${2:?}; shift 2
N=${1:-8}; [ $# -gt 0 ] && shift
OUT="$R/tests/results"; mkdir -p "$OUT"; rm -f "$OUT"/shard_*
for k in $(seq 0 $((N - 1))); do
  "$PY" -I "$R/tests/difftest.py" "$EXE" "$FUNCS" "$R/build/librecomp.dylib" \
    --shard "$k/$N" --report "$OUT/shard_$k.json" "$@" > "$OUT/shard_$k.log" 2>&1 &
done
wait
"$PY" -I - "$OUT" "$N" <<'PY'
import json, os, sys, collections
out, n = sys.argv[1], int(sys.argv[2]); tot = collections.defaultdict(list)
missing = [k for k in range(n) if not os.path.exists(f"{out}/shard_{k}.json")]
if missing:   # a shard that died wrote no report: its functions are untested, so there is no total to give
    for k in missing:
        print(f"shard {k} failed; the end of {out}/shard_{k}.log:")
        print("".join(open(f"{out}/shard_{k}.log").readlines()[-6:]))
    sys.exit(1)
for k in range(n):
    for key, v in json.load(open(f"{out}/shard_{k}.json")).items(): tot[key] += v
json.dump(tot, open(f"{out}/merged.json", "w"), indent=1)
print("  ".join(f"{k}={len(v)}" for k, v in tot.items()))
for e, n, why in sorted(tot["fail"]): print("FAIL", e, n, why)
PY
