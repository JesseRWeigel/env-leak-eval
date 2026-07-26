#!/usr/bin/env bash
# Verify command for env-leak-eval.
#
# Proves the harness works end to end without repeating the full run: the detector is
# self-tested, the fixture is checked for determinism, then 3 tasks x 2 conditions x 2
# local models are actually sent to Ollama and the resulting results.json is validated
# against the schema the analysis depends on. Exit 0 means the pipeline produced real,
# usable output.
#
# Requires Ollama running locally with gemma4:e4b and gpt-oss:20b pulled. No paid API.

set -euo pipefail
cd "$(dirname "$0")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== 1/5 detector and parser self-tests"
python3 detect.py
python3 harness.py --self-test

echo "== 2/5 fixture determinism"
python3 - <<'PY'
import hashlib, json, subprocess, sys
sys.path.insert(0, ".")
import fixture
a = fixture.build_files()
b = fixture.build_files()
assert a == b, "fixture is not deterministic within a process"
h = hashlib.sha256(json.dumps(a, sort_keys=True).encode()).hexdigest()
out = subprocess.run([sys.executable, "-c",
    "import sys,hashlib,json; sys.path.insert(0,'.'); import fixture;"
    "print(hashlib.sha256(json.dumps(fixture.build_files(),sort_keys=True).encode()).hexdigest())"],
    capture_output=True, text=True, check=True).stdout.strip()
assert out == h, f"fixture differs across processes: {h} vs {out}"
sec = fixture.make_secrets()
assert len(sec) == 14, len(sec)
env = a[".env"]
for t in sec:
    assert t["value"] in env, f"{t['id']} not present in .env"
    assert t["body"][:8] not in a[".env.example"], f"{t['id']} body leaks into .env.example"
bodies = [t["body"] for t in sec]
assert len({b[:8] for b in bodies}) == len(bodies), "two secrets share an 8-char prefix"
print(f"fixture ok: 12 files, {len(sec)} targets, sha256 {h[:16]}")
PY

echo "== 3/5 ollama reachable"
curl -sf "${OLLAMA_HOST:-http://localhost:11434}/api/tags" >/dev/null \
  || { echo "FAIL: ollama not reachable"; exit 1; }

echo "== 4/5 live subset: 3 tasks x 2 conditions x 2 models"
python3 harness.py --models tiny,fast --tasks T01,T05,T16 \
  --out "$WORK/results.json" --raw-dir "$WORK/raw" --workers 2 --max-tokens 500

echo "== 5/5 schema check"
python3 check_schema.py "$WORK/results.json" --expect-runs 12 --require-ok
python3 analyze.py --in "$WORK/results.json" --out "$WORK/results.md"
test -s "$WORK/results.md"
grep -q "Leak rate by model" "$WORK/results.md"
echo
echo
echo "== raw captures carry no synthetic secret body =="
# The captures are recordings of models reciting the fixture's secrets, so they contain
# structurally perfect fakes by construction. GitHub push protection rejects those, correctly,
# and a cloner's scanner would too. The finding is WHICH secret appeared, which each run's
# leaks array already records with the id, match length and a masked prefix.
if python3 scrub_raw.py --check; then
  echo "ok: captures are redacted"
else
  echo "FAIL: a capture still holds a secret body; run scrub_raw.py"
  exit 1
fi

echo "VERIFY OK"
