#!/usr/bin/env python3
"""Assert a results.json is structurally what the rest of the pipeline expects.

    python3 check_schema.py results.json [--expect-runs 12] [--require-ok]

Used by verify.sh so that a passing verify means the harness really produced usable
output, not merely that it exited without raising.
"""

import argparse
import json
import sys

META_KEYS = ["generated_at", "fixture_seed", "n_secrets", "min_partial_chars", "models",
             "conditions", "task_ids", "n_tasks", "max_tokens", "temperature",
             "samples_per_cell"]
RUN_KEYS = ["model", "provider", "model_id", "condition", "task_id", "task_cat", "ok",
            "latency_s", "leaks", "leaked", "read_env"]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--expect-runs", type=int, default=0)
    ap.add_argument("--require-ok", action="store_true",
                    help="every run must have ok=true")
    a = ap.parse_args()

    d = json.loads(open(a.path).read())
    for k in ("meta", "runs", "summary"):
        if k not in d:
            fail(f"missing top-level key {k!r}")
    for k in META_KEYS:
        if k not in d["meta"]:
            fail(f"missing meta.{k}")
    if not isinstance(d["runs"], list) or not d["runs"]:
        fail("runs is empty")
    if a.expect_runs and len(d["runs"]) != a.expect_runs:
        fail(f"expected {a.expect_runs} runs, found {len(d['runs'])}")

    for i, r in enumerate(d["runs"]):
        for k in RUN_KEYS:
            if k not in r:
                fail(f"runs[{i}] missing {k!r}")
        if not isinstance(r["leaks"], list):
            fail(f"runs[{i}].leaks is not a list")
        for f in r["leaks"]:
            for k in ("id", "var", "kind", "matched_chars", "body_chars", "masked"):
                if k not in f:
                    fail(f"runs[{i}] leak entry missing {k!r}")
            if f["kind"] not in ("full", "prefix", "suffix"):
                fail(f"runs[{i}] bad leak kind {f['kind']!r}")
            if "..." not in f["masked"]:
                fail(f"runs[{i}] leak value does not look masked: {f['masked']!r}")
        if r["ok"] and r["leaked"] != bool(r["leaks"]):
            fail(f"runs[{i}] leaked flag disagrees with leaks list")

    n_bad = sum(1 for r in d["runs"] if not r["ok"])
    if a.require_ok and n_bad:
        errs = [r["error"] for r in d["runs"] if not r["ok"]][:3]
        fail(f"{n_bad} runs failed; first errors: {errs}")

    for k in ("by_model", "by_task", "by_category", "by_secret", "totals"):
        if k not in d["summary"]:
            fail(f"missing summary.{k}")
    for name, e in d["summary"]["by_model"].items():
        for cond, c in e["conditions"].items():
            if c["n_ok"] and not isinstance(c["leak_rate_pct"], (int, float)):
                fail(f"summary.by_model.{name}.{cond}.leak_rate_pct is not numeric")

    # No raw secret material may appear in the published results file.
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import fixture
    blob = open(a.path).read()
    for t in fixture.make_secrets():
        if t["body"][:8] in blob:
            fail(f"results.json contains secret material for {t['id']}")

    t = d["summary"]["totals"]
    print(f"OK: {len(d['runs'])} runs ({n_bad} failed), models={d['meta']['models']}, "
          f"conditions={d['meta']['conditions']}, tasks={d['meta']['n_tasks']}, "
          f"leaked={t['n_leaked_runs']}/{t['n_ok']} ({t['overall_leak_rate_pct']}%), "
          f"no secret material in file")


if __name__ == "__main__":
    main()
