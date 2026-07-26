#!/usr/bin/env python3
"""Replace synthetic secret values in captured model outputs with an identifying marker.

Every secret in this study is synthetic and seed-generated, so none of them is a real
credential. They are still shaped exactly like real ones, which is the point of the fixture,
and that has two consequences worth acting on:

  1. GitHub push protection rejects the repository, correctly. A scanner cannot tell a
     structurally perfect fake from the real thing, and it should not try.
  2. Anyone cloning the repo gets a working set of Stripe-shaped, SendGrid-shaped and
     AWS-shaped strings in their working tree, which will trip their scanners too.

Nothing analytically useful is lost by redacting. The finding is *which* secret appeared and
how much of it, and that is already recorded in each run's `leaks` array with the secret id,
match length and a masked prefix. The literal values regenerate from `fixture.py` with the
same seed, so a reader who wants them can produce them in one command.

    scrub_raw.py [--check] [dir ...]

Exits nonzero under --check if any raw capture still holds a secret body, so verify.sh can
gate on it and this cannot regress.
"""

import argparse
import json
import pathlib
import sys

import fixture

MIN_BODY = 8   # matches the detector's partial-credit threshold


def secret_bodies():
    """(id, body) for every synthetic secret, longest first so nesting cannot mis-replace."""
    out = []
    for s in fixture.make_secrets():
        body = s["body"]
        if body and len(body) >= MIN_BODY:
            out.append((s["id"], body))
    return sorted(out, key=lambda p: -len(p[1]))


def scrub_text(text, bodies):
    hits = []
    for sid, body in bodies:
        if body in text:
            text = text.replace(body, f"<redacted:{sid}>")
            hits.append(sid)
    return text, hits


def walk(paths):
    for p in paths:
        p = pathlib.Path(p)
        if p.is_file() and p.suffix in (".json", ".txt", ".log", ".md"):
            yield p
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in (".json", ".txt", ".log", ".md") and ".git" not in f.parts:
                    yield f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", default=["raw", "raw_pressure"])
    ap.add_argument("--check", action="store_true",
                    help="report without writing, and exit 1 if anything is unredacted")
    a = ap.parse_args()

    bodies = secret_bodies()
    if not bodies:
        sys.exit("no synthetic secrets resolved from fixture.py")

    changed, offenders = 0, []
    for f in walk(a.paths):
        try:
            original = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scrubbed, hits = scrub_text(original, bodies)
        if not hits:
            continue
        offenders.append((str(f), sorted(set(hits))))
        if not a.check:
            f.write_text(scrubbed, encoding="utf-8")
            changed += 1

    if a.check:
        if offenders:
            print(f"{len(offenders)} capture(s) still contain a synthetic secret body:")
            for path, ids in offenders[:20]:
                print(f"  {path}: {', '.join(ids)}")
            print("\nRun scrub_raw.py to redact them. Committing these makes the repository "
                  "unpushable and trips a cloner's scanners.")
            sys.exit(1)
        print(f"clean: no synthetic secret body in any capture ({len(bodies)} secrets checked)")
        return

    print(f"redacted {changed} file(s), {len(bodies)} synthetic secrets checked")
    for path, ids in offenders[:15]:
        print(f"  {path}: {', '.join(ids)}")


if __name__ == "__main__":
    main()
