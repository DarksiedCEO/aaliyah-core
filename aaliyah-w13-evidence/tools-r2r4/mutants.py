#!/usr/bin/env python3
"""Mutant runner for R2-R4 detectors.

  mutants.py <sha> <spec.json> <out.jsonl>

Each spec entry: {"name", "path", "old", "new", "tests": [...], "regen_evidence": bool,
                  "expect_killer": "substring of the test that must kill it"}
For every mutant, alone: the disposable worktree is forced to <sha>, the
single replacement applied (it must match exactly once, or the mutant is
reported NOT-APPLIED and counts as a failure of the sweep), the migration
evidence optionally regenerated (for mutants that change migration SQL, as a
real developer would), the named test files run under the watchdog, and the
tests that failed recorded. KILLED means the verdict is FAIL and the expected
killer is among the failures. The worktree is forced back to <sha> after.
"""
import json, os, subprocess, sys

M = os.path.expanduser("~/aaliyah-w13-r1mut/aaliyah-wave1-core")
ENV = dict(os.environ, AALIYAH_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:54610/aaliyah_test")

def reset(sha):
    subprocess.run(["git", "-C", M, "checkout", "-q", "-f", "--detach", sha], check=True)
    subprocess.run(["git", "-C", M, "clean", "-q", "-f", "--", "src", "tests", "scripts"], check=True)

def main():
    sha, spec_path, out_path = sys.argv[1:4]
    spec = json.load(open(spec_path))
    results = []
    for m in spec:
        reset(sha)
        p = os.path.join(M, m["path"])
        s = open(p).read()
        n = s.count(m["old"])
        if n != 1:
            results.append({"name": m["name"], "status": "NOT-APPLIED", "matches": n}); continue
        open(p, "w").write(s.replace(m["old"], m["new"]))
        if m.get("regen_evidence"):
            r = subprocess.run(["node", "--require", "ts-node/register", "scripts/migration-evidence.ts", "--write"],
                               cwd=M, env=ENV, capture_output=True, text=True)
            if r.returncode != 0:
                results.append({"name": m["name"], "status": "REGEN-FAILED", "err": r.stderr[-400:]}); continue
        ev = f"/tmp/mut-{os.getpid()}-{m['name']}.json"
        subprocess.run(["node", "scripts/test-watchdog.mjs", "--evidence", ev, *m["tests"]],
                       cwd=M, env=ENV, capture_output=True, text=True)
        e = json.load(open(ev)); os.remove(ev)
        failed = [f["name"] for f in e["failures"]] + [t["name"] for t in e["timedOut"]]
        killer = m.get("expect_killer", "")
        killed = e["verdict"] != "PASS" and any(killer in f for f in failed)
        results.append({"name": m["name"], "status": "KILLED" if killed else "SURVIVED",
                        "verdict": e["verdict"], "counts": e["counts"], "failed": [f[:110] for f in failed]})
        print(json.dumps(results[-1])[:400], flush=True)
    reset(sha)
    with open(out_path, "w") as f:
        for r in results: f.write(json.dumps(r) + "\n")
    bad = [r["name"] for r in results if r["status"] != "KILLED"]
    print("SWEEP:", len(results) - len(bad), "of", len(results), "killed;", "not killed:", bad)
    sys.exit(1 if bad else 0)

main()
