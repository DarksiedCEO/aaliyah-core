import subprocess, json, sys, os
M = os.path.expanduser("~/aaliyah-w13-r1mut/aaliyah-wave1-core")
W = "scripts/test-watchdog.mjs"
MUTANTS = [ ("M7-empty-manifest-accepted", W, 'if (lines.length === 0) {', 'if (false) {', 'tests/testWatchdog.test.ts') ]
OLD = [
 ("M1-vacuous-verified", W, 'return {\n      verified: false,\n      vacuous: true,', 'return {\n      verified: true,\n      vacuous: false,', "tests/testWatchdog.test.ts"),
 ("M1b-vacuous-no-reason", W, 'reason:\n        "DISCOVERY_VACUOUS:', 'reason: null && \n        "DISCOVERY_VACUOUS:', "tests/testWatchdog.test.ts"),
 ("M2-synthetic-silent", W, 'if (synthetic.length > 0) {\n      reasons.push(', 'if (false) {\n      reasons.push(', "tests/testWatchdog.test.ts"),
 ("M3-lost-ignored", W, 'return { added: added.sort(), lost: lost.sort() };', 'return { added: added.sort(), lost: [] };', "tests/testWatchdog.test.ts"),
 ("M4-added-ignored", W, 'return { added: added.sort(), lost: lost.sort() };', 'return { added: [], lost: lost.sort() };', "tests/testWatchdog.test.ts"),
 ("M5-denominator-unchecked", W, 'if (summary && summary.counts.tests !== expected.length) {', 'if (false) {', "tests/testWatchdog.test.ts"),
 ("M6-filebinding-skipped", W, 'const manifestRefusal = manifestFileBinding(files);', 'const manifestRefusal = null;', "tests/testWatchdog.test.ts"),
 ("M7-empty-manifest-accepted", W, 'if (lines.length === 0) {', 'if (false) {', None),
 ("M8-tolerance-drops-23505", "src/persistence/postgres/migrations.ts", 'new Set(["42P07", "23505", "42710"])', 'new Set(["42P07", "42710"])', "tests/wave1MigrationReplayPostgres.integration.test.ts"),
]
env = dict(os.environ, AALIYAH_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:54610/aaliyah_test")
out = []
for name, path, old, new, test in MUTANTS:
    subprocess.run(["git","-C",M,"checkout","-q","-f","--detach","27b545e4607c62e8e74df9799183540e10f00eb7"], check=True)
    p = os.path.join(M, path); s = open(p).read()
    if s.count(old) != 1: out.append((name, "MUTANT-NOT-APPLIED", s.count(old))); continue
    open(p,"w").write(s.replace(old,new))
    if test is None: out.append((name, "NO-DETECTOR-RUN (see note)")); continue
    ev = os.path.expanduser(f"~/aaliyah-w13-r1-runs/mut-{name}.json")
    r = subprocess.run(["node","scripts/test-watchdog.mjs","--evidence",ev,test], cwd=M, env=env, capture_output=True, text=True)
    e = json.load(open(ev))
    killers = [f["name"][:70] for f in e["failures"]] + [t["name"][:70] for t in e["timedOut"]]
    out.append((name, e["verdict"], e["counts"] and f'{e["counts"]["passed"]}/{e["counts"]["tests"]}', killers))
subprocess.run(["git","-C",M,"checkout","-q","-f","--detach","27b545e4607c62e8e74df9799183540e10f00eb7"], check=True)
for o in out: print(json.dumps(o))
