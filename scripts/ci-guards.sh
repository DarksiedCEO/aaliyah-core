#!/usr/bin/env bash
# Deterministic release guards — the invariants that must hold on every commit.
# Each check is fail-closed and prints why. Run from the aaliyah-core root.
#
#   scripts/ci-guards.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
note() { printf '  %s\n' "$1"; }
ok()   { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

# 1. Frozen-file integrity — the fortress doctrine must be byte-identical.
if scripts/aegis-frozen.sh verify >/tmp/frozen.out 2>&1; then
  ok "$(cat /tmp/frozen.out)"
else
  bad "frozen manifest verification failed:"
  sed 's/^/    /' /tmp/frozen.out
fi

# 2. No production file-backed state — Postgres is the sole durable store.
HITS="$(grep -rnE 'appendFileSync|writeFileSync|createWriteStream' src/ 2>/dev/null || true)"
if [ -z "$HITS" ]; then
  ok "no file-backed persistence in src/"
else
  bad "file-backed persistence found in src/:"; echo "$HITS" | sed 's/^/    /'
fi

# 3. No-send invariant — mail.send.execute may only appear in the REFUSED list.
SEND_HITS="$(grep -rn 'mail\.send\.execute' src/ 2>/dev/null | grep -v 'REFUSED_SERVICE_GRANTS' \
  | grep -viE '^\s*\*|//|reserved for the internal' || true)"
# The comment line in permissions.ts is documentation; only flag a real grant.
GRANT_HITS="$(grep -rnE 'roles?.*mail\.send\.execute|grant.*mail\.send\.execute|mail\.send\.execute.*:\s*\[' src/ 2>/dev/null || true)"
if [ -z "$GRANT_HITS" ]; then
  ok "no role/service grants mail.send.execute"
else
  bad "a grant of mail.send.execute was found:"; echo "$GRANT_HITS" | sed 's/^/    /'
fi

# 4. Placeholder scan with honest classification. Targets unambiguous
#    unfinished-work MARKERS (not real identifiers that merely contain "stub" or
#    "placeholder"). The known frozen simulations + the pre-existing out-of-scope
#    planner are DISCLOSED, not new blockers, and are excluded.
ALLOW='src/services/executeIdempotent.ts|src/services/verifyPostconditions.ts|src/application/planner/llmPlanner.ts|src/application/planner/planTask.ts'
PH="$(grep -rniE 'TODO|FIXME|not implemented|NotImplemented|console-only persistence|fire.and.forget' src/ 2>/dev/null \
  | grep -vE "$ALLOW" || true)"
if [ -z "$PH" ]; then
  ok "no new unfinished-work markers (disclosed frozen sims excluded)"
else
  bad "new unfinished-work marker(s) in reachable production code:"; echo "$PH" | sed 's/^/    /'
fi

# 5. Secret scan — nothing secret-shaped may be committed.
SEC="$(git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)|\.pem$|\.key$|service-account.*\.json$' || true)"
if [ -z "$SEC" ]; then
  ok "no committed .env / key / service-account files"
else
  bad "secret-shaped file(s) committed:"; echo "$SEC" | sed 's/^/    /'
fi

# 6. Cross-repo dependency — core must not import/build against aaliyah-workflows.
#    Only flag real module references, not prose in comments or this guard.
WF="$(grep -rnE "(import|require|from)[^\n]*aaliyah-workflows" src/ scripts/ 2>/dev/null \
  | grep -v 'scripts/ci-guards.sh' || true)"
if [ -z "$WF" ]; then
  ok "no core->aaliyah-workflows code dependency"
else
  bad "core references aaliyah-workflows:"; echo "$WF" | sed 's/^/    /'
fi

# 7. Shared completion contracts must resolve to the exact reviewed candidate.
if scripts/contracts-provenance.sh >/tmp/contracts-provenance.out 2>&1; then
  ok "$(cat /tmp/contracts-provenance.out)"
else
  bad "Contracts provenance mismatch:"
  sed 's/^/    /' /tmp/contracts-provenance.out
fi

# 8. The full suite's executed set must be the COMMIT's set.
#    Red team K-19 against 8a0bf05: `.gitignore` excludes `coverage`, and the
#    full-suite glob walks the filesystem, so `tests/coverage/*.test.ts` was
#    discovered and EXECUTED while `git status` stayed empty and the evidence
#    recorded `git.dirty: false`. Asked here as well as inside `npm test`,
#    because a guard that answers in under a second is worth having before
#    anyone pays for a suite.
if node scripts/test-watchdog.mjs --verify-discovery >/tmp/discovery.out 2>&1; then
  ok "the full suite's executed set is bound to the commit"
else
  bad "test discovery is not bound to the commit:"
  sed 's/^/    /' /tmp/discovery.out
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "RELEASE GUARDS: FAIL"; exit 1
fi
echo "RELEASE GUARDS: PASS"
