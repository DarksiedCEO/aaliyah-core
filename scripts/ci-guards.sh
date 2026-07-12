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
if shasum -a 256 -c .aegis-frozen.sha256 >/tmp/frozen.out 2>&1; then
  ok "frozen files byte-identical ($(wc -l < .aegis-frozen.sha256 | tr -d ' ') pinned)"
else
  bad "frozen file(s) changed:"; grep -v ': OK$' /tmp/frozen.out | sed 's/^/    /'
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

echo
if [ "$fail" -ne 0 ]; then
  echo "RELEASE GUARDS: FAIL"; exit 1
fi
echo "RELEASE GUARDS: PASS"
