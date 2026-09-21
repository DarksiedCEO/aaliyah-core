# AEGIS Ω-MAX ADJUDICATION — W1.3 Trusted Memory, candidate-4

    subject        w13-candidate-4 = e71b51e9ed333d1feab1cd6819496269d201a6e2
    contracts      7d576681d1001eb4c4a7f044f7793cdb3f80af76
    evidence       aaliyah-w13-evidence/e71b51e/reviews/ at 1b0499f (remote)
    adjudicator    independent session, cloud clone of origin. Not the builder,
                   not the coordinator, not any gate. Saw no work being produced.
    date           2026-09-20

## VERDICT

**W1.3: RED. BLOCK. NOT CERTIFIED.** Production: NOT CERTIFIED. Fortress: NOT CERTIFIED.

Five of seven gates block. Under the weakest-mandatory-domain rule, one blocking gate
suffices; here the Test Falsifiability gate alone carries a Critical finding (F5) that
invalidates the candidate's headline claim, and four other gates block independently.

This adjudication does not dispute any gate's blocking finding. It disputes two
severities, resolves the four cross-gate disagreements the coordinator left open,
re-clusters twenty-odd findings into five root causes, and orders the remediation so the
next candidate is measured by an instrument that works before anything else is measured.

## EVIDENCE STANDARD USED HERE

| tier | meaning | applied to |
|---|---|---|
| CONFIRMED-BY-READING | adjudicator read the source at e71b51e and the claim is what the source says | RT4-3, RT4-4, RT4-1 (absence of any assume-unchanged check), R-10, R-11, F6/R-13 mechanism |
| EXECUTED-BY-GATE | gate reports execution with verbatim output; adjudicator could not reproduce (no contracts repo, no Postgres in this seat) | F5, R-13, R-14, I-5, I-9, D-03, D-09, RT4-6, SEC-E, R-01/R-02 |
| REPORTED | asserted without verbatim execution record | none load-bearing |

Nothing below is upgraded past its tier. Every EXECUTED-BY-GATE finding is a claim the
builder must re-execute as the first step of its remediation, not accept.

## THE HEADLINE, IN ONE PARAGRAPH

The migrator fix of this round is sound. Gate 3 reproduced the race at will without the
lock (15,965 lost races in 21,600) and eliminated it with the lock (0 in 9,600); crash
recovery is clean; both restored controls have named detectors. That work stands. What
blocks is everything around it: **the suite cannot demonstrate that green means green**
(F5, R-13, R-14, I-9: five consecutive runs at one SHA, zero reproductions of 1088/1088 in
one gate, one in five in another, 118 false failures then 471/471 on a recreated database
in a third); **the migration ledger fails open** (D-03, I-5: it certifies schemas that were
never applied, and the pre-057 upgrade path launders edited migrations permanently);
**controls whose removal nothing detects** are still being shipped in violation of the
branch's own standing rule (R-10, RT4-3, RT4-4, D-09: 17 CHECK constraints, 3 pool bounds,
the G-02 tenant-crossover fix, and the migrator lock's ordering); and **the builder's own
gate evidence is forgeable** by a single git command (RT4-1). Candidate-4 is a better
candidate than candidate-1. It is not a certifiable one.

## CROSS-GATE DISAGREEMENTS — RESOLVED

**1. RT-M4 / the three-column unnest JOIN (gate 2: Low, gate 4: Important).**
Ruling: **Important, blocking. Gate 4 stands.** The two gates measured different axes.
Exploitability (gate 2) is correct today because the scoped map key is load-bearing.
Detectability (gate 4) is the axis the standing rule governs: this JOIN is the recorded
fix for G-02, the previous round's HIGH, and it has survived removal across two rounds
with the full suite green. The rule says a control is closed by a detector or by an
executed redundancy proof reviewed as a production change. Neither exists. If the JOIN is
redundant, prove it by execution and record the map key as the sole control; if it is
not, write the detector. CONFIRMED-BY-READING: the JOIN at wave1TrustedMemoryStore.ts:2699-2701.

**2. The migrator (gate 3: SOUND; gate 4: lock defeated by reordering).**
Ruling: **both stand; RT4-3 is Important and blocking.** The code is correct. The detector
K-06c cannot see a reorder because every destroyer in the set deletes or inverts, none
reorders. CONFIRMED-BY-READING: migrations.ts:6278-6279, lock then ledger. A detector
that fails when the ledger is created before the lock is held is required. This is the
same finding-shape as the round's own lesson: "no test fails when I move this."

**3. The 1086/1087 denominator (four gates, none closed it).**
Ruling: **stays OPEN as a root cause; CLOSED as a risk by a structural control.** Nothing
in the repository pins the expected denominator, so a moving count can only ever be
noticed, never refused. Remediation R1.3 below pins the executed test-name manifest to the
commit and makes the watchdog fail on any delta. After that lands, the discrepancy stops
being a mystery and becomes a detected event with a named file. Gate 1's F2 (hookSentinel
+1 mechanism) and gate 5's I-10 (synthetic file-level failure entries) are the two
mechanisms in hand; root-cause them under the pinned denominator, not before.

**4. Gate 4's claim that pool.ts K-05 bounds went unmutated.**
Ruling: **gate 3's R-08/R-10 already covered it; gate 4 could not see gate 3's report.**
Not a finding. The narrower hole (isConnectionAmbiguous, releaseClient) is folded into R3.1.

## SEVERITY ADJUSTMENTS

- **D-05 (no RLS; tenant isolation is a query contract) — gate 7: Important, blocking.
  Adjudicated: Important, NOT a W1.3 blocker, FOUNDER DECISION required before W1.4.**
  The candidate does not claim database-enforced read isolation; migrations.ts:25-27
  discloses the opposite. A disclosed limitation outside the claimed boundary is not a
  defect in the candidate. It is a defect in the product plan if Aaliyah ships
  multi-tenant, which is the stated intent. See Founder Decision B.
- **R-07 (315 failures under co-tenant load) — environment-attributed by the gate.
  Adjudicated: not blocking, but it is the third suite denominator (1091) and feeds R1.**
- **SEC-E (privilege map blind to SECURITY DEFINER bodies) — Medium, non-blocking, handed
  up. Adjudicated: Medium, scheduled in R3. DBA-tier to exploit; cheap to close (digest
  prosrc into the map).**

## ROOT CAUSES — FIVE, NOT TWENTY

| # | root cause | findings that are symptoms of it |
|---|---|---|
| RC-1 | **The measuring instrument is unreliable.** The suite's verdict depends on residual database state, a test hangs by assert-before-release, the denominator is unpinned, and a 57P01 admin-termination is unexplained. | F5, F6, R-13, R-14, R-07, I-9, I-10, F2, D-01, coordinator's 2×2 hypothesis |
| RC-2 | **The ledger is trusted where effects should be verified.** The migrator believes ledger rows it did not write, backfills digests it cannot vouch for, and never reads back the schema it claims to have produced. | D-03 (L4, L4b, L5), I-5, I-6, R-04 |
| RC-3 | **Controls without detectors are still being shipped**, contrary to the standing rule the branch adopted two days ago. | R-10, R-15, RT4-3, RT4-4, D-09(B), F1, F3, RT4-6 |
| RC-4 | **Gate evidence produced by the builder is forgeable.** Hygiene claims rest on `git status` and the watchdog's `git.dirty`, both blind to `assume-unchanged`; guard 8 passes with zero tests run. | RT4-1, RT4-5, I-1, I-3, I-4 |
| RC-5 | **Tenant isolation has no database backstop.** Architectural; disclosed; outside W1.3's claim. | D-05, SEC-E, SEC-F |

## REMEDIATION ORDER — THE WORK ORDER

Principle: fix the instrument before the measured. Every "1088/1088" in this round,
including the coordinator's three clean serial runs, is unproven until R1 lands, because
nothing yet distinguishes a real pass from a pristine-database pass.

### R1 — Instrument (gate for everything after it)

- **R1.1 F6/R-13.** `wave1PoolResiliencePostgres.integration.test.ts:515-523`: release
  the client before asserting; ensure `pool.end()` cannot wait forever on a held client.
  CONFIRMED-BY-READING. Also the K-05 companion that hangs instead of reporting (F6).
- **R1.2 I-9.** The full-suite harness must run against a database it created in that run,
  or record a pre-run fingerprint (schema hash + row counts of every `memory_%` table +
  ledger) and refuse to run on a used one. Then **execute the 2×2** (serial/concurrent ×
  pristine/used) and record it. If "used" fails and "pristine" passes, I-9 is confirmed
  and pristine becomes mandatory, not advisory.
- **R1.3 Denominator.** Commit a manifest of executed test names. Watchdog fails on any
  delta between executed set and manifest. Root-cause F2 (hookSentinel +1) and I-10 under
  that control.
- **R1.4 R-11.** The migration positive control accepts the full `LEDGER_RACE_LOST` set
  (`42P07`, `23505`, `42710`), not `23505` alone. CONFIRMED-BY-READING: test :785 vs
  migrations.ts:6128.
- **R1.5 R-14.** The `57P01` must be root-caused, not tolerated. Likely a
  `pg_terminate_backend` from another test's cleanup on a shared database, which R1.2
  would eliminate; verify that, do not assume it.
- **R1.6 RT4-5.** `--verify-discovery` / guard 8 must FAIL when zero tests executed.

**R1 acceptance:** five consecutive full-suite runs, serial, quiet host, pristine database
each, identical executed set equal to the manifest, all PASS. Then five more on a used
database. Report both cells. If the used cell fails, that is the I-9 confirmation and the
harness enforces pristine.

### R2 — Ledger integrity

- **R2.1 D-03 L4/L5.** Post-057, a ledger row with NULL digest is refused, not re-blessed.
  Phantom rows with no digest are refused.
- **R2.2 I-5 / D-03 L4b.** The pre-057 upgrade path must not silently backfill digests.
  Backfill becomes an explicit, operator-attested step recorded in the ledger with actor
  and timestamp. Independently: **each migration declares the catalog objects it creates,
  and the migrator reads them back after apply** (doctrine item 2: external success
  requires read-back). That closes L4b, which no digest scheme can close, because a true
  digest on a row for SQL that never ran is indistinguishable from a real one.
- **R2.3 RT4-3.** A detector that fails when the ledger is created before the advisory
  lock is held.
- **R2.4 R-04.** Lock wait (120 s) vs per-statement work (300 s, unbounded aggregate):
  either the wait bound covers the work bound, or the second instance waits-and-retries
  rather than crash-looping at boot. Add the test that relates the two bounds.
- **R2.5 I-6.** Fix the comment or the code; the partial-restore claim is currently false.

### R3 — Controls without detectors

- **R3.1 R-10 / R-15.** Assert pool bounds against independent expected values, or
  behaviourally (a connection that hangs is cut at `connectionTimeoutMillis`). Same for
  `PROVIDER_DEADLINE_MS`. Include `isConnectionAmbiguous` and `releaseClient` mutants.
- **R3.2 RT4-4.** G-02 JOIN: detector, or executed redundancy proof reviewed as a
  production change. Given G-02's history, detector.
- **R3.3 D-09(B).** The 8 CHECK constraints that are the sole enforcement on the
  key-destruction settlement path get drop-tests first. The other 9: detector or executed
  redundancy proof. Correct the register: population is 162, untested is 17, triggers 0/56.
  The "67" figure is withdrawn.
- **R3.4 RT4-6.** G-07's unreachability proof is false (the harness's own database has
  NULL `datacl`). Reclassify, add the case, and extend the closure audit's denominator to
  include it. Fourth instance of a reasoned-not-executed proof failing; the standing rule
  already requires execution.
- **R3.5 F1, F3.** K-07's fixture-precondition assertion measured in the right session;
  migrator ledger-completeness assertions that detect a migration silently not applying.
- **R3.6 SEC-E.** Digest `prosrc` of every SECURITY DEFINER function into the privilege map.

### R4 — Provenance

- **R4.1 RT4-1.** Hygiene = on-disk content hashes compared against `git ls-tree HEAD`,
  plus `git ls-files -v` scanned for `assume-unchanged`/`skip-worktree` bits. `git status`
  is not a hygiene check. CONFIRMED-BY-READING: no such check exists in scripts/ or CI.
- **R4.2 Gates 1–3 are never again run by the builder's session.** They are run by the
  review side, and the record names which session ran them.
- **R4.3 I-1, I-3, I-4, mkenv.sh.** Correct the handoff's false "verifiable without the
  contracts repo" claim; extend the frozen manifest to cover `scripts/`; unique tmp names
  in `ci-guards.sh`; `mkenv.sh` migrates the cluster it creates.

### Out of W1.3 scope, carried forward with their own gates

- Approval-review double count (reviewed_at not persisted): first change after
  certification, before consolidation, as already scheduled.
- Migration 047 not rolling-safe: documented; no deployment authorised.
- D-04 (plaintext in heap until VACUUM): disclosed accurately; schedule a VACUUM policy.
- D-08 (no rollback path; TRUNCATE defeats append-only): owner-tier; register it.

## FOUNDER DECISIONS REQUIRED

**A. Merge/split identity semantics.** Unchanged from the handoff. Blocks W1.4.

**B. Database-enforced tenant isolation (D-05).** Aaliyah is intended as a multi-tenant
product. Today, one forgotten `WHERE tenant_id = $1` is a cross-tenant read with no
backstop. Options: (1) RLS on all 21 `memory_%` tables as a W1.4 item, before any
multi-tenant claim; (2) accept query-contract isolation for W1.3 and the first
single-tenant deployment, with RLS gated before the second tenant. Adjudicator's
recommendation: (1), scheduled, not folded into W1.3. Either way, decide it now so the
W1.4 plan is built on the answer.

**C. Confirm the seventh gate.** The coordinator inferred "Data & Persistence" for gate 7
because only six gate files existed. It produced the D-09 headline. Confirm it as the
permanent seventh, or name what was intended.

## PROCESS FINDINGS FOR THE REGISTER

1. **Reviewer independence found what builder-run gates missed, for the second candidate
   in a row.** Gates 1–3 passed on candidates 1–4. The seven independent gates blocked
   candidate-4 five ways. The separation is not a formality.
2. **Concurrent dispatch corrupted timing evidence.** Load 76 on 14 CPUs, by the
   coordinator's own account. Next round: at most two gates concurrent; timing-sensitive
   gates (1, 3) alone on a quiet host.
3. **The same defect shape, sixth time.** Every real finding in this build has been a
   control whose removal nothing detects or an assertion that cannot fail. It has now
   appeared in tests, in verification tooling, in a published proof, and in the hygiene
   evidence itself. The standing rule exists; R3 and R4 are its enforcement.

## RE-CERTIFICATION PATH

Remediation produces a new descendant. Candidate-5 must:
1. Pass R1 acceptance (both 2×2 cells reported) before any other gate runs.
2. Have gates 1–3 run by the review side, with R4.1 hygiene.
3. Be re-reviewed by all seven gates; gates may carry forward only findings they
   re-execute at the new SHA (per gate 6's own rule).
4. Return to this seat for adjudication.

Honest sizing: R1 is one to two builder sessions and gates everything. R2–R4 are two to
four more. Then a full gate round. If no new class of finding appears, W1.3 certification
is one to two weeks of build sessions away. The base rate in this build says a new class
of finding will appear; plan for one more round after that.

**Not certified. Not production. Not Fortress. RED.**
