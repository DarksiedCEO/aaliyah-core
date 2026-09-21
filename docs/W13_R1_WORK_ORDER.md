# W1.3 — R1 WORK ORDER: REPAIR THE INSTRUMENT

    issued       2026-09-20
    authority    AEGIS Ω-MAX adjudication of candidate-4,
                 aaliyah-w13-evidence/e71b51e/AEGIS-ADJUDICATION.md
    verdict      W1.3 RED. BLOCK. NOT CERTIFIED.
    subject      e71b51e (candidate-4) is the adjudicated SHA. R1 produces a
                 descendant. Candidate-5 is NOT declared until R1 acceptance is met.
    scope        R1 ONLY. R1 gates every other item in the remediation order.

## THE LAW FOR THIS SESSION

**Nothing but R1 until R1's acceptance is met.** Not R2, not R3, not R4, not the
carried-forward items, not the founder decisions. This is not sequencing preference;
it is the adjudication's central ruling, and the reason is mechanical:

> Every "1088/1088" in this round, including the coordinator's three clean serial runs,
> is unproven until R1 lands, because nothing yet distinguishes a real pass from a
> pristine-database pass.

Any fix landed before R1 is measured by an instrument that cannot show it worked. You
would be adding unverifiable claims to a pile the adjudicator has already refused.

**Do not re-run gates 1–3 from this session.** R4.2 removes builder-run gates permanently.
Until R4 lands, a gate result produced by the builder's session is not evidence.

## EVIDENCE TIERS USED BELOW

| tier | meaning |
|---|---|
| VERIFIED-HERE | read at `e71b51e` while writing this order; the anchor is what the source says |
| ADJUDICATED | the adjudicator read it at `e71b51e` (CONFIRMED-BY-READING in that document) |
| EXECUTED-BY-GATE | a gate reports execution with verbatim output; **re-execute before accepting** |

Per the adjudication: *every EXECUTED-BY-GATE finding is a claim the builder must
re-execute as the first step of its remediation, not accept.* That applies to R1.2 and
R1.5 in particular — they are the two items here whose premise is a gate's report.

---

## R1.1 — THE TEST THAT HANGS INSTEAD OF REPORTING

**Tier: VERIFIED-HERE.** `tests/wave1PoolResiliencePostgres.integration.test.ts`

    515    assert.equal(isConnectionAmbiguous(failure), true, String(failure));
    516    releaseClient(client, failure);
    ...
    523    await pool.end().catch(() => undefined);

The assert precedes the release. When line 515 fails, 516 never runs, the client is never
returned to the pool, and `pool.end()` at 523 waits forever on a held client. **A failing
assertion becomes a hang, not a failure report.** This is a test that cannot tell you it
is broken — the exact shape this branch has now found six times.

**Do:** release the client before asserting, in this test and in the K-05 companion that
shares the defect (F6). Then ensure `pool.end()` cannot block indefinitely regardless —
a bounded end, or a release in `finally` that runs before it.

**Proven done by:** forcing the assertion to fail (invert it temporarily) and observing
the suite REPORT a failure within the normal timeout, not hang. Record that observation.
A fix here that is only reasoned about repeats RT4-6's error.

## R1.2 — THE HARNESS MUST NOT RUN ON A USED DATABASE

**Tier: EXECUTED-BY-GATE (I-9). Re-execute the premise before building the fix.**

Three gates produced three different denominators at one SHA — gate 1 saw 1088/1088 zero
times in five runs, gate 3 once in five, gate 5 took 118 failures, recreated the database,
and got 471/471. The hypothesis is residual database state.

**Do, in order:**
1. **Re-execute the premise.** Confirm that a used database changes the verdict at this
   SHA. If it does not, stop and report — the root cause is elsewhere and R1.5 becomes
   primary.
2. Make the full-suite harness either create the database it runs against in that run, or
   record a pre-run fingerprint — schema hash, plus row counts of every `memory_%` table
   and the migration ledger — and **refuse to run** on a used one.
3. **Execute the 2×2**: serial/concurrent × pristine/used. Record all four cells.

**Note the refusal must be a refusal**, not a warning. A harness that prints a caution and
proceeds is RC-3's shape in the instrument itself.

## R1.3 — PIN THE DENOMINATOR

**Tier: VERIFIED-HERE (absence).** No test-name manifest exists in `scripts/`.

Nothing in the repository pins the expected test count or set, so the 1086/1087/1088/1091
drift can only ever be *noticed*, never *refused*.

**Do:** commit a manifest of executed test names. The watchdog fails on any delta between
the executed set and the manifest — additions and removals alike.

**Then, and only under that control,** root-cause the two mechanisms already in hand:
F2 (the `hookSentinel` +1) and I-10 (synthetic file-level failure entries). The
adjudication is explicit that these are diagnosed *after* the denominator is pinned, not
before — otherwise you are explaining a number that is still free to move.

## R1.4 — THE POSITIVE CONTROL IS NARROWER THAN THE TOLERANCE IT GUARDS

**Tier: VERIFIED-HERE.**

Production tolerates the full lost-race set — `migrations.ts:6128`:

    const LEDGER_RACE_LOST = new Set(["42P07", "23505", "42710"]);

The positive control accepts one member of it — `tests/wave1MigrationReplayPostgres.integration.test.ts:785`:

    assert.ok(
      codes.every((code) => code === "23505"),
      `expected 23505 unique-violation losses; got ${JSON.stringify(codes)}`,
    );

A migrator losing the race with `42P07` or `42710` is forgiven in production and has never
been exercised by the control that claims to cover it. Worse, the test would **fail** on a
legitimate production-tolerated outcome.

**Do:** accept the full `LEDGER_RACE_LOST` set. Assert the set relationship against the
production constant directly rather than re-typing the codes, so the two cannot drift
apart again — this is a detector for the drift, not just a wider assertion.

## R1.5 — ROOT-CAUSE THE 57P01, DO NOT TOLERATE IT

**Tier: EXECUTED-BY-GATE (R-14).**

An admin termination is appearing in runs and is currently unexplained. The leading
hypothesis is a `pg_terminate_backend` from another test's cleanup against a shared
database — which R1.2 would eliminate as a side effect.

**Do:** verify that hypothesis; do not assume it. If R1.2 lands and the 57P01 disappears,
that is consistent with the hypothesis but does not prove it — name which cleanup path
issued it, or record explicitly that the cause is unproven and the disappearance is
correlation only. Do not close this by observing the symptom stop.

## R1.6 — A GUARD THAT AFFIRMS A PROPERTY OF THE EMPTY SET

**Tier: VERIFIED-HERE.** This is worse than RT4-5 as stated. The chain:

- `scripts/test-watchdog.mjs:162-166` — `discoveryBinding(files)`: when the relative file
  list is empty, it returns `{ verified: true, ignored: [], untracked: [], missing: [], reason: null }`.
- `scripts/test-watchdog.mjs:480-482` — `if (options.verifyDiscoveryOnly) { finish("PASS"); return; }`,
  unconditional once the binding "verified".
- `scripts/ci-guards.sh:87-89` — exit 0 prints `ok "the full suite's executed set is bound to the commit"`.

**Zero tests discovered yields a green claim that the executed set is bound to the commit.**
The empty set satisfies the binding vacuously. Note that `:674` already has a `ZERO_TESTS`
reason in the *run* path — the concept exists; the discovery path simply never reaches it.

**Do:** `--verify-discovery` FAILS when the discovered set is empty, and `discoveryBinding`
distinguishes "verified" from "vacuous". A binding assertion over an empty set is not
satisfied, it is undefined.

**While you are in this file:** `ci-guards.sh:87` writes to the fixed path `/tmp/discovery.out`
(finding I-4). It is a one-line fix and you are already editing the line. Take it — but do
not expand further into R4; the rest of R4.3 waits.

---

## R1 ACCEPTANCE — THE EXIT CRITERION

    five consecutive full-suite runs
      serial, quiet host, PRISTINE database each
      identical executed set, equal to the committed manifest
      all PASS

    then five more on a USED database

    report BOTH cells

If the used cell fails, that is the I-9 confirmation, and the harness enforces pristine
from then on. If the used cell passes, say so plainly — it falsifies the leading hypothesis
and R1.5 becomes the primary open thread.

**Report both cells whatever they say.** A one-cell report is not R1 acceptance, and the
adjudicator will treat it as one.

"Quiet host" is load-bearing and was violated last round: the coordinator dispatched
concurrently at load 76 on 14 CPUs and corrupted the timing evidence. Do not run the
acceptance runs alongside anything else on this machine.

## TRAPS THIS ROUND HAS ALREADY PAID FOR

1. **A harness setting that changes what a measurement means.** Gate 3 disclosed a false
   FAIL from running the baseline under the mutant-judging timeout. If you change a
   timeout, a flag, or a concentration, the measurement before and after are not
   comparable — say so in the record rather than reporting the delta.
2. **Reasoned proofs that execution falsifies.** Four instances so far (M-47/M-55, G-07,
   the masking triple, the M-30 redundancy claim). The standing rule already requires
   execution. Every claim in the R1 report is executed or it is labelled unproven.
3. **Fixing the symptom you can see instead of the one you measured.** R1.5 is the live
   example; R1.3's ordering exists for the same reason.
4. **`git status` is not hygiene.** Do not add evidence that rests on it. R4.1 replaces it
   wholesale, but do not pre-empt R4 here either — just do not deepen the dependency.

## WHAT TO HAND BACK

A report, as a committed file under `aaliyah-w13-evidence/`, carrying:

- each R1 item, what changed, and the **executed** proof it works — including the
  deliberately-failed assertion for R1.1;
- the 2×2 table, all four cells, verbatim output;
- the acceptance runs, both cells of five;
- anything R1 touched that moved a number elsewhere;
- explicitly, what R1 did **not** cover.

Then stop. Candidate-5 is declared by the review side, not by this session, and gates 1–3
are run by the review side under R4.2.

