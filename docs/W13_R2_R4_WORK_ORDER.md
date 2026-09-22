# W1.3 — R2/R3/R4 WORK ORDER (Track B, certification)

    branch        wave1/w13-trusted-memory
    base          fa14db0 (R1 acceptance MET; 1098/1098 ×10, manifest pinned)
    source        aaliyah-w13-evidence/e71b51e/AEGIS-ADJUDICATION.md §R2–R4, plus the four
                  items R1 reported it did not cover
    writer        the Track B builder session, sole writer on this branch
    issuer        adjudication seat, 2026-09-21

## Why R2–R4 run BEFORE the next gate round

A seven-gate round now would re-find every R2–R4 item the adjudication already
holds. One gate round on the R2–R4 descendant is the fewer-iterations path.
Gates 1–3 and the seven reviewers run once, on the candidate that carries all of
R1–R4, by the review side.

## Standing rules (unchanged)

- Re-execute every EXECUTED-BY-GATE premise before acting on it.
- A premise that fails to reproduce stops its own item only.
- Test-only fixes: no stop. Production-code change: record in the register, add
  the detector that kills its mutant, continue. Stop only for scope beyond R2–R4
  or a founder decision.
- Commit and push at every checkpoint. Full-suite runs serial, pristine database,
  never inside a subagent. Nothing destructive in git.
- A surviving mutant is closed by a detector or by an EXECUTED redundancy proof.
  Never by deleting the mechanism.

## R2 — Ledger integrity

| id | item | acceptance |
|---|---|---|
| R2.1 | D-03 L4/L5: post-057, a ledger row with NULL digest is REFUSED, never re-blessed; phantom rows without digest are REFUSED | gate 7's L4, L4b, L5 cases re-executed and all three fail CLOSED; L5-control still refuses |
| R2.2 | I-5 / D-03 L4b: pre-057 upgrade path does not silently backfill digests. Backfill is an explicit operator-attested step recorded in the ledger (actor, timestamp). Each migration declares the catalog objects it creates and the migrator READS THEM BACK after apply | gate 5's p4 probe re-executed: the edited-055 upgrade is REFUSED, not laundered; a ledger row for a migration whose objects are absent is REFUSED |
| R2.3 | RT4-3: detector that fails when the ledger is created before the advisory lock is held (the reorder mutant) | MUT-B (swap :6278/:6279) killed with a named assertion |
| R2.4 | R-04: lock wait (120 s) vs per-statement bound (300 s). Either the wait covers the work, or the second instance waits-and-retries instead of crash-looping. Add the test that relates the two bounds | a second migrator against a slow first migrator does not crash at boot |
| R2.5 | I-6: fix the partial-restore comment or the code; the claim is currently false | comment and behaviour agree; a test pins it |

## R3 — Controls without detectors

| id | item | acceptance |
|---|---|---|
| R3.1 | R-10 / R-15: pool bounds asserted against independent expected values or behaviourally; `PROVIDER_DEADLINE_MS` asserted; `isConnectionAmbiguous` and `releaseClient` mutants; adminPool in the pool-resilience test gets a client-side timeout (R1 leftover) | weakening any bound 10× fails the suite |
| R3.2 | RT4-4: G-02 three-column JOIN gets a detector (given G-02's history, not a redundancy proof) | the key_ref-only mutant fails the suite |
| R3.3 | D-09(B): drop-tests for the 8 sole-enforcement CHECKs on the key-destruction path first, then the other 9. Register corrected: population 162, untested 17, triggers 0/56; "67" withdrawn | gate 7's tier-3 group-drop re-executed: the full suite FAILS with the 17 absent |
| R3.4 | RT4-6: G-07 unreachability proof is false (harness DB has NULL datacl). Reclassify, add the case, extend the closure-audit denominator | the NULL-datacl branch has a test that reaches it |
| R3.5 | F1, F3: K-07 fixture-precondition assertion measured in the right session; migrator ledger-completeness assertions that detect a migration silently not applying | each has a mutant that dies |
| R3.6 | SEC-E: digest `prosrc` of every SECURITY DEFINER function into the privilege map | a function-body swap fails the privilege-map test |

## R4 — Provenance

| id | item | acceptance |
|---|---|---|
| R4.1 | RT4-1: hygiene = on-disk hashes vs `git ls-tree HEAD` + `git ls-files -v` scanned for assume-unchanged/skip-worktree; boundToCommit counts untracked files (R1 leftover) | the assume-unchanged forge and an untracked-file forge both produce FAIL |
| R4.2 | Gates 1–3 are never run by the builder; the record names the running session | register rule + reviewer handoff updated |
| R4.3 | I-1 handoff claim corrected; frozen manifest extended to `scripts/`; `ci-guards.sh` unique tmp names (both remaining fixed paths); `mkenv.sh` migrates the cluster it creates | two concurrent guard runs cannot collide; manifest covers evidence-manufacturing scripts |
| R4.4 | 2×2 concurrent column (R1 leftover): five concurrent-pair runs, pristine, reported | verbatim VERDICT lines in the register |

## On completion

Tag `w13-candidate-5` at the final SHA. Write `docs/W13_R2R4_REPORT.md`: every item
with commit SHA, every premise re-executed with result, every production-code
change with its detector. Then STOP. The review side runs gates 1–3 and the seven
reviewers on candidate-5. Do not self-run any gate.
