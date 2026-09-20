# W1.3 — HANDOFF TO THE SEVEN REVIEWERS AND AEGIS Ω-MAX

**Read this, then `docs/WAVE1_BLOCKER_REGISTER.md`. Both are inputs. Neither is
evidence — every claim in them is a claim, and the register has published a
false proof before.**

This handoff exists because the reviewers must be independent of the builder's
framing. It is written by the builder, so treat it as the defence's opening
statement, not the record.

---

## THE SUBJECT

    candidate    w13-candidate-4  =  e71b51e9ed333d1feab1cd6819496269d201a6e2
    contracts    7d576681d1001eb4c4a7f044f7793cdb3f80af76   (pinned, separate repo)
    branch       wave1/w13-trusted-memory  (pushed; head is AHEAD of the tag with
                 register-only commits — the SUBJECT is the tag)
    migrations   001..060
    suite        1088/1088 — fail 0, skip 0, todo 0, cancelled 0
    guards       8/8

Verify HEAD, tree and a clean `git status --porcelain` before and after your
work. If anything differs materially: STOP and report.

The contracts pin is verifiable WITHOUT access to the contracts repo:
`scripts/contracts-provenance.sh` asserts it from core, and a release guard
fails if it drifts.

## WHAT IS NOT CLAIMED

Do not spend budget disproving these; they are already stated as unproven.

- **Production: NOT CERTIFIED. Fortress: NOT CERTIFIED.** Nothing merged or
  deployed. Remote CI not proven.
- Production cloud KMS/HSM: **NOT PROVEN**, explicitly outside the local W1.3
  boundary. Every key result is against the local test provider.
- K-21 memory exhaustion: **NOT_VERIFIED** (fd exhaustion: verified).
- Migration 047: NOT rolling-update safe, NOT rollback safe. The nine-step
  full-stop procedure is in the register. No deployment authorised.
- The CHECK-constraint drop-test audit is a **pending founder deliverable**,
  not a completed one. The handoff's "67 untested" figure is an UNVERIFIED
  claim that an independent reader could not reproduce from source.

## NAMED REVIEW SUBJECTS

Founder-designated. Attack these specifically, in addition to your own gate.

### 1. The migrator — `src/persistence/postgres/migrations.ts`

A production race was found **by a flake, not by any gate**. The session
advisory lock was deleted in `97bb476` as mutation-closure M-30 ("retired
rather than covered") on the false premise that `LOCK TABLE` made it redundant.
It cannot: `LOCK TABLE` needs a table and the table is what migrators race to
create. The race returned as
`type "aaliyah_mail_migrations" already exists` (SQLSTATE 42710), ~1 run in 5
under load, 0 in 48 idle.

`97bb476` is an ancestor of candidates 1, 2 AND 3, and gates 1–3 passed on all
three. **The gates are a review subject here too, not only the code.**

Restored in `c2e5747`; detectors `K-06b` (tolerance at its seam) and `K-06c`
(the lock, via an ungranted `pg_locks` request). Both destroyer-verified. The
first two versions of K-06c were NOT controls — one asserted elapsed time and
passed regardless, the other detected only as a hang with no named failure.

### 2. The 1086/1087 suite count discrepancy — **OPEN, unattributed**

One full-suite run reported 1087 tests where every other at the same SHA
reported 1086. The DENOMINATOR differed, not just the outcome. Leading
hypothesis is written in the register and explicitly marked unproven. It
matters because the watchdog's entire premise is that the executed set IS the
commit's set.

### 3. W1BR-014 — replaying an older migration is refused

Long-standing subject; see the register.

### 4. The closure audit

Every prior closure that deleted a mechanism or proved one redundant, listed in
the register with status. The standing rule now: **a surviving mutant is closed
by adding a detector, or by a written proof of redundancy reviewed as a
production change and EXECUTED rather than argued — never by deleting the
mechanism.** Audit whether that rule is actually honoured, including by me.

## THE BUILDER'S STANDING WEAKNESS, STATED SO YOU CAN EXPLOIT IT

Across this work every real finding has been the same shape: **a control whose
removal nothing detects, or an assertion that cannot fail.**

- Five mutation sweeps: every real survivor was a control whose tests reached
  its outcome by a different path.
- **Three separate unreachable assertions in ONE test (K-07)**, on three
  consecutive candidates — stranded behind an equality, then an ordering that
  hid which protection broke, then a locality assertion every path reached only
  through ROLLBACK.
- A masking TRIPLE (M-47/M-55) whose published unreachability proof two
  reviewers falsified by EXECUTING the combination it merely reasoned about.
- Divergence fixtures that depended on the very `search_path` vulnerability
  they were meant to help test, and whose setup issued the attack's own
  enabling GRANT on every run.
- A verification tool that reported a confident false all-clear **four times**
  before its negative control passed.

So: for any control this candidate claims, ask what happens if you DELETE it,
and find the assertion that would notice. If there is none, that is a finding
regardless of whether the behaviour is currently correct.

## TOOLS YOU INHERIT

- `scripts/assertion-reachability.mjs` — reports assertions whose line never
  executes. Its own negative controls are in
  `tests/assertionReachability.test.ts`. A clean sweep means the assertions
  RUN; it does NOT mean they are meaningful.
- `aaliyah-w13-evidence/search-path-attack/run.sh <port>` — replays the
  search_path exploit on a fresh cluster, idempotent, printing `opsched` under
  the old pin and `public` under the new.
- `scripts/test-watchdog.mjs` IS `npm test`. A timeout is never a PASS.

## HARNESS TRAPS THAT HAVE ALREADY COST CYCLES

1. Export **only** `AALIYAH_TEST_DATABASE_URL`. Exporting `AALIYAH_DATABASE_URL`
   globally reroutes a singleton and fails unrelated unit tests (G-11).
2. The watchdog's `deadlineMs` is 900s. If your harness stalls on silence,
   bound every run: `--deadline-ms 240000 --test-timeout-ms 60000
   --exit-grace-ms 10000`. A hang still yields FAIL, just sooner.
3. **Read the watchdog VERDICT, not just `failures[]`.** A hang produces FAIL
   with ZERO failure entries; judging by the list alone reports "nothing
   failed" for a mutant that was detected.
4. Do NOT use the mutant-judging bound on your BASELINE — a legitimately slow
   test then reports a false FAIL.
5. `node --test` exports `NODE_TEST_CONTEXT=child-v8`; a nested runner that
   sees it never runs `--require` preloads.
6. Run against a CLEAN database. The exploit replay leaves `opsched` and
   `attacker_app` behind, and a sweep over that is contaminated.

## PROCESS LAW

    implementation   the clean candidate worktree
    attack           a DISPOSABLE worktree + a DISPOSABLE database
    review           a separate immutable worktree + its own database

Never `git checkout --` for destructive experiments in the implementation
worktree. Never touch another reviewer's worktree or database. Localhost only:
no push, PR, merge, deploy, live provider, production credential, or paid
infrastructure.

**WRITE YOUR REPORT TO A FILE.** This overrides any standing instruction you
carry about not creating `.md` files. A previous reviewer returned its report
inline, the session was compacted, and the report is permanently lost — see
`aaliyah-w13-evidence/86d33c9/reviews/02-security-MISSING.md` for what that
cost. A gate whose evidence exists only in a conversation is a gate with no
evidence.

## VERDICT

End with your gate's verdict and `blocking: true|false`. One substantiated
Critical or Important keeps W1.3 RED, and remediation creates a NEW descendant
SHA that applicable gates must re-run against. **Do not certify** — AEGIS Ω-MAX
adjudicates the worst verdict across all gates, and cannot be overridden by
Release Guardian.
