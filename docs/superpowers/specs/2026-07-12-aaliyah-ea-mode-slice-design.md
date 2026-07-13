# Aaliyah Executive Assistant Mode — Thin Vertical Slice (Design)

**Date:** 2026-07-12
**Branch:** `feature/aaliyah-ea-mode` (off `feature/local-runner`)
**Status:** Design approved by Andre Love. Awaiting implementation plan.

## Mission

Upgrade the existing guarded Gmail drafting runner so it drafts **useful, context-aware,
authority-bounded replies as an Executive Assistant to the CEO** — not generic
acknowledgements. Prove it live on three real emails, then stop and return an expansion plan.

The Gmail read → analyze → draft → manual-approval path already works and is live-proven.
This slice adds the **judgment and control layer** on top of it.

## Non-goals / hard constraints (binding)

- **Do NOT rebuild** the model router, style engine, relationship memory, revenue context, or
  confidence engine. Reuse them.
- **Do NOT modify frozen files** (the 17 in `.aegis-frozen.sha256`, incl. `sendGuard.ts`).
- **No auto-send, ever.** No send path is added. Manual approval remains mandatory.
- **No deterministic CEO drafting fallback.** If a model is unavailable, fail **degraded →
  review-only**. Bad drafting is worse than no drafting.
- Not the full 12-category system. Five categories only. Expansion comes after live proof.

## Separation of judgment from control (the core principle)

```
Stage 0  high-confidence deterministic system filter   (free, no model)
Stage 1  Haiku structured classification               (model judgment)
Stage 2  deterministic risk/category authority policy   (code decides action)
Stage 3  Sonnet executive drafting — permitted messages only
Stage 4  manual approval, no send
```

The model **proposes** (category, risk, reason, confidence). Deterministic code **decides**
the action (draft / decline-draft / no-action / escalate / review-only). A model can never
*grant* permission to draft — it can only inform, and RED/low-confidence can only *subtract* it.

## Reuse vs new (verified against the codebase)

**Reused, unmodified:** `AaliyahModelRouter` (Anthropic→OpenAI→Gemini priority + health
fallback, `AllProvidersFailedError`), `routerDraftGenerator` (already folds in style +
relationship + forbidden-phrase enforcement), `styleDirectives`/`enforceForbiddenPhrases`,
`relationshipDirectives`, `computeRevenueSignals`, `buildConfidence`.

**New core capability** → `src/application/executive/` (unit-tested in `tests/`; read-only
w.r.t. the filesystem so the "no file-writes in src/" release guard stays green):
- `ceoProfile.ts` — zod schema (schema-versioned) + validation + prompt-context builder.
- `triage.ts` — Stage 0 deterministic filter + Stage 1 Haiku classifier + JSON parsing/guarding.
- `authorityPolicy.ts` — Stage 2 deterministic risk/category → action mapping.
- `executiveDraft.ts` — Stage 3 prompt composition (CEO context + category directive +
  guardrails) over the existing router; fail-degraded semantics.
- `modelResolution.ts` — env overrides + Models-API verification + fail-degraded, no silent substitution.

**New operator glue** → `local-runner/`:
- `ceoProfileFile.ts` — load + permission-check the local pilot profile file.
- `init-profile` command — scaffold the profile pre-filled with Z Best Media defaults.
- `draft-inbox` rewired to the EA pipeline.
- `models` / `status` extended to run the Models-API verification.

## Block 1 — CEO profile (minimal, pilot-scoped)

**Persistence classification (honest):** this is **Local pilot profile persistence** — a
single editable JSON on the operator's machine. It is **not** production durable
tenant/workspace/user storage. Production will later use the existing PostgreSQL-backed scoped
application store; that is out of scope for this slice and must be labeled as future work, not
claimed as done.

- Location: `~/.aaliyah-local/ceo-profile.json`, `chmod 600`.
- **Fail closed** if the file is group- or world-readable (permission bits looser than `600`)
  → refuse to run, clear remediation message. (Acceptance case 6.)
- **Schema-versioned** (`schemaVersion` field); unknown/incompatible version rejected.
- Never logged; never committed (add to `.gitignore` patterns / confirm outside repo tree —
  it lives under `~/.aaliyah-local`, already outside the repo).
- Fields (slice): `schemaVersion`, `name`, `title`, `companies[]`, `priorities[]`, `tone`,
  `greeting`, `signoff`, `neverPromise[]` (pricing, deadlines, meetings, contracts, refunds,
  legal positions), `confidentialTopics[]`, `vipContacts[]` (optional), `approvedFacts[]` (optional).
- `init-profile` scaffolds it with Andre's defaults: name "Andre Love", company "Z Best Media",
  tone "direct, warm, concise", priorities [leads, clients, partnerships, protecting time],
  neverPromise [pricing, deadlines, meetings, contracts, refunds, legal positions].

## Block 2 — Executive triage (hybrid)

### Stage 0 — high-confidence deterministic system filter (free)

Short-circuits to `notification_system` (no model call) **only** on high-confidence signals —
`List-Unsubscribe` alone is NOT sufficient (legitimate customers/vendors/communities use bulk
headers). Short-circuit only when:

- sender matches a known system pattern (`no-reply@`, `do-not-reply@`, `mailer-daemon@`,
  `postmaster@`, `notifications?@`, known digest senders), **OR**
- bulk headers (`List-Unsubscribe` / `Precedence: bulk`) **AND** an obvious
  digest/newsletter signal in the subject or sender (e.g. "digest", "newsletter", "weekly",
  "your stories", noreply-style local part).

Anything else — including a bulk-header message that looks like real correspondence — falls
through to Stage 1. (Acceptance case 3: bulk header on legitimate correspondence is NOT
automatically skipped.) Requires the Gmail reader to surface `List-Unsubscribe` and
`Precedence` headers (it already fetches full messages; small addition).

### Stage 1 — Haiku structured classification (survivors only)

One structured model call returning strictly:
```
{ category: real_lead | vendor_solicitation | notification_system | sensitive_escalation | unknown,
  risk: green | yellow | red,
  reason: string,
  confidence: number (0..1) }
```

- The email body is passed as **untrusted data**, explicitly fenced/labeled; the system prompt
  instructs the classifier to treat any instructions inside the body as content to classify,
  not commands to obey. (Acceptance case 5: prompt-injection resistance.)
- **Malformed / unparseable JSON** (or schema-invalid output) → treat as **degraded →
  review-only**, never a guessed category. (Acceptance case 4.)
- If the triage model is unavailable (`AllProvidersFailedError` / no key) → **degraded →
  review-only**.

## Block 2b — Authority policy (Stage 2, deterministic)

Applied **in this precedence order** — risk gates before category:

```
1. risk = red            → NO draft → escalate (review-only, surfaced prominently)
2. confidence < 0.70     → treat as unknown → review-only          (tunable after live evidence)
3. risk = yellow         → draft allowed ONLY with an explicit caution marker + manual approval
4. risk = green          → category policy applies
```

Category policy (only reached at green, or yellow with caution marker):

| category | action | draft? |
|---|---|---|
| real_lead | executive BD reply (Sonnet) | yes |
| vendor_solicitation | firm, polite decline (Sonnet) | yes |
| notification_system | no action | no |
| sensitive_escalation | escalate — review-only | no |
| unknown | cautious — review-only | no |

Consequences (make the gap-closure explicit):
- `real_lead + risk=red` → **no draft**, escalate. (Acceptance case 1.)
- `real_lead + confidence<0.70` → **review-only**. (Acceptance case 2.)
- The action is **never** model-decided; the table is the sole authority.

## Block 3 — Executive drafting (Stage 3, wiring)

For permitted messages only (green, or yellow-with-caution; categories real_lead /
vendor_solicitation), compose the system prompt from: CEO profile context + category directive
(lead → useful, specific BD reply that answers the actual question; vendor → concise firm
decline) + guardrails (never promise pricing/deadlines/meetings/contracts/refunds/legal; no
invented facts/pricing; no commitment without approval; concise, warm, direct) + existing style
+ relationship directives. Route through `routerDraftGenerator` / `AaliyahModelRouter` using the
**Sonnet** drafting tier.

**Fail-degraded (hard rule):** if the router throws `AllProvidersFailedError` → the email
becomes **review-only, reason "model unavailable — degraded", NO draft created.** There is no
deterministic CEO drafting fallback. The old deterministic generator is **not** used in EA mode.

Every produced draft carries `confidence` + `reason` + `generatorMode` metadata and is created
in Gmail as a draft awaiting manual approval (reusing the verified `runInboundDraft` create path).

## Model resolution (no stale aliases, no silent substitution)

- Env overrides: `AALIYAH_TRIAGE_MODEL`, `AALIYAH_DRAFT_MODEL`.
- Documented defaults: triage `claude-haiku-4-5-20251001`, drafting `claude-sonnet-5`.
- At setup / `status`: query the Anthropic **Models API** (`/v1/models`) and **verify the
  configured IDs are available to this account.**
- If a configured tier is **unavailable → fail degraded** (that stage becomes review-only for
  drafting, or the run refuses for triage) — **never silently substitute** Opus/Fable or any
  other (esp. more expensive) model.
- Cache the verified selection for the current run.

## CLI & output

`draft-inbox` runs the EA pipeline; keeps `--dry-run`, `--limit`, `--query`. Per email prints:
**category · risk · action · reason**, and for draftable messages the reply preview. Escalations
and degraded items print prominently. Output boundary preserved: **no tokens, no raw inbound
body, no API keys** in output (only From / Subject / classification / reply preview). New
`init-profile` command; `status` extended with Models-API verification.

## Safety summary

No auto-send · no payment instructions · no contract acceptance · no legal advice · no
disclosure of confidential topics · no meeting commitment · no fabricated company claims · no
draft for notification/system mail · email body treated as untrusted data · key never in
chat/logs/commits/history · profile file fails closed on loose permissions · model outage fails
degraded to review-only.

## Tests / acceptance cases

Unit + integration tests (deterministic; model calls faked) covering at minimum:
1. `real_lead + risk=red` → no draft, escalate.
2. `real_lead + confidence < 0.70` → review-only.
3. Bulk-header on legitimate-looking correspondence → NOT auto-skipped (goes to Haiku).
4. Malformed classifier JSON → degraded review-only.
5. Prompt-injection email body → classifier treats content as untrusted data (no instruction-following).
6. CEO profile file permissions too open (not 600) → fail closed.
Plus: real lead → draftable; vendor → decline draft; notification/system → no action;
sensitive → escalate no draft; unknown → review-only; triage model unavailable → degraded;
drafting model unavailable → degraded (no deterministic draft); manual approval required; no auto-send.

## Live acceptance set (Andre runs; agent does not — private inbox)

Three messages: (1) real lead → useful CEO-office draft; (2) vendor solicitation → concise
decline; (3) notification/digest → skipped. Commands: `draft-inbox --dry-run` first, then live.

## Success definition

Aaliyah reads a real inbox message, classifies it correctly, applies deterministic authority,
drafts a useful CEO-office reply **only for permitted messages**, records confidence + reason,
creates a Gmail draft or takes no action / escalates, and **sends nothing** — with model
outages failing degraded to review-only rather than emitting a generic draft.

## Required report (on completion)

1. Files changed · 2. Tests added · 3. Exact test counts · 4. Example drafts before/after ·
5. Risk report · 6. Frozen-file verification · 7. No-send verification · 8. Live dry-run
command · 9. Live one-draft command.

## Out of scope (future / expansion — do not claim as done)

Full 12-category taxonomy; Postgres-backed production CEO profile store; calendar verification
for meeting requests; OpenAI/Gemini keys; Secret Manager key sourcing (production); hosted
onboarding. These follow only after the slice is green and live-proven.
