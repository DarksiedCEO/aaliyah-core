# Aaliyah Onboarding OS (Block 4)

Goal: a non-technical user reaches first value in under 5 minutes — no terminal
commands, no OAuth tokens shown, no developer language.

## Flow (state machine)

`welcome → choose_use_case → connect_gmail → choose_mode → choose_style →
inbox_discovery → first_opportunities → complete`

Each step is enforced by `advanceOnboarding(state, action)` — an action is only
valid at its step, so a UI can drive the flow without being able to skip Gmail
connection or jump ahead.

```ts
let s = startOnboarding({ tenantId, userId });        // workspaceId backfilled
s = advanceOnboarding(s, { type: "begin" });
s = advanceOnboarding(s, { type: "set_use_case", useCase: "sales_followup" });
s = advanceOnboarding(s, { type: "connect_gmail", connected: true });
s = advanceOnboarding(s, { type: "set_mode", mode: "draft_replies" });
s = advanceOnboarding(s, { type: "set_style", style: "professional" });
s = advanceOnboarding(s, { type: "run_discovery", opportunities });
s = advanceOnboarding(s, { type: "accept_opportunities" }); // persists prefs
```

## Operating modes

| Mode | Behavior |
|---|---|
| `observe_only` | Watches; drafts nothing |
| `draft_replies` | **Default.** Drafts inbound replies, awaits approval |
| `draft_followups` | Drafts follow-ups via the frozen engine, awaits approval |
| `guarded_operator` | Broadest assistance — still stops at human approval |

**No mode enables auto-send.** Persisted preferences always carry
`autoSend: false` (a contract literal — auto-send is unrepresentable).

## Use cases

`sales_followup`, `inbox_management`, `customer_support`,
`business_development`, `personal_assistant`.

## Communication style

The chosen `communicationStyle` id (`professional` default) is recorded here;
the full style profile behind it is owned by the Style & Voice Engine (Block 5).

## Inbox discovery

`discoverOpportunities(inbox, max=3)` reuses the inbound reply-worthiness
analysis to surface the first useful threads to draft for. Read-only — it never
drafts or sends.

## Guarantees

- No OAuth token is exposed to the user — Gmail connection is a boolean signal
  here; credentials live in the credential provider, never in onboarding state.
- Preferences are stored per `(tenantId, workspaceId, userId)` and isolated.
- Onboarding never enables auto-send and never touches the frozen follow-up
  doctrine, urgency, owner routing, escalation, monitoring, or guarded execution.
