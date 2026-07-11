# Google Connect (Phase B2)

One Connect-Inbox product; Google is the first live-proven adapter. Sending
stays disabled — this vertical slice proves connect / read / draft / refresh /
disconnect only.

## Environment contract

The app disables Google cleanly (returns `provider_not_configured`) unless ALL
of these are set. It never presents a functional Connect button against a
half-configured backend.

```
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_OAUTH_REDIRECT_URI        # exact, must match the Google console
MAIL_CREDENTIAL_ENCRYPTION_KEY   # base64 of 32 random bytes (AES-256)
MAIL_CREDENTIAL_KEY_VERSION      # e.g. v1
AALIYAH_FRONTEND_INBOXES_URL     # e.g. https://app.example/settings/inboxes
```

## Routes

```
POST   /api/mail/connections/google/start      -> { authorizationUrl } | 503 { available:false, reasonCode }
GET    /api/mail/connections/google/callback    -> 302 <frontend>?connection=success|failed  (never leaks code/token/email)
GET    /api/mail/connections/:connectionId       -> sanitized { status: connected|needs_attention|disconnected }
POST   /api/mail/connections/:connectionId/test  -> controlled read + draft create/retrieve (NO send)
DELETE /api/mail/connections/:connectionId        -> revoke + destroy + stop jobs + invalidate approvals
```

The browser NEVER receives authorization codes (post-callback), access tokens,
refresh tokens, client secrets, or raw provider errors.

> Identity comes ONLY from a `Authorization: Bearer` credential resolved
> server-side (session store for humans, service registry for workloads);
> tenant, workspaces, and roles are resolved from the membership directory —
> `x-aaliyah-*` headers are never read (Phase B3).
>
> Mail state (Phase B4): OAuth states, connections, credentials, health,
> send approvals, reconciliation, job markers, and audit all have durable
> Postgres stores (`AALIYAH_DATABASE_URL`; server runs migrations at boot).
> Refresh tokens and PKCE verifiers rest as KMS envelopes (fresh data key
> per secret; local env master today, cloud KMS swaps the wrapper only).
> The connect vertical (oauth/connections/credentials/job markers) runs on
> this backend; without a database URL it runs on the conformance-tested
> in-memory twin — dev only, announced at boot.
>
> Send approvals (sendGuard unlock, 2026-07-10): the durable store IS the
> only approval source of truth — atomic conditional claim (fresh operation
> id persisted before any provider call), operation-id-matched settlement,
> ambiguous outcomes stay `sending` for explicit reconciliation, disconnect
> invalidates durably. The module-level store is gone. Durable audit is the
> sole production audit sink (JSONL removed): mutations fail closed when
> the audit record cannot persist; health reads continue with an
> operational error. Production startup fails closed without
> AALIYAH_DATABASE_URL. sendGuard.ts is REFROZEN — see the recorded hash in
> the B4.5 commit message.
>
> Remaining gaps, stated plainly: (1) Session store and membership
> directory are in-memory; no real IdP/login flow yet — sessions are issued
> programmatically (Phase B5). (2) Sending remains disabled: no role or
> service grant maps to mail.send.execute, and live sending awaits explicit
> authorization. (3) Adapters not live-proven until the real Google app
> registration and the 13-step live run.

## Client experience

```
Connect your inbox
[ Continue with Google ]
```
then
```
Connected
sales@pussycatalley.com
Aaliyah will prepare drafts for your approval.
[ Finish ]
```
No client-id fields, redirect URLs, scopes, or credential config.

## Live verification sequence (run once real credentials are installed)

Use a unique marker `AALIYAH_GOOGLE_SMOKE_<uuid>` for deterministic cleanup.

1. Click Continue with Google.
2. Authorize the controlled test mailbox.
3. Verify the returned mailbox identity.
4. Confirm encrypted credential persistence (ciphertext ≠ plaintext).
5. Locally invalidate the access token.
6. Prove refresh-token recovery.
7. Read one controlled test email.
8. Create one uniquely-named draft.
9. Retrieve the draft; verify recipient, subject, body.
10. Delete the test draft.
11. Disconnect.
12. Confirm token revocation and job shutdown.
13. Confirm subsequent mailbox access fails.

Only after this survives refresh, disconnect, revocation, failure-recovery, and
tenant-isolation may Google be promoted from `implemented` to live-proven.
Everything above steps 5–13 that does not require a live Google account is
already covered by the automated tests; steps needing a real token/consent are
the operator-run portion.
```
