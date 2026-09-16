import type { Pool } from "pg";

/**
 * Ordered, idempotent migrations for the durable mail state. Each entry runs
 * once, recorded in aaliyah_mail_migrations; re-running is a no-op. Every
 * tenant-owned table carries tenant_id + workspace_id and every read is
 * expected to filter on them — scoping is a query contract, not an option.
 */
const MIGRATIONS: ReadonlyArray<{ id: string; sql: string }> = [
  {
    id: "001_mail_oauth_states",
    sql: `CREATE TABLE IF NOT EXISTS mail_oauth_states (
      state_hash text PRIMARY KEY,
      provider text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      user_id text NOT NULL,
      session_id text NOT NULL,
      redirect_uri text NOT NULL,
      code_verifier_encrypted text NOT NULL,
      code_verifier_key_version text NOT NULL,
      created_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz
    )`,
  },
  {
    id: "002_mail_connections",
    sql: `CREATE TABLE IF NOT EXISTS mail_connections (
      connection_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      user_id text NOT NULL,
      provider text NOT NULL,
      email_address text NOT NULL,
      auth_kind text NOT NULL,
      status text NOT NULL,
      connected_at timestamptz NOT NULL
    )`,
  },
  {
    id: "003_mail_credentials",
    sql: `CREATE TABLE IF NOT EXISTS mail_credentials (
      connection_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      user_id text NOT NULL,
      provider text NOT NULL,
      key_id text NOT NULL,
      wrapped_data_key text NOT NULL,
      ciphertext text NOT NULL,
      granted_scopes jsonb NOT NULL DEFAULT '[]',
      connected_email text NOT NULL,
      access_token_expires_at timestamptz,
      revoked_at timestamptz
    )`,
  },
  {
    id: "004_mail_connection_health",
    sql: `CREATE TABLE IF NOT EXISTS mail_connection_health (
      connection_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      healthy boolean NOT NULL,
      detail text,
      checked_at timestamptz NOT NULL
    )`,
  },
  {
    id: "005_mail_send_approvals",
    sql: `CREATE TABLE IF NOT EXISTS mail_send_approvals (
      approval_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      connection_id text NOT NULL,
      draft_id text,
      recipient_hash text NOT NULL,
      body_hash text NOT NULL,
      approved_by_user_id text NOT NULL,
      approved_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      status text NOT NULL,
      operation_id text,
      provider_message_id text,
      updated_at timestamptz NOT NULL
    )`,
  },
  {
    id: "006_mail_reconciliation",
    sql: `CREATE TABLE IF NOT EXISTS mail_reconciliation (
      id bigserial PRIMARY KEY,
      approval_id text NOT NULL,
      operation_id text,
      checked_at timestamptz NOT NULL,
      outcome text NOT NULL,
      detail text
    )`,
  },
  {
    id: "007_mail_job_markers",
    sql: `CREATE TABLE IF NOT EXISTS mail_job_markers (
      connection_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      stopped_at timestamptz NOT NULL
    )`,
  },
  {
    id: "008_mail_audit_events",
    sql: `CREATE TABLE IF NOT EXISTS mail_audit_events (
      audit_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      connection_id text,
      actor_type text,
      actor_user_id text,
      actor_service_id text,
      action text NOT NULL,
      detail text,
      at timestamptz NOT NULL
    )`,
  },
  {
    id: "009_indexes",
    sql: `CREATE INDEX IF NOT EXISTS idx_mail_connections_scope ON mail_connections (tenant_id, workspace_id);
      CREATE INDEX IF NOT EXISTS idx_mail_send_approvals_conn ON mail_send_approvals (connection_id, status);
      CREATE INDEX IF NOT EXISTS idx_mail_send_approvals_sending ON mail_send_approvals (status, updated_at);
      CREATE INDEX IF NOT EXISTS idx_mail_audit_scope ON mail_audit_events (tenant_id, workspace_id, at);
      CREATE INDEX IF NOT EXISTS idx_mail_reconciliation_approval ON mail_reconciliation (approval_id, checked_at)`,
  },
  {
    id: "010_auth_users",
    sql: `CREATE TABLE IF NOT EXISTS auth_users (
      id text PRIMARY KEY,
      tenant_id text NOT NULL,
      external_provider text NOT NULL,
      external_subject text NOT NULL,
      email text NOT NULL,
      email_verified boolean NOT NULL,
      status text NOT NULL,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL,
      UNIQUE (external_provider, external_subject)
    )`,
  },
  {
    id: "011_workspace_memberships",
    sql: `CREATE TABLE IF NOT EXISTS workspace_memberships (
      user_id text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      role_ids jsonb NOT NULL DEFAULT '[]',
      status text NOT NULL,
      created_at timestamptz NOT NULL,
      revoked_at timestamptz,
      PRIMARY KEY (user_id, tenant_id, workspace_id)
    )`,
  },
  {
    id: "012_auth_sessions",
    sql: `CREATE TABLE IF NOT EXISTS auth_sessions (
      id text PRIMARY KEY,
      user_id text NOT NULL,
      tenant_id text NOT NULL,
      session_token_hash text NOT NULL UNIQUE,
      auth_strength text NOT NULL,
      created_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      last_seen_at timestamptz NOT NULL,
      revoked_at timestamptz
    )`,
  },
  {
    id: "013_service_identities",
    sql: `CREATE TABLE IF NOT EXISTS service_identities (
      id text PRIMARY KEY,
      tenant_id text,
      name text NOT NULL,
      permission_ids jsonb NOT NULL DEFAULT '[]',
      credential_hash text NOT NULL UNIQUE,
      status text NOT NULL,
      created_at timestamptz NOT NULL,
      rotated_at timestamptz NOT NULL
    )`,
  },
  {
    id: "014_identity_indexes",
    sql: `CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions (user_id);
      CREATE INDEX IF NOT EXISTS idx_memberships_user ON workspace_memberships (user_id, tenant_id, status)`,
  },
  {
    id: "015_service_identities_workspaces",
    sql: `ALTER TABLE service_identities
      ADD COLUMN IF NOT EXISTS workspace_ids jsonb NOT NULL DEFAULT '[]'`,
  },
  {
    // Credential lifecycle state (healthy/refreshing/degraded/
    // reauthorization_required/revoked). Existing rows predate the column;
    // 'healthy' is the safe backfill since they were written only on a
    // successful check.
    id: "016_mail_connection_health_state",
    sql: `ALTER TABLE mail_connection_health
      ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'healthy'`,
  },
  {
    // Durable home for the previously file-backed application stores that hold a
    // single latest document per key (style profiles, onboarding preferences,
    // relationship maps). `store` names the logical store; `doc_key` is its
    // per-store identity (e.g. userId). Payload is the contract-validated JSON.
    id: "017_aaliyah_documents",
    sql: `CREATE TABLE IF NOT EXISTS aaliyah_documents (
      store text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      doc_key text NOT NULL,
      payload jsonb NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (store, tenant_id, workspace_id, doc_key)
    )`,
  },
  {
    // Durable home for the previously file-backed append-only logs (decision
    // traces, draft-quality, revenue signals, observability traces, reply
    // outcomes, follow-up outcomes). Insertion order is preserved by `id`.
    id: "018_aaliyah_append_logs",
    sql: `CREATE TABLE IF NOT EXISTS aaliyah_append_logs (
      id bigserial PRIMARY KEY,
      store text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_aaliyah_append_logs_scope
      ON aaliyah_append_logs (store, tenant_id, workspace_id, id)`,
  },
  {
    // Follow-up approval reviews were already Postgres-capable via ad-hoc inline
    // DDL keyed on DATABASE_URL; fold that schema into the ordered migration
    // runner so it lives on the same durable (AALIYAH_DATABASE_URL) backend as
    // the rest of the app. Column set matches the prior inline DDL exactly.
    id: "019_aaliyah_followup_approvals",
    sql: `CREATE TABLE IF NOT EXISTS aaliyah_followup_approvals (
      id BIGSERIAL PRIMARY KEY,
      task_id TEXT NOT NULL,
      thread_id TEXT NOT NULL,
      approved BOOLEAN NOT NULL,
      edited BOOLEAN NOT NULL,
      edit_distance INT NOT NULL,
      rejection_reason TEXT,
      reviewer_id TEXT NOT NULL,
      reviewer_role TEXT,
      draft_confidence INT,
      review_source TEXT,
      category TEXT,
      live_operator_pilot BOOLEAN,
      tenant_id TEXT,
      workspace_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_aaliyah_followup_approvals_scope
      ON aaliyah_followup_approvals (tenant_id, workspace_id, created_at)`,
  },
  {
    id: "020_wave1_lifecycle_events",
    sql: `CREATE TABLE IF NOT EXISTS wave1_lifecycle_events (
      id bigserial PRIMARY KEY,
      event_id text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      task_id text NOT NULL,
      idempotency_key text NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, workspace_id, event_id)
    );
    CREATE INDEX IF NOT EXISTS idx_wave1_lifecycle_operation_tail
      ON wave1_lifecycle_events
      (tenant_id, workspace_id, task_id, idempotency_key, id DESC)`,
  },
  {
    id: "021_wave1_lifecycle_payload_binding",
    sql: `ALTER TABLE wave1_lifecycle_events
      ADD CONSTRAINT wave1_lifecycle_tenant_binding
        CHECK (payload->>'tenantId' = tenant_id),
      ADD CONSTRAINT wave1_lifecycle_workspace_binding
        CHECK (payload->>'workspaceId' = workspace_id),
      ADD CONSTRAINT wave1_lifecycle_task_binding
        CHECK (payload->>'taskId' = task_id),
      ADD CONSTRAINT wave1_lifecycle_idempotency_binding
        CHECK (payload->>'idempotencyKey' = idempotency_key),
      ADD CONSTRAINT wave1_lifecycle_event_binding
        CHECK (payload->>'eventId' = event_id)`,
  },
  {
    id: "022_wave1_lifecycle_strict_payload_binding",
    sql: `ALTER TABLE wave1_lifecycle_events
      DROP CONSTRAINT wave1_lifecycle_tenant_binding,
      DROP CONSTRAINT wave1_lifecycle_workspace_binding,
      DROP CONSTRAINT wave1_lifecycle_task_binding,
      DROP CONSTRAINT wave1_lifecycle_idempotency_binding,
      DROP CONSTRAINT wave1_lifecycle_event_binding,
      ADD CONSTRAINT wave1_lifecycle_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      ADD CONSTRAINT wave1_lifecycle_tenant_binding
        CHECK (payload->>'tenantId' IS NOT NULL AND payload->>'tenantId' = tenant_id),
      ADD CONSTRAINT wave1_lifecycle_workspace_binding
        CHECK (payload->>'workspaceId' IS NOT NULL AND payload->>'workspaceId' = workspace_id),
      ADD CONSTRAINT wave1_lifecycle_task_binding
        CHECK (payload->>'taskId' IS NOT NULL AND payload->>'taskId' = task_id),
      ADD CONSTRAINT wave1_lifecycle_idempotency_binding
        CHECK (payload->>'idempotencyKey' IS NOT NULL AND payload->>'idempotencyKey' = idempotency_key),
      ADD CONSTRAINT wave1_lifecycle_event_binding
        CHECK (payload->>'eventId' IS NOT NULL AND payload->>'eventId' = event_id)`,
  },
  // ---------------------------------------------------------------------
  // Wave 1.3 TRUSTED MEMORY (contracts: aaliyah.trusted-memory/v1).
  //
  // Contracts defines the VOCABULARY and deliberately proves none of
  // atomicity, persistence, uniqueness, compare-and-swap, nonce consumption
  // or read-back. Those live here and in
  // src/persistence/postgres/wave1TrustedMemoryStore.ts.
  //
  // Four tables, and the split between them is the security design, not
  // tidiness:
  //
  //   memory_record_versions        append-only version chain, head by id DESC
  //   memory_authorization_receipts the full receipt, payload in jsonb
  //   memory_authorization_nonces   the CONSUMABLE token, scalar columns only
  //   memory_mutation_receipts      append-only outcome log
  //
  // WHY THE NONCE IS NOT A COLUMN ON THE RECEIPT ROW (contracts header,
  // "THE DIGEST IS UNKEYED"). `canonicalDigest` is an UNKEYED SHA-256: it
  // binds fields together, it authenticates nobody. If the receipt payload
  // and its binding digest live in one row, whoever can write that row
  // rewrites both and every structural check still passes. So the token that
  // is actually spent lives in memory_authorization_nonces, which has NO
  // jsonb payload and NO self-describing blob at all — only scalar columns
  // and UNIQUE (tenant_id, binding_digest). Consumption is one
  // `UPDATE ... WHERE consumed_at IS NULL` against THAT table, and the store
  // additionally requires the nonce row and the receipt row to AGREE on
  // authorization, action, target and validity before it spends anything.
  // Rewriting one table is therefore not enough.
  //
  // WHAT THIS DOES NOT SOLVE, STATED PLAINLY: this is integrity through
  // separation, not authenticity. A writer with write access to BOTH tables,
  // or any superuser, can still forge a consistent pair. Closing that needs
  // a KEYED construction (issuer signature / HMAC with the key in a KMS or
  // HSM, outside the database) verified before a receipt is honoured. That
  // primitive is not in this package, is not built here, and is not claimed
  // by anything in this file.
  {
    id: "023_memory_record_versions",
    sql: `CREATE TABLE IF NOT EXISTS memory_record_versions (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      record_id text NOT NULL,
      version integer NOT NULL,
      state text NOT NULL,
      content_digest text NOT NULL,
      predecessor_digest text,
      authorization_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, workspace_id, record_id, version),
      CONSTRAINT memory_record_versions_state_domain
        CHECK (state IN ('active', 'deleted')),
      CONSTRAINT memory_record_versions_version_positive
        CHECK (version >= 1),
      CONSTRAINT memory_record_versions_genesis_predecessor
        CHECK ((version = 1) = (predecessor_digest IS NULL)),
      CONSTRAINT memory_record_versions_content_digest_form
        CHECK (content_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_record_versions_predecessor_digest_form
        CHECK (predecessor_digest IS NULL
               OR predecessor_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_record_versions_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_record_versions_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_record_versions_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_record_versions_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_record_versions_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_record_versions_record_binding
        CHECK (payload->>'recordId' IS NOT NULL
               AND payload->>'recordId' = record_id),
      CONSTRAINT memory_record_versions_version_binding
        CHECK (payload->>'version' IS NOT NULL
               AND payload->>'version' = version::text),
      CONSTRAINT memory_record_versions_state_binding
        CHECK (payload->>'state' IS NOT NULL
               AND payload->>'state' = state),
      CONSTRAINT memory_record_versions_content_digest_binding
        CHECK (payload->>'contentDigest' IS NOT NULL
               AND payload->>'contentDigest' = content_digest),
      CONSTRAINT memory_record_versions_predecessor_digest_binding
        CHECK ((payload->>'predecessorDigest')
               IS NOT DISTINCT FROM predecessor_digest),
      CONSTRAINT memory_record_versions_authorization_binding
        CHECK (payload->>'authorizationId' IS NOT NULL
               AND payload->>'authorizationId' = authorization_id),
      CONSTRAINT memory_record_versions_mutation_receipt_binding
        CHECK (payload->>'mutationReceiptId' IS NOT NULL
               AND payload->>'mutationReceiptId' = mutation_receipt_id)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_record_versions_head
      ON memory_record_versions (tenant_id, workspace_id, record_id, id DESC)`,
  },
  {
    // The receipt as contracts defines it. `consumed_at` is here for the
    // receipt's own bookkeeping and for cheap pre-checks; it is NOT the
    // authority on single use. memory_authorization_nonces is.
    //
    // TWO uniqueness constraints on purpose. The tenant-scoped one follows
    // the convention every other table here uses. The GLOBAL one exists
    // because the store resolves an authorization by id ALONE and then
    // compares all four scope dimensions against the authenticated actor in
    // application code. Filtering the lookup by tenant would make the
    // tenant check unfalsifiable — deleting it would change nothing, so no
    // test could kill it. A globally unique CSPRNG id lets each of the four
    // scope comparisons be an independently killable control.
    id: "024_memory_authorization_receipts",
    sql: `CREATE TABLE IF NOT EXISTS memory_authorization_receipts (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      authorization_id text NOT NULL,
      action text NOT NULL,
      target_record_id text NOT NULL,
      binding_digest text NOT NULL,
      issued_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz,
      consumed_at timestamptz,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, workspace_id, authorization_id),
      CONSTRAINT memory_authorization_receipts_global_id
        UNIQUE (authorization_id),
      CONSTRAINT memory_authorization_receipts_binding_digest_form
        CHECK (binding_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_authorization_receipts_window
        CHECK (expires_at > issued_at),
      CONSTRAINT memory_authorization_receipts_max_validity
        CHECK (expires_at <= issued_at + interval '24 hours'),
      CONSTRAINT memory_authorization_receipts_revoked_after_issue
        CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
      CONSTRAINT memory_authorization_receipts_consumed_after_issue
        CHECK (consumed_at IS NULL OR consumed_at >= issued_at),
      CONSTRAINT memory_authorization_receipts_not_both
        CHECK (NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)),
      CONSTRAINT memory_authorization_receipts_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_authorization_receipts_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_authorization_receipts_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_authorization_receipts_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_authorization_receipts_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_authorization_receipts_authorization_binding
        CHECK (payload->>'authorizationId' IS NOT NULL
               AND payload->>'authorizationId' = authorization_id),
      CONSTRAINT memory_authorization_receipts_action_binding
        CHECK (payload->>'action' IS NOT NULL
               AND payload->>'action' = action),
      CONSTRAINT memory_authorization_receipts_target_binding
        CHECK (payload->>'targetRecordId' IS NOT NULL
               AND payload->>'targetRecordId' = target_record_id),
      CONSTRAINT memory_authorization_receipts_nonce_binding
        CHECK (payload->'nonce'->>'bindingDigest' IS NOT NULL
               AND payload->'nonce'->>'bindingDigest' = binding_digest)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_authorization_receipts_scope
      ON memory_authorization_receipts
      (tenant_id, workspace_id, target_record_id, id DESC)`,
  },
  {
    // THE CONSUMABLE TOKEN, OUT OF BAND.
    //
    // No jsonb. No payload. No digest OF this row. Only scalar columns and
    // UNIQUE (tenant_id, binding_digest), exactly as the contracts module
    // header requires. Recomputing the binding digest from the receipt row
    // would be no defence at all, because both sides of that comparison come
    // from the row under attack; this table is a SECOND place that has to be
    // rewritten consistently, under a different privilege (see 029).
    //
    // `consumed_by_mutation_receipt_id` is a witness: a consumed nonce names
    // the mutation that spent it, and the CHECK below makes "consumed with
    // no spender" unrepresentable.
    id: "025_memory_authorization_nonces",
    sql: `CREATE TABLE IF NOT EXISTS memory_authorization_nonces (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      binding_digest text NOT NULL,
      authorization_id text NOT NULL,
      action text NOT NULL,
      target_record_id text NOT NULL,
      issued_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz,
      consumed_at timestamptz,
      consumed_by_mutation_receipt_id text,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_authorization_nonces_unique
        UNIQUE (tenant_id, binding_digest),
      CONSTRAINT memory_authorization_nonces_authorization_unique
        UNIQUE (authorization_id),
      CONSTRAINT memory_authorization_nonces_digest_form
        CHECK (binding_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_authorization_nonces_window
        CHECK (expires_at > issued_at),
      CONSTRAINT memory_authorization_nonces_max_validity
        CHECK (expires_at <= issued_at + interval '24 hours'),
      CONSTRAINT memory_authorization_nonces_consumption_witness
        CHECK ((consumed_at IS NULL) = (consumed_by_mutation_receipt_id IS NULL)),
      CONSTRAINT memory_authorization_nonces_not_both
        CHECK (NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS idx_memory_authorization_nonces_unspent
      ON memory_authorization_nonces (tenant_id, binding_digest)
      WHERE consumed_at IS NULL`,
  },
  {
    // APPEND-ONLY OUTCOME LOG.
    //
    // Two rows per mutation, and that is the fail-closed design, not an
    // accident. The `pending` row is written INSIDE the mutation transaction
    // and always carries UNKNOWN_PENDING_RECONCILIATION; the `terminal` row
    // is appended only AFTER an independent post-commit read-back has said
    // what actually happened. A process that dies between the two leaves
    // UNKNOWN durably on disk. Success is never the default and never the
    // residue of a crash.
    id: "026_memory_mutation_receipts",
    sql: `CREATE TABLE IF NOT EXISTS memory_mutation_receipts (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      phase text NOT NULL,
      authorization_id text NOT NULL,
      consumed_nonce_digest text NOT NULL,
      action text NOT NULL,
      target_record_id text NOT NULL,
      outcome_status text NOT NULL,
      emitted_at timestamptz NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, workspace_id, mutation_receipt_id, phase),
      CONSTRAINT memory_mutation_receipts_phase_domain
        CHECK (phase IN ('pending', 'terminal')),
      CONSTRAINT memory_mutation_receipts_outcome_domain
        CHECK (outcome_status IN (
          'COMMITTED_AND_READ_BACK',
          'COMMITTED_READ_BACK_DIVERGED',
          'UNKNOWN_PENDING_RECONCILIATION',
          'ABORTED_NO_MUTATION')),
      CONSTRAINT memory_mutation_receipts_pending_is_unknown
        CHECK (phase <> 'pending'
               OR outcome_status = 'UNKNOWN_PENDING_RECONCILIATION'),
      CONSTRAINT memory_mutation_receipts_nonce_digest_form
        CHECK (consumed_nonce_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_mutation_receipts_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_mutation_receipts_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_mutation_receipts_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_mutation_receipts_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_mutation_receipts_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_mutation_receipts_id_binding
        CHECK (payload->>'mutationReceiptId' IS NOT NULL
               AND payload->>'mutationReceiptId' = mutation_receipt_id),
      CONSTRAINT memory_mutation_receipts_authorization_binding
        CHECK (payload->>'authorizationId' IS NOT NULL
               AND payload->>'authorizationId' = authorization_id),
      CONSTRAINT memory_mutation_receipts_nonce_binding
        CHECK (payload->>'consumedNonceDigest' IS NOT NULL
               AND payload->>'consumedNonceDigest' = consumed_nonce_digest),
      CONSTRAINT memory_mutation_receipts_action_binding
        CHECK (payload->>'action' IS NOT NULL
               AND payload->>'action' = action),
      CONSTRAINT memory_mutation_receipts_target_binding
        CHECK (payload->>'targetRecordId' IS NOT NULL
               AND payload->>'targetRecordId' = target_record_id),
      CONSTRAINT memory_mutation_receipts_outcome_binding
        CHECK (payload->'outcome'->>'status' IS NOT NULL
               AND payload->'outcome'->>'status' = outcome_status)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_mutation_receipts_target
      ON memory_mutation_receipts
      (tenant_id, workspace_id, target_record_id, id DESC)`,
  },
  {
    // W1BR-006 — THE NUMERIC RESIDUAL, CLOSED IN THE DATABASE.
    //
    // Verified against this exact PostgreSQL 16 instance: jsonb stores
    // 9007199254740993 and 0.1000000000000000000001 EXACTLY, because jsonb
    // numbers are `numeric` with arbitrary precision. Node's JSON.parse
    // collapses both to IEEE-754 doubles, so 0.1 and
    // 0.1000000000000000000001 arrive in JavaScript as the same double and
    // `canonicalDigest` produces the SAME digest for two different stored
    // values. The contracts digest rejects unsafe INTEGERS; it does not and
    // cannot reject the FRACTIONAL class, because 0.1 is a perfectly
    // ordinary double.
    //
    // The instruction was that Core must be the only writer on the receipt
    // path AND that the exclusivity be enforced rather than assumed.
    // Migration 029 enforces WHO may write. This one enforces WHAT may be
    // written, by ANY writer, including one that has defeated 029: every
    // jsonb number anywhere in these payloads must be an integer in its
    // exact stored text form and within the IEEE-754 safe integer range.
    // A trigger is not application code — it holds for psql, for a rogue
    // service, for a migration, and for a writer that never imports this
    // package.
    //
    // Consequence, stated so nobody discovers it by surprise: memory content
    // on this path may not contain non-integer JSON numbers. `2.0` is
    // rejected too, because Postgres stores the text `2.0` while Node would
    // render `2`, and a digest taken over the round-tripped value would not
    // describe what is on disk. Decimal data belongs in a string.
    //
    // NOT SOLVED: a superuser can drop this trigger. Nothing inside the
    // database defends against the database's owner.
    id: "027_memory_exact_numeric_domain",
    sql: `CREATE OR REPLACE FUNCTION aaliyah_memory_jsonb_numbers(doc jsonb)
      RETURNS SETOF text
      LANGUAGE sql
      IMMUTABLE
      AS $fn$
        WITH RECURSIVE walk(node) AS (
          SELECT doc
          UNION ALL
          SELECT child.value
          FROM walk
          CROSS JOIN LATERAL (
            SELECT value FROM jsonb_array_elements(
              CASE WHEN jsonb_typeof(walk.node) = 'array'
                   THEN walk.node ELSE '[]'::jsonb END)
            UNION ALL
            SELECT value FROM jsonb_each(
              CASE WHEN jsonb_typeof(walk.node) = 'object'
                   THEN walk.node ELSE '{}'::jsonb END)
          ) AS child(value)
        )
        SELECT node #>> '{}' FROM walk WHERE jsonb_typeof(node) = 'number';
      $fn$;
    CREATE OR REPLACE FUNCTION aaliyah_memory_reject_inexact_numbers()
      RETURNS trigger
      LANGUAGE plpgsql
      AS $fn$
      DECLARE
        offending text;
      BEGIN
        SELECT n INTO offending
        FROM aaliyah_memory_jsonb_numbers(NEW.payload) AS t(n)
        WHERE n !~ '^-?(0|[1-9][0-9]*)$'
           OR abs(n::numeric) > 9007199254740991
        LIMIT 1;
        IF offending IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: jsonb number % is outside the exact numeric domain'
            , offending
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_exact_numbers
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_record_versions
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_reject_inexact_numbers();
    DROP TRIGGER IF EXISTS memory_authorization_receipts_exact_numbers
      ON memory_authorization_receipts;
    CREATE TRIGGER memory_authorization_receipts_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_authorization_receipts
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_reject_inexact_numbers();
    DROP TRIGGER IF EXISTS memory_mutation_receipts_exact_numbers
      ON memory_mutation_receipts;
    CREATE TRIGGER memory_mutation_receipts_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_mutation_receipts
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_reject_inexact_numbers()`,
  },
  {
    // APPEND-ONLY, ENFORCED.
    //
    // A version chain that can be rewritten in place is not a version chain,
    // and a mutation receipt that can be edited after the fact is not
    // evidence. UPDATE and DELETE are refused by the database for both
    // tables. TRUNCATE is deliberately NOT covered: test fixtures reset
    // these tables, and a TRUNCATE is visible and total, unlike a silent
    // single-row rewrite.
    id: "028_memory_append_only",
    sql: `CREATE OR REPLACE FUNCTION aaliyah_memory_forbid_row_rewrite()
      RETURNS trigger
      LANGUAGE plpgsql
      AS $fn$
      BEGIN
        RAISE EXCEPTION
          'aaliyah memory: % on % is forbidden; this table is append-only'
          , TG_OP, TG_TABLE_NAME
          USING ERRCODE = 'check_violation';
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_append_only
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_append_only
      BEFORE UPDATE OR DELETE ON memory_record_versions
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_mutation_receipts_append_only
      ON memory_mutation_receipts;
    CREATE TRIGGER memory_mutation_receipts_append_only
      BEFORE UPDATE OR DELETE ON memory_mutation_receipts
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite()`,
  },
  {
    // PRIVILEGE SEPARATION (contracts header, item 2).
    //
    // "Core is the only writer" is worth nothing while every connection is
    // the table owner. Three NOLOGIN roles, and the store runs its
    // transactions under the first via SET LOCAL ROLE:
    //
    //   aaliyah_memory_mutator  may SELECT everything on this path, INSERT
    //                           record versions and mutation receipts, and
    //                           UPDATE exactly two columns of the nonce
    //                           table (consumed_at and its witness) plus
    //                           consumed_at on the receipt. It CANNOT issue
    //                           an authorization, CANNOT mint a nonce,
    //                           CANNOT un-revoke one, CANNOT move an expiry,
    //                           and CANNOT touch a binding digest.
    //   aaliyah_memory_issuer   may INSERT authorizations and nonces and
    //                           nothing else. It cannot consume or revoke.
    //   aaliyah_memory_revoker  may UPDATE revoked_at and nothing else.
    //
    // Column-level UPDATE grants are what make this real: the mutator
    // physically cannot write expires_at or binding_digest, so the row it
    // checks is not a row it can author.
    //
    // HONEST LIMIT: roles are cluster objects and this migration needs the
    // privilege to create them. It fails loudly rather than skipping,
    // because a silently-skipped privilege boundary is the failure mode this
    // whole file exists to avoid.
    id: "029_memory_privilege_separation",
    sql: `DO $do$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_mutator') THEN
          CREATE ROLE aaliyah_memory_mutator NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_issuer') THEN
          CREATE ROLE aaliyah_memory_issuer NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_revoker') THEN
          CREATE ROLE aaliyah_memory_revoker NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_reader') THEN
          CREATE ROLE aaliyah_memory_reader NOLOGIN;
        END IF;
      END
      $do$;
    GRANT SELECT ON
      memory_record_versions,
      memory_authorization_receipts,
      memory_authorization_nonces,
      memory_mutation_receipts
      TO aaliyah_memory_mutator, aaliyah_memory_reader,
         aaliyah_memory_issuer, aaliyah_memory_revoker;
    GRANT INSERT ON memory_record_versions, memory_mutation_receipts
      TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE
      memory_record_versions_id_seq, memory_mutation_receipts_id_seq
      TO aaliyah_memory_mutator;
    GRANT UPDATE (consumed_at, consumed_by_mutation_receipt_id)
      ON memory_authorization_nonces TO aaliyah_memory_mutator;
    GRANT UPDATE (consumed_at)
      ON memory_authorization_receipts TO aaliyah_memory_mutator;
    GRANT INSERT ON memory_authorization_receipts, memory_authorization_nonces
      TO aaliyah_memory_issuer;
    GRANT USAGE, SELECT ON SEQUENCE
      memory_authorization_receipts_id_seq, memory_authorization_nonces_id_seq
      TO aaliyah_memory_issuer;
    GRANT UPDATE (revoked_at)
      ON memory_authorization_receipts, memory_authorization_nonces
      TO aaliyah_memory_revoker`,
  },
  {
    // W1.3 PART D — THE CROSS-WORKSPACE POLICY, AS A TABLE.
    //
    // "Explicit, not implicit" has to be enforced by something. This table is
    // that something: a tenant with no row here cannot bind an alias, because
    // `memory_alias_bindings` carries a FOREIGN KEY onto (tenant_id,
    // cross_workspace_policy). There is no default value, no fallback branch
    // and no ON DELETE SET DEFAULT; absence is refusal, in the database,
    // for every writer.
    //
    // PRIMARY KEY (tenant_id) is what makes the policy SINGULAR: one tenant
    // cannot hold two policies, so two binding rows of one tenant cannot
    // disagree about whether workspaces share an alias space. The extra
    // UNIQUE (tenant_id, cross_workspace_policy) exists solely so the binding
    // table's composite foreign key has something to point at; it also means
    // changing a tenant's policy while bindings exist is refused by the
    // foreign key rather than silently re-scoping every existing alias.
    id: "030_memory_alias_tenant_policy",
    sql: `CREATE TABLE IF NOT EXISTS memory_alias_tenant_policy (
      tenant_id text PRIMARY KEY,
      cross_workspace_policy text NOT NULL,
      set_by_actor_id text NOT NULL,
      policy_version text NOT NULL,
      set_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_alias_tenant_policy_domain
        CHECK (cross_workspace_policy IN
               ('workspace_isolated', 'tenant_exclusive')),
      CONSTRAINT memory_alias_tenant_policy_fk_target
        UNIQUE (tenant_id, cross_workspace_policy)
    );
    CREATE TABLE IF NOT EXISTS memory_alias_protected_domains (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      registrable_domain text NOT NULL,
      corpus_ref text NOT NULL,
      added_by_actor_id text NOT NULL,
      added_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_alias_protected_domains_unique
        UNIQUE (tenant_id, workspace_id, registrable_domain),
      CONSTRAINT memory_alias_protected_domains_host_form
        CHECK (registrable_domain ~
               '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$')
    );
    CREATE INDEX IF NOT EXISTS idx_memory_alias_protected_domains_scope
      ON memory_alias_protected_domains (tenant_id, workspace_id, id DESC)`,
  },
  {
    // THE ALIAS REGISTRY ITSELF.
    //
    // GLOBAL UNIQUENESS IS THE WHOLE POINT. The contracts header says it
    // plainly: a per-record validator sees one value at one instant and can
    // never speak for the population, so uniqueness "is a UNIQUE constraint in
    // Core's database". There are TWO here, and they are PARTIAL:
    //
    //   memory_alias_bindings_alias_unique     (tenant_id, scope_key,
    //                                           normalized_alias)
    //   memory_alias_bindings_skeleton_unique  (tenant_id, scope_key,
    //                                           skeleton)
    //
    // both `WHERE removed_at IS NULL`, so a retired binding neither blocks a
    // reassignment nor disappears from the audit trail. The skeleton index is
    // the one that stops two VISUALLY CONFUSABLE aliases from both binding:
    // NFC does not fold Cyrillic onto Latin and neither does NFKC, so the
    // normalized-alias index accepts both spellings happily and only a
    // skeleton can separate them.
    //
    // SCOPE_KEY IS DERIVED BY A CHECK, NOT BY THE APPLICATION. Under
    // `tenant_exclusive` every row of a tenant carries the sentinel '*', so
    // the indexes above become tenant-wide; under `workspace_isolated` the row
    // carries its own workspace_id and they are per-workspace. The CHECK makes
    // a row that lies about its scope_key unrepresentable, and the foreign key
    // onto memory_alias_tenant_policy makes a row that lies about the policy
    // unrepresentable too. A writer that has defeated the application still
    // cannot write a binding that escapes the tenant's declared policy.
    //
    // The '*' sentinel cannot collide with a real workspace: MemoryIdSchema
    // admits only [a-z0-9][a-z0-9._:-]{2,127}, and the CHECK below refuses a
    // workspace literally named '*' anyway.
    id: "031_memory_alias_bindings",
    sql: `CREATE TABLE IF NOT EXISTS memory_alias_bindings (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      cross_workspace_policy text NOT NULL,
      scope_key text NOT NULL,
      alias_id text NOT NULL,
      normalized_alias text NOT NULL,
      skeleton text NOT NULL,
      skeleton_algorithm text NOT NULL,
      normalization_profile text NOT NULL,
      canonical_participant_id text NOT NULL,
      registrable_domain text NOT NULL,
      script_code text NOT NULL,
      restriction_level text NOT NULL,
      subject_participant_id text NOT NULL,
      source_evidence_ref text NOT NULL,
      source_evidence_digest text NOT NULL,
      observed_at timestamptz NOT NULL,
      fresh_until timestamptz NOT NULL,
      authorization_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      bound_at timestamptz NOT NULL,
      removed_at timestamptz,
      removed_by_mutation_receipt_id text,
      removed_authorization_id text,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_alias_bindings_policy_fk
        FOREIGN KEY (tenant_id, cross_workspace_policy)
        REFERENCES memory_alias_tenant_policy (tenant_id, cross_workspace_policy),
      CONSTRAINT memory_alias_bindings_workspace_not_sentinel
        CHECK (workspace_id <> '*'),
      CONSTRAINT memory_alias_bindings_scope_key_derivation
        CHECK (scope_key = CASE
                 WHEN cross_workspace_policy = 'tenant_exclusive' THEN '*'
                 ELSE workspace_id END),
      CONSTRAINT memory_alias_bindings_evidence_digest_form
        CHECK (source_evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_alias_bindings_freshness_window
        CHECK (fresh_until > observed_at),
      CONSTRAINT memory_alias_bindings_removal_witness
        CHECK ((removed_at IS NULL) = (removed_by_mutation_receipt_id IS NULL)
               AND (removed_at IS NULL) = (removed_authorization_id IS NULL)),
      CONSTRAINT memory_alias_bindings_removal_after_binding
        CHECK (removed_at IS NULL OR removed_at >= bound_at),
      -- REDUNDANT BACKSTOP, disclosed as one. PostgreSQL evaluates CHECK
      -- constraints in NAME order, and every payload-binding CHECK below
      -- sorts earlier and also fails on a non-object payload (the JSON
      -- dereference is NULL). This constraint can therefore never be the
      -- reported violation and no test can name it. It is kept because a
      -- payload field added later without its own binding CHECK would have
      -- nothing else standing behind it.
      CONSTRAINT memory_alias_bindings_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_alias_bindings_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_alias_bindings_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_alias_bindings_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_alias_bindings_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_alias_bindings_alias_id_binding
        CHECK (payload->>'aliasId' IS NOT NULL
               AND payload->>'aliasId' = alias_id),
      CONSTRAINT memory_alias_bindings_normalized_binding
        CHECK (payload->>'normalizedAlias' IS NOT NULL
               AND payload->>'normalizedAlias' = normalized_alias),
      CONSTRAINT memory_alias_bindings_skeleton_binding
        CHECK (payload->>'skeleton' IS NOT NULL
               AND payload->>'skeleton' = skeleton),
      CONSTRAINT memory_alias_bindings_participant_binding
        CHECK (payload->>'canonicalParticipantId' IS NOT NULL
               AND payload->>'canonicalParticipantId' = canonical_participant_id),
      CONSTRAINT memory_alias_bindings_subject_binding
        CHECK (payload->>'subjectParticipantId' IS NOT NULL
               AND payload->>'subjectParticipantId' = subject_participant_id),
      CONSTRAINT memory_alias_bindings_policy_binding
        CHECK (payload->>'crossWorkspacePolicy' IS NOT NULL
               AND payload->>'crossWorkspacePolicy' = cross_workspace_policy),
      CONSTRAINT memory_alias_bindings_scope_key_binding
        CHECK (payload->>'scopeKey' IS NOT NULL
               AND payload->>'scopeKey' = scope_key),
      CONSTRAINT memory_alias_bindings_authorization_binding
        CHECK (payload->>'authorizationId' IS NOT NULL
               AND payload->>'authorizationId' = authorization_id),
      CONSTRAINT memory_alias_bindings_mutation_receipt_binding
        CHECK (payload->>'mutationReceiptId' IS NOT NULL
               AND payload->>'mutationReceiptId' = mutation_receipt_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_bindings_alias_unique
      ON memory_alias_bindings (tenant_id, scope_key, normalized_alias)
      WHERE removed_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_bindings_skeleton_unique
      ON memory_alias_bindings (tenant_id, scope_key, skeleton)
      WHERE removed_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_bindings_alias_id_unique
      ON memory_alias_bindings (tenant_id, scope_key, alias_id)
      WHERE removed_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_memory_alias_bindings_participant
      ON memory_alias_bindings
      (tenant_id, workspace_id, canonical_participant_id, id DESC);
    CREATE OR REPLACE FUNCTION aaliyah_alias_binding_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      AS $fn$
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah alias registry: DELETE on % is forbidden; a binding is retired, never erased'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.removed_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: a retired alias binding is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.removed_at IS NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement is the only permitted update'
            USING ERRCODE = 'check_violation';
        END IF;
        IF (to_jsonb(NEW) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id')
           IS DISTINCT FROM
           (to_jsonb(OLD) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id') THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement may not rewrite a binding'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_retire_only
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_retire_only
      BEFORE UPDATE OR DELETE ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION aaliyah_alias_binding_guard();
    DROP TRIGGER IF EXISTS memory_alias_bindings_exact_numbers
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_reject_inexact_numbers()`,
  },
  {
    // PRIVILEGE SEPARATION FOR THE ALIAS PATH, continuing 029.
    //
    // The mutator may bind and retire. It may NOT set a tenant's
    // cross-workspace policy and it may NOT add or drop a protected domain:
    // both of those change what the gates MEAN, and a role that can weaken its
    // own gate has no gate. Those two tables are administrative and are held by
    // the owner. The mutator's UPDATE grant on the binding table is
    // COLUMN-LEVEL and covers only the three retirement columns, so it
    // physically cannot rewrite a normalized alias, a skeleton, a participant
    // or a scope key — and the retire-only trigger refuses the rest for every
    // writer, including one that has more grants than this.
    id: "032_memory_alias_privileges",
    sql: `GRANT SELECT ON
      memory_alias_bindings,
      memory_alias_tenant_policy,
      memory_alias_protected_domains
      TO aaliyah_memory_mutator, aaliyah_memory_reader,
         aaliyah_memory_issuer, aaliyah_memory_revoker;
    GRANT INSERT ON memory_alias_bindings TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE memory_alias_bindings_id_seq
      TO aaliyah_memory_mutator;
    GRANT UPDATE (removed_at, removed_by_mutation_receipt_id,
                  removed_authorization_id)
      ON memory_alias_bindings TO aaliyah_memory_mutator`,
  },
  {
    // W1.3 PART B2, M-1 AND M-4 — NAME RESOLUTION AND MESSAGE HYGIENE.
    //
    // TWO DEFECTS, BOTH PROVEN AGAINST A LIVE DATABASE, BOTH CLOSED HERE.
    //
    // 1. SEARCH-PATH SHADOWING. Migration 027 claimed its trigger "holds for
    //    psql, for a rogue service, for a migration, and for a writer that
    //    never imports this package". It did not. The trigger function called
    //    `aaliyah_memory_jsonb_numbers()` UNQUALIFIED, was not SECURITY
    //    DEFINER, and carried no pinned `search_path`, so name resolution
    //    happened in the CALLER's search_path. A non-superuser with CREATE on
    //    a schema of its own declared a stub of that name, put the schema
    //    first on its search_path, and stored
    //    `{"balance":0.1000000000000000000001}` — the exact W1BR-006 value the
    //    trigger exists to refuse. Every internal call is now schema-qualified
    //    AND every function on this path pins `search_path`, so the resolution
    //    a caller controls is no longer the resolution the trigger uses.
    //
    // 2. RECORD CONTENT IN THE SERVER LOG. The rejection interpolated the
    //    OFFENDING VALUE into its message: a real mutation carrying
    //    `{"coPayAmount": 4211.37}` put `4211.37` verbatim into the
    //    PostgreSQL server log, where it is readable by anyone with the log
    //    and is retained by whatever ships it. `TRUNCATED_MEMORY_REJECTIONS`
    //    is a CLOSED enum precisely so a rejection can never carry record
    //    content; a RAISE that interpolates the value walks around it. The
    //    value is gone from the message. The class is still named, the
    //    ERRCODE is unchanged, and the phrase every caller matches on
    //    ("outside the exact numeric domain") is preserved.
    //
    // WHAT THIS STILL DOES NOT SOLVE: a superuser can replace these functions
    // or drop the triggers. Nothing inside the database defends against the
    // database's owner.
    id: "033_memory_trigger_name_resolution",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_jsonb_numbers(doc jsonb)
      RETURNS SETOF text
      LANGUAGE sql
      IMMUTABLE
      SET search_path = pg_catalog, public
      AS $fn$
        WITH RECURSIVE walk(node) AS (
          SELECT doc
          UNION ALL
          SELECT child.value
          FROM walk
          CROSS JOIN LATERAL (
            SELECT value FROM pg_catalog.jsonb_array_elements(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'array'
                   THEN walk.node ELSE '[]'::jsonb END)
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_each(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'object'
                   THEN walk.node ELSE '{}'::jsonb END)
          ) AS child(value)
        )
        SELECT node #>> '{}' FROM walk
         WHERE pg_catalog.jsonb_typeof(node) = 'number';
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_reject_inexact_numbers()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        offending text;
      BEGIN
        SELECT n INTO offending
        FROM public.aaliyah_memory_jsonb_numbers(NEW.payload) AS t(n)
        WHERE n !~ '^-?(0|[1-9][0-9]*)$'
           OR pg_catalog.abs(n::numeric) > 9007199254740991
        LIMIT 1;
        IF offending IS NOT NULL THEN
          -- The VALUE is deliberately absent. A rejection on this path may
          -- name the class and must never carry the record.
          RAISE EXCEPTION
            'aaliyah memory: a jsonb number in this payload is outside the exact numeric domain'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_forbid_row_rewrite()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        RAISE EXCEPTION
          'aaliyah memory: % on % is forbidden; this table is append-only'
          , TG_OP, TG_TABLE_NAME
          USING ERRCODE = 'check_violation';
      END;
      $fn$`,
  },
  {
    // W1.3 PART B2, H-1 AND H-2 — WHAT MAY BE APPENDED, NOT ONLY WHO MAY
    // APPEND IT.
    //
    // THE ROOT CAUSE, STATED ONCE. Migration 029 constrains WHO may rewrite
    // history and WHO may mint authorizations. It places NO constraint on WHAT
    // MAY BE APPENDED. Every integrity property — the authorization exists, it
    // was consumed, the predecessor links, version = head + 1, the owner does
    // not change mid-chain — lived only in TypeScript in `mutate()` and bound
    // only writes that went through it. Executed as the LEAST-PRIVILEGE
    // mutator role, against a live database:
    //
    //   * a record version naming `auth-does-not-exist-00000000` was ACCEPTED
    //     (no foreign key existed and no trigger tied a version to a consumed
    //     nonce);
    //   * a TERMINAL `COMMITTED_AND_READ_BACK` receipt — the system's only
    //     success signal — was minted for an authorization that did not exist;
    //   * v99 then v5 were appended onto a chain at v4, and because the head
    //     query orders by surrogate id, v5 became the head and carried a
    //     predecessor digest from the genesis row.
    //
    // These triggers are the enforcement point. They bind every writer,
    // including one that never imports this package, and they are INSERT
    // guards: a mutation that has already been refused by a CHECK or by the
    // numeric-domain trigger is still refused by that, with its own message.
    // These are AFTER ROW triggers on purpose — a BEFORE trigger would preempt
    // every CHECK constraint on these tables and make the most specific
    // violation unreportable. An AFTER trigger only ever rejects a row that
    // would otherwise have been ACCEPTED, which is exactly the population
    // these guards exist for.
    //
    // THE WITNESS IS THE NONCE, NOT THE RECEIPT. `memory_authorization_nonces`
    // is the one table the mutator can neither INSERT into nor mint a row of
    // (029). It can only CONSUME. So "a consumed nonce that names this
    // mutation receipt" is a link the mutator cannot fabricate, while "an
    // authorization receipt exists" would be a link the issuer alone controls
    // and a plain foreign key would not require consumption at all.
    //
    // SCOPE CONTINUITY IS HERE AND NOT ONLY IN THE APPLICATION. The four scope
    // dimensions were compared actor <-> authorization and NEVER actor <->
    // TARGET RECORD, so an authorization scoped to principal-attacker naming a
    // record owned by principal-victim took the record over, changed its
    // ownership columns mid-chain, and the read-back CONFIRMED the takeover
    // because it compared the observed scope against the AUTHORIZATION. The
    // application check is in wave1TrustedMemoryStore.mutate(); this is the
    // half that holds when the application is not the writer.
    //
    // NOT SOLVED, SAID PLAINLY: a superuser drops these triggers. The nonce
    // digest is still UNKEYED, so a party that can write the nonce table can
    // still mint a consistent witness — that is W1BR-008 and it needs a keyed
    // construction outside the database, which is not in this repository.
    id: "034_memory_append_integrity",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_version_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        prior public.memory_record_versions%ROWTYPE;
      BEGIN
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_authorization_nonces AS n
           WHERE n.tenant_id = NEW.tenant_id
             AND n.authorization_id = NEW.authorization_id
             AND n.target_record_id = NEW.record_id
             AND n.consumed_at IS NOT NULL
             AND n.consumed_by_mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed authorization witnesses this record version'
            USING ERRCODE = 'check_violation';
        END IF;

        SELECT * INTO prior
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.record_id
           AND v.id <> NEW.id
         ORDER BY v.version DESC
         LIMIT 1;

        IF NOT FOUND THEN
          IF NEW.version <> 1 THEN
            RAISE EXCEPTION
              'aaliyah memory: a record chain must begin at version 1'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END IF;

        IF NEW.version <> prior.version + 1 THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must be exactly one past the head'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.predecessor_digest IS DISTINCT FROM prior.content_digest THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must link to the head content digest'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.principal_id <> prior.principal_id
           OR NEW.user_id <> prior.user_id THEN
          RAISE EXCEPTION
            'aaliyah memory: a record chain may not change principal or user'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_authorized_append
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_authorized_append
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_record_version_guard();
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_outcome_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        committed boolean;
      BEGIN
        -- ABORTED_NO_MUTATION and UNKNOWN_PENDING_RECONCILIATION are what an
        -- attempt that consumed nothing is REQUIRED to be able to record, so
        -- they are deliberately not gated. The two statuses below are the
        -- only ones that CLAIM a commit.
        IF NEW.outcome_status NOT IN
             ('COMMITTED_AND_READ_BACK', 'COMMITTED_READ_BACK_DIVERGED') THEN
          RETURN NULL;
        END IF;
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_authorization_nonces AS n
           WHERE n.tenant_id = NEW.tenant_id
             AND n.authorization_id = NEW.authorization_id
             AND n.binding_digest = NEW.consumed_nonce_digest
             AND n.consumed_at IS NOT NULL
             AND n.consumed_by_mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed outcome requires a consumed authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_record_versions AS v
           WHERE v.tenant_id = NEW.tenant_id
             AND v.workspace_id = NEW.workspace_id
             AND v.record_id = NEW.target_record_id
             AND v.mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO committed;
        IF NOT committed THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed outcome requires the record version it claims'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_mutation_receipts_authorized_outcome
      ON memory_mutation_receipts;
    CREATE TRIGGER memory_mutation_receipts_authorized_outcome
      AFTER INSERT ON memory_mutation_receipts
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_outcome_guard();
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_insert_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
      BEGIN
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_authorization_nonces AS n
           WHERE n.tenant_id = NEW.tenant_id
             AND n.authorization_id = NEW.authorization_id
             AND n.consumed_at IS NOT NULL
             AND n.consumed_by_mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: no consumed authorization witnesses this binding'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_authorized_bind
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_authorized_bind
      AFTER INSERT ON memory_alias_bindings
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_alias_binding_insert_guard();
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah alias registry: DELETE on % is forbidden; a binding is retired, never erased'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.removed_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: a retired alias binding is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.removed_at IS NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement is the only permitted update'
            USING ERRCODE = 'check_violation';
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id')
           IS DISTINCT FROM
           (pg_catalog.to_jsonb(OLD) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id') THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement may not rewrite a binding'
            USING ERRCODE = 'check_violation';
        END IF;
        -- LAST, so every check above still reports its own violation.
        -- Retirement is a mutation and needs an authorization it has spent,
        -- exactly as binding does.
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_authorization_nonces AS n
           WHERE n.tenant_id = NEW.tenant_id
             AND n.authorization_id = NEW.removed_authorization_id
             AND n.consumed_at IS NOT NULL
             AND n.consumed_by_mutation_receipt_id
                 = NEW.removed_by_mutation_receipt_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: no consumed authorization witnesses this retirement'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$`,
  },
  {
    // W1.3 PART B2, M-2 — CONSUMPTION IS IRREVERSIBLE, AND THE TWO SOURCES
    // REALLY ARE UNDER DIFFERENT PRIVILEGES.
    //
    // wave1TrustedMemoryStore's header claimed "migration 029 puts those
    // sources under different privileges". For CONSUMPTION that was false:
    // 029 granted the mutator UPDATE(consumed_at, consumed_by_...) on the
    // NONCE and UPDATE(consumed_at) on the RECEIPT, so one role held both.
    // Executed as that role: consume, un-consume (set both back to NULL, which
    // satisfies the consumption_witness CHECK), re-consume. Replay was stopped
    // only by the version UNIQUE constraint, not by the privilege split.
    //
    // TWO CHANGES MAKE THE CLAIM TRUE.
    //
    // 1. MONOTONICITY. A trigger refuses any transition of `consumed_at` away
    //    from a value it already holds, on BOTH tables, for EVERY writer
    //    including the owner. Un-consuming is no longer representable, so a
    //    spent approval cannot be resurrected and re-spent.
    //
    // 2. THE MUTATOR LOSES THE SECOND SOURCE. The receipt's `consumed_at` is
    //    bookkeeping; the nonce is the authority. The mutator's UPDATE grant
    //    on the receipt is REVOKED and the database itself mirrors consumption
    //    from the nonce onto the receipt in a SECURITY DEFINER trigger. The
    //    mutator can now write exactly one of the two sources, which is what
    //    the header always said, and the two can no longer be made to disagree
    //    by anything the mutator can do.
    //
    // STILL TRUE AND STILL DISCLOSED: the mutator can BURN a pending approval
    // by consuming it out of band, which is a denial of service against an
    // approval, not a forgery. Monotonicity is what makes that burn visible
    // and permanent rather than something that can be covered up afterwards.
    id: "035_memory_consumption_monotonic",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_consumption_monotonic()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        old_row jsonb := pg_catalog.to_jsonb(OLD);
        new_row jsonb := pg_catalog.to_jsonb(NEW);
      BEGIN
        IF old_row->>'consumed_at' IS NOT NULL
           AND new_row->>'consumed_at' IS DISTINCT FROM old_row->>'consumed_at' THEN
          RAISE EXCEPTION
            'aaliyah memory: consumption is irreversible on %'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF old_row->>'consumed_by_mutation_receipt_id' IS NOT NULL
           AND new_row->>'consumed_by_mutation_receipt_id'
               IS DISTINCT FROM old_row->>'consumed_by_mutation_receipt_id' THEN
          RAISE EXCEPTION
            'aaliyah memory: a consumption witness is irreversible on %'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_authorization_nonces_consumption_monotonic
      ON memory_authorization_nonces;
    CREATE TRIGGER memory_authorization_nonces_consumption_monotonic
      BEFORE UPDATE ON memory_authorization_nonces
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_consumption_monotonic();
    DROP TRIGGER IF EXISTS memory_authorization_receipts_consumption_monotonic
      ON memory_authorization_receipts;
    CREATE TRIGGER memory_authorization_receipts_consumption_monotonic
      BEFORE UPDATE ON memory_authorization_receipts
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_consumption_monotonic();
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_mirror_consumption()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL THEN
          UPDATE public.memory_authorization_receipts
             SET consumed_at = NEW.consumed_at
           WHERE tenant_id = NEW.tenant_id
             AND authorization_id = NEW.authorization_id
             AND consumed_at IS NULL
             AND revoked_at IS NULL;
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_authorization_nonces_mirror_consumption
      ON memory_authorization_nonces;
    CREATE TRIGGER memory_authorization_nonces_mirror_consumption
      AFTER UPDATE ON memory_authorization_nonces
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_mirror_consumption();
    REVOKE UPDATE (consumed_at)
      ON memory_authorization_receipts FROM aaliyah_memory_mutator`,
  },
  {
    // W1.3 PART F — LEGAL HOLDS, ENFORCED IN THE DATABASE.
    //
    // THE CONFIRMED DEFECT THIS CLOSES. `legalHoldRestricts` existed in
    // contracts and was NEVER CALLED anywhere in Core: a grep across the
    // trusted-memory files returned one hit, a prose disclaimer in a header,
    // and the `legal_hold_active` abort reason was unreachable. A hold was a
    // shape nobody consulted. Worse, the ORIGINAL design gated DELETION only,
    // so `correct` could rewrite a held record — and the correction schema
    // REQUIRES the content to change, which made the supported, audited,
    // receipt-bearing path a spoliation path.
    //
    // THERE IS NO `restrictedActions` COLUMN HERE, DELIBERATELY, for the same
    // reason the contract has no such member: a list of restricted actions is
    // a list somebody under-fills. An ACTIVE HOLD RESTRICTS EVERY ACTION. The
    // only narrowing is an explicit carve-out row that names its court order
    // and its granting authority, and `memory_legal_hold_carve_outs_never`
    // makes a carve-out for delete, correct, merge_identity or split_identity
    // physically unrepresentable — those four destroy or reshape the very
    // evidence a hold exists to preserve.
    //
    // WHY THE ENFORCEMENT IS A TRIGGER AND NOT A CHECK IN `mutate()`. A
    // property that lives in TypeScript binds only the writes that come
    // through TypeScript. Migration 034 already established the posture: the
    // hold is consulted by an AFTER INSERT trigger on
    // `memory_record_versions`, so a hostile writer holding
    // `aaliyah_memory_mutator` and issuing a direct INSERT is refused by the
    // same control as the application. The ACTION is not taken from the
    // inserting statement — it is read from the CONSUMED NONCE that 034
    // already requires to witness the row, which is the one table the mutator
    // can neither insert into nor mint.
    //
    // SUBJECT COVERAGE FAILS CLOSED AND OVER-BLOCKS, SAID PLAINLY. A hold
    // whose coverage is `subjects` names canonical participant ids. A
    // `memory_record_versions` row carries no participant edge — there is no
    // record -> participant relation in this schema — so the record-level
    // guard CANNOT evaluate subject coverage precisely. It therefore treats an
    // active `subjects` hold as covering the whole (tenant, workspace) scope.
    // That over-blocks legitimate writes; the alternative is to let a
    // subject-scoped hold be silently unenforced, which is the defect this
    // migration exists to kill. The alias path, which DOES carry
    // `canonical_participant_id`, is matched precisely.
    //
    // NOT SOLVED: a superuser drops these triggers or releases a hold
    // directly. Nothing inside the database defends against its owner.
    id: "036_memory_legal_holds",
    sql: `DO $do$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_hold_officer') THEN
          CREATE ROLE aaliyah_memory_hold_officer NOLOGIN;
        END IF;
      END
      $do$;
    CREATE TABLE IF NOT EXISTS memory_legal_holds (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      hold_id text NOT NULL,
      matter_ref text NOT NULL,
      issuing_authority_id text NOT NULL,
      issued_at timestamptz NOT NULL,
      coverage_kind text NOT NULL,
      status_state text NOT NULL,
      released_at timestamptz,
      releasing_authority_id text,
      release_order_ref text,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_legal_holds_unique
        UNIQUE (tenant_id, workspace_id, hold_id),
      CONSTRAINT memory_legal_holds_fk_target
        UNIQUE (tenant_id, workspace_id, hold_id, coverage_kind),
      CONSTRAINT memory_legal_holds_coverage_domain
        CHECK (coverage_kind IN ('records', 'subjects', 'entire_scope')),
      CONSTRAINT memory_legal_holds_status_domain
        CHECK (status_state IN ('active', 'released')),
      CONSTRAINT memory_legal_holds_release_witness
        CHECK ((status_state = 'released') = (released_at IS NOT NULL)
               AND (status_state = 'released') = (releasing_authority_id IS NOT NULL)
               AND (status_state = 'released') = (release_order_ref IS NOT NULL)),
      CONSTRAINT memory_legal_holds_release_after_issue
        CHECK (released_at IS NULL OR released_at > issued_at),
      CONSTRAINT memory_legal_holds_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_legal_holds_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_legal_holds_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_legal_holds_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_legal_holds_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_legal_holds_hold_binding
        CHECK (payload->>'holdId' IS NOT NULL
               AND payload->>'holdId' = hold_id),
      CONSTRAINT memory_legal_holds_matter_binding
        CHECK (payload->>'matterRef' IS NOT NULL
               AND payload->>'matterRef' = matter_ref),
      CONSTRAINT memory_legal_holds_authority_binding
        CHECK (payload->>'issuingAuthorityId' IS NOT NULL
               AND payload->>'issuingAuthorityId' = issuing_authority_id),
      CONSTRAINT memory_legal_holds_coverage_binding
        CHECK (payload->'coverage'->>'kind' IS NOT NULL
               AND payload->'coverage'->>'kind' = coverage_kind),
      CONSTRAINT memory_legal_holds_status_binding
        CHECK (payload->'status'->>'state' IS NOT NULL
               AND payload->'status'->>'state' = status_state)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_legal_holds_active
      ON memory_legal_holds (tenant_id, workspace_id, coverage_kind)
      WHERE status_state = 'active';
    CREATE TABLE IF NOT EXISTS memory_legal_hold_records (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      hold_id text NOT NULL,
      coverage_kind text NOT NULL,
      record_id text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_legal_hold_records_unique
        UNIQUE (tenant_id, workspace_id, hold_id, record_id),
      CONSTRAINT memory_legal_hold_records_kind
        CHECK (coverage_kind = 'records'),
      CONSTRAINT memory_legal_hold_records_hold_fk
        FOREIGN KEY (tenant_id, workspace_id, hold_id, coverage_kind)
        REFERENCES memory_legal_holds (tenant_id, workspace_id, hold_id, coverage_kind)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_legal_hold_records_lookup
      ON memory_legal_hold_records (tenant_id, workspace_id, record_id);
    CREATE TABLE IF NOT EXISTS memory_legal_hold_subjects (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      hold_id text NOT NULL,
      coverage_kind text NOT NULL,
      canonical_participant_id text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_legal_hold_subjects_unique
        UNIQUE (tenant_id, workspace_id, hold_id, canonical_participant_id),
      CONSTRAINT memory_legal_hold_subjects_kind
        CHECK (coverage_kind = 'subjects'),
      CONSTRAINT memory_legal_hold_subjects_hold_fk
        FOREIGN KEY (tenant_id, workspace_id, hold_id, coverage_kind)
        REFERENCES memory_legal_holds (tenant_id, workspace_id, hold_id, coverage_kind)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_legal_hold_subjects_lookup
      ON memory_legal_hold_subjects (tenant_id, workspace_id, canonical_participant_id);
    CREATE TABLE IF NOT EXISTS memory_legal_hold_carve_outs (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      hold_id text NOT NULL,
      action text NOT NULL,
      order_ref text NOT NULL,
      granting_authority_id text NOT NULL,
      granted_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_legal_hold_carve_outs_unique
        UNIQUE (tenant_id, workspace_id, hold_id, action),
      CONSTRAINT memory_legal_hold_carve_outs_action_domain
        CHECK (action IN ('create', 'correct', 'delete', 'restore', 'promote',
                          'assign_alias', 'remove_alias', 'merge_identity',
                          'split_identity')),
      -- MEMORY_ACTIONS_NEVER_CARVED_OUT, in the database. A carve-out for a
      -- content-destroying or graph-reshaping action is spoliation with a
      -- cover letter, and it is not representable here for any writer.
      CONSTRAINT memory_legal_hold_carve_outs_never
        CHECK (action NOT IN ('delete', 'correct', 'merge_identity',
                              'split_identity')),
      CONSTRAINT memory_legal_hold_carve_outs_hold_fk
        FOREIGN KEY (tenant_id, workspace_id, hold_id)
        REFERENCES memory_legal_holds (tenant_id, workspace_id, hold_id)
    );
    CREATE TABLE IF NOT EXISTS memory_retention_obligations (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      obligation_id text NOT NULL,
      record_id text NOT NULL,
      policy_ref text NOT NULL,
      retain_until timestamptz NOT NULL,
      imposing_authority_id text NOT NULL,
      imposed_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_retention_obligations_unique
        UNIQUE (tenant_id, workspace_id, obligation_id),
      CONSTRAINT memory_retention_obligations_window
        CHECK (retain_until > imposed_at)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_retention_obligations_lookup
      ON memory_retention_obligations
      (tenant_id, workspace_id, record_id, retain_until DESC);
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_jsonb_strings(doc jsonb)
      RETURNS SETOF text
      LANGUAGE sql
      IMMUTABLE
      SET search_path = pg_catalog, public
      AS $fn$
        WITH RECURSIVE walk(node) AS (
          SELECT doc
          UNION ALL
          SELECT child.value
          FROM walk
          CROSS JOIN LATERAL (
            SELECT value FROM pg_catalog.jsonb_array_elements(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'array'
                   THEN walk.node ELSE '[]'::jsonb END)
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_each(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'object'
                   THEN walk.node ELSE '{}'::jsonb END)
          ) AS child(value)
        )
        SELECT node #>> '{}' FROM walk
         WHERE pg_catalog.jsonb_typeof(node) = 'string';
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_jsonb_member_names(doc jsonb)
      RETURNS SETOF text
      LANGUAGE sql
      IMMUTABLE
      SET search_path = pg_catalog, public
      AS $fn$
        WITH RECURSIVE walk(node) AS (
          SELECT doc
          UNION ALL
          SELECT child.value
          FROM walk
          CROSS JOIN LATERAL (
            SELECT value FROM pg_catalog.jsonb_array_elements(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'array'
                   THEN walk.node ELSE '[]'::jsonb END)
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_each(
              CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'object'
                   THEN walk.node ELSE '{}'::jsonb END)
          ) AS child(value)
        )
        SELECT k FROM walk
         CROSS JOIN LATERAL pg_catalog.jsonb_object_keys(
           CASE WHEN pg_catalog.jsonb_typeof(walk.node) = 'object'
                THEN walk.node ELSE '{}'::jsonb END) AS k;
      $fn$;
    -- THE FREE-TEXT GATE. Every string anywhere in a hold or a tombstone must
    -- be an identifier, an evidence reference, an enum word, a digest, a
    -- field name or an ISO instant. "SENSITIVE: CEO divorce settlement terms"
    -- matches none of those, and neither does any sentence: the identifier
    -- form admits no spaces and no leading capital. This is the structural
    -- half of "a tombstone has nowhere to put the payload it destroyed".
    --
    -- DISCLOSED LIMIT: a lowercase, space-free, punctuation-limited token is
    -- indistinguishable from an identifier and would pass. The gate bounds the
    -- SHAPE of what can survive here; it is not a classifier.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_first_free_text(doc jsonb)
      RETURNS text
      LANGUAGE sql
      STABLE
      SET search_path = pg_catalog, public
      AS $fn$
        SELECT s FROM public.aaliyah_memory_jsonb_strings(doc) AS t(s)
         WHERE NOT (
           s ~ '^[a-z0-9][a-z0-9._:/+_-]{0,253}$'
           OR s ~ '^[a-z][a-zA-Z0-9_]{0,63}$'
           OR s ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$'
         )
         LIMIT 1;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_legal_hold_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah memory: DELETE on % is forbidden; a legal hold is released, never erased'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF TG_OP = 'UPDATE' THEN
          IF OLD.status_state <> 'active' THEN
            RAISE EXCEPTION
              'aaliyah memory: a released legal hold is immutable'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.status_state <> 'released' THEN
            RAISE EXCEPTION
              'aaliyah memory: release is the only permitted update to a legal hold'
              USING ERRCODE = 'check_violation';
          END IF;
          IF (pg_catalog.to_jsonb(NEW) - 'status_state' - 'released_at'
                - 'releasing_authority_id' - 'release_order_ref' - 'payload')
             IS DISTINCT FROM
             (pg_catalog.to_jsonb(OLD) - 'status_state' - 'released_at'
                - 'releasing_authority_id' - 'release_order_ref' - 'payload') THEN
            RAISE EXCEPTION
              'aaliyah memory: releasing a hold may not rewrite its coverage'
              USING ERRCODE = 'check_violation';
          END IF;
          IF (NEW.payload - 'status') IS DISTINCT FROM (OLD.payload - 'status') THEN
            RAISE EXCEPTION
              'aaliyah memory: releasing a hold may not rewrite its coverage'
              USING ERRCODE = 'check_violation';
          END IF;
        END IF;
        IF public.aaliyah_memory_first_free_text(NEW.payload) IS NOT NULL THEN
          -- The VALUE is deliberately absent from this message: migration 033
          -- closed exactly this leak on the numeric path.
          RAISE EXCEPTION
            'aaliyah memory: a legal hold may not carry free-form text'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_legal_holds_release_only ON memory_legal_holds;
    CREATE TRIGGER memory_legal_holds_release_only
      BEFORE INSERT OR UPDATE OR DELETE ON memory_legal_holds
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_legal_hold_guard();
    DROP TRIGGER IF EXISTS memory_legal_hold_records_append_only
      ON memory_legal_hold_records;
    CREATE TRIGGER memory_legal_hold_records_append_only
      BEFORE UPDATE OR DELETE ON memory_legal_hold_records
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_legal_hold_subjects_append_only
      ON memory_legal_hold_subjects;
    CREATE TRIGGER memory_legal_hold_subjects_append_only
      BEFORE UPDATE OR DELETE ON memory_legal_hold_subjects
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_legal_hold_carve_outs_append_only
      ON memory_legal_hold_carve_outs;
    CREATE TRIGGER memory_legal_hold_carve_outs_append_only
      BEFORE UPDATE OR DELETE ON memory_legal_hold_carve_outs
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_retention_obligations_append_only
      ON memory_retention_obligations;
    CREATE TRIGGER memory_retention_obligations_append_only
      BEFORE UPDATE OR DELETE ON memory_retention_obligations
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_forbid_row_rewrite();
    -- THE LOOKUP EVERY GUARD BELOW SHARES. Answers the hold id that RESTRICTS
    -- this action on this record, or NULL. A carve-out narrows exactly the one
    -- action it names and nothing else.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_restricting_hold(
      p_tenant text, p_workspace text, p_record text,
      p_participant text, p_action text)
      RETURNS text
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
        SELECT h.hold_id
          FROM public.memory_legal_holds AS h
         WHERE h.tenant_id = p_tenant
           AND h.workspace_id = p_workspace
           AND h.status_state = 'active'
           AND (
             h.coverage_kind = 'entire_scope'
             OR (h.coverage_kind = 'records' AND EXISTS (
                   SELECT 1 FROM public.memory_legal_hold_records AS r
                    WHERE r.tenant_id = h.tenant_id
                      AND r.workspace_id = h.workspace_id
                      AND r.hold_id = h.hold_id
                      AND r.record_id = p_record))
             OR (h.coverage_kind = 'subjects' AND p_participant IS NULL)
             OR (h.coverage_kind = 'subjects' AND p_participant IS NOT NULL
                 AND EXISTS (
                   SELECT 1 FROM public.memory_legal_hold_subjects AS s
                    WHERE s.tenant_id = h.tenant_id
                      AND s.workspace_id = h.workspace_id
                      AND s.hold_id = h.hold_id
                      AND s.canonical_participant_id = p_participant))
           )
           AND NOT EXISTS (
             SELECT 1 FROM public.memory_legal_hold_carve_outs AS c
              WHERE c.tenant_id = h.tenant_id
                AND c.workspace_id = h.workspace_id
                AND c.hold_id = h.hold_id
                AND c.action = p_action)
         ORDER BY h.id ASC
         LIMIT 1;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_version_hold_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
        blocking text;
      BEGIN
        -- The action is NOT taken from the inserting statement. It is read
        -- from the consumed nonce that migration 034 already requires to
        -- witness this row, which is the one table the mutator can neither
        -- insert into nor mint.
        SELECT n.action INTO acted
          FROM public.memory_authorization_nonces AS n
         WHERE n.tenant_id = NEW.tenant_id
           AND n.authorization_id = NEW.authorization_id
           AND n.target_record_id = NEW.record_id
           AND n.consumed_at IS NOT NULL
           AND n.consumed_by_mutation_receipt_id = NEW.mutation_receipt_id
         LIMIT 1;
        IF acted IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: the action of this append cannot be resolved, so a legal hold cannot be evaluated'
            USING ERRCODE = 'check_violation';
        END IF;
        blocking := public.aaliyah_memory_restricting_hold(
          NEW.tenant_id, NEW.workspace_id, NEW.record_id, NULL, acted);
        IF blocking IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: legal hold % restricts % on this record'
            , blocking, acted
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_legal_hold
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_legal_hold
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_record_version_hold_guard();
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_hold_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
        target text;
        blocking text;
        auth_id text;
        receipt_id text;
      BEGIN
        IF TG_OP = 'INSERT' THEN
          auth_id := NEW.authorization_id;
          receipt_id := NEW.mutation_receipt_id;
        ELSE
          auth_id := NEW.removed_authorization_id;
          receipt_id := NEW.removed_by_mutation_receipt_id;
        END IF;
        SELECT n.action, n.target_record_id INTO acted, target
          FROM public.memory_authorization_nonces AS n
         WHERE n.tenant_id = NEW.tenant_id
           AND n.authorization_id = auth_id
           AND n.consumed_at IS NOT NULL
           AND n.consumed_by_mutation_receipt_id = receipt_id
         LIMIT 1;
        IF acted IS NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: the action of this binding cannot be resolved, so a legal hold cannot be evaluated'
            USING ERRCODE = 'check_violation';
        END IF;
        blocking := public.aaliyah_memory_restricting_hold(
          NEW.tenant_id, NEW.workspace_id, target,
          NEW.canonical_participant_id, acted);
        IF blocking IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: legal hold % restricts % on this participant'
            , blocking, acted
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_legal_hold
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_legal_hold
      AFTER INSERT OR UPDATE ON memory_alias_bindings
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_alias_binding_hold_guard();
    -- PRIVILEGES. The hold officer is the ONLY role that may place or release
    -- a hold or impose a retention obligation. The mutator gets SELECT and
    -- nothing else: a role that can lift its own hold has no hold, which is
    -- the same argument migration 032 makes about the alias policy tables.
    GRANT SELECT ON
      memory_legal_holds,
      memory_legal_hold_records,
      memory_legal_hold_subjects,
      memory_legal_hold_carve_outs,
      memory_retention_obligations
      TO aaliyah_memory_mutator, aaliyah_memory_reader,
         aaliyah_memory_issuer, aaliyah_memory_revoker,
         aaliyah_memory_hold_officer;
    GRANT SELECT ON
      memory_record_versions,
      memory_authorization_receipts,
      memory_authorization_nonces,
      memory_mutation_receipts
      TO aaliyah_memory_hold_officer;
    GRANT INSERT ON
      memory_legal_holds,
      memory_legal_hold_records,
      memory_legal_hold_subjects,
      memory_legal_hold_carve_outs,
      memory_retention_obligations
      TO aaliyah_memory_hold_officer;
    GRANT USAGE, SELECT ON SEQUENCE
      memory_legal_holds_id_seq,
      memory_legal_hold_records_id_seq,
      memory_legal_hold_subjects_id_seq,
      memory_legal_hold_carve_outs_id_seq,
      memory_retention_obligations_id_seq
      TO aaliyah_memory_hold_officer;
    GRANT UPDATE (status_state, released_at, releasing_authority_id,
                  release_order_ref, payload)
      ON memory_legal_holds TO aaliyah_memory_hold_officer`,
  },
  {
    // W1.3 PART F — DELETION IS ERASURE, AND A TOMBSTONE ACCOUNTS FOR IT.
    //
    // THE CONFIRMED DEFECT THIS CLOSES. `delete()` advanced the head to a
    // `deleted` state and destroyed nothing. "Deleted" was a LABEL. An
    // independent review of the original candidate found an "erased" record
    // still holding "SENSITIVE: CEO divorce settlement terms" verbatim at an
    // earlier version, and the security gate showed the combination with the
    // takeover defect was worse still: an attacker-driven delete moved the
    // head to `deleted` while the victim's content stayed fully readable at
    // version 1.
    //
    // ERASURE VERSUS THE APPEND-ONLY CHAIN — THE RESOLUTION, STATED ONCE.
    //
    // Migrations 028 and 034 make the version chain append-only: UPDATE and
    // DELETE are refused, every appended version must be witnessed by a
    // consumed authorization, contiguous in version, linked by predecessor
    // digest, with owner continuity. Real erasure must destroy prior content.
    // Those look contradictory. They are not, once CHAIN METADATA and RECORD
    // CONTENT are separated:
    //
    //   * CHAIN METADATA — version, state, content_digest,
    //     predecessor_digest, authorization_id, mutation_receipt_id, the four
    //     scope columns, created_at — stays APPEND-ONLY AND IMMUTABLE. Nothing
    //     below may touch it. Every integrity property 034 enforces is stated
    //     purely over these columns, so every one of them still holds after an
    //     erasure, and the chain is still walkable and verifiable end to end.
    //
    //   * RECORD CONTENT — `payload->'content'` alone — is MUTABLE EXACTLY
    //     ONCE, from its value to JSON `null`, and only under a tombstone that
    //     already exists and names this record. `content_erased_at` records
    //     that the transition happened and makes it unrepeatable.
    //
    // The content digest is DELIBERATELY RETAINED: it is what keeps the next
    // version's `predecessor_digest` meaningful, so erasing a record does not
    // break the successor's linkage. The honest consequence, disclosed: the
    // digest is unkeyed, so it remains an offline oracle for guessed content
    // exactly as W1BR-008 already says. Erasure removes the plaintext, not the
    // oracle.
    //
    // "DELETED" CANNOT BE A LABEL AGAIN. `memory_record_versions_deletion_erases`
    // is a DEFERRED CONSTRAINT TRIGGER: at COMMIT, a record that has just
    // acquired a `deleted` head and still has ANY unerased prior version is
    // refused. Marking without erasing is not representable for any writer,
    // not only for callers of `delete()`.
    //
    // A TOMBSTONE HAS NOWHERE TO PUT THE PAYLOAD. Three independent controls:
    // the top-level key set is CLOSED to the eighteen contract members; no
    // member anywhere may be named `content`, `payload`, `value`, `body`,
    // `text`, `note`, `data`, `plaintext` or `secret`; and every string
    // anywhere must pass `aaliyah_memory_first_free_text`. `legal_hold_state`
    // is additionally forbidden from being `held`, because destroying under an
    // active hold is spoliation.
    //
    // THE DELETED HEAD CANNOT CARRY THE PAYLOAD EITHER. The content of a
    // version whose state is `deleted` must be a DELETION ORDER: exactly three
    // members, a pinned schema version, a reason from the contract's closed
    // enum, and an evidence reference. A delete therefore cannot smuggle the
    // record's plaintext forward into the version it is deleting it at.
    //
    // NOT SOLVED, SAID PLAINLY. Nulling `payload->'content'` writes a new heap
    // tuple; the old one survives until VACUUM, and the pre-image is in the
    // WAL, in any replica, and in any physical backup taken before the
    // erasure. The tombstone's propagation members exist precisely because
    // Core cannot claim otherwise, and `unknown` is the honest answer this
    // implementation records. A superuser can also drop every trigger here.
    id: "037_memory_erasure_tombstones",
    sql: `DO $do$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.memory_record_versions'::regclass
             AND attname = 'content_erased_at'
             AND NOT attisdropped
        ) THEN
          ALTER TABLE public.memory_record_versions
            ADD COLUMN content_erased_at timestamptz,
            ADD COLUMN erasure_tombstone_id text;
          ALTER TABLE public.memory_record_versions
            ADD CONSTRAINT memory_record_versions_erasure_witness
            CHECK ((content_erased_at IS NULL) = (erasure_tombstone_id IS NULL));
        END IF;
      END
      $do$;
    CREATE TABLE IF NOT EXISTS memory_tombstones (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      tombstone_id text NOT NULL,
      target_record_id text NOT NULL,
      target_version integer NOT NULL,
      tombstone_version integer NOT NULL,
      authorization_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      reason text NOT NULL,
      effective_at timestamptz NOT NULL,
      retain_until timestamptz,
      legal_hold_state text NOT NULL,
      cache_index_propagation text NOT NULL,
      restoration_eligibility_kind text NOT NULL,
      tombstone_digest text NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_tombstones_unique
        UNIQUE (tenant_id, workspace_id, tombstone_id),
      CONSTRAINT memory_tombstones_version_unique
        UNIQUE (tenant_id, workspace_id, target_record_id, tombstone_version),
      CONSTRAINT memory_tombstones_reason_domain
        CHECK (reason IN ('subject_erasure_request', 'retention_expiry',
                          'erroneous_record', 'policy_violation',
                          'legal_requirement', 'duplicate_record')),
      CONSTRAINT memory_tombstones_hold_state_domain
        CHECK (legal_hold_state IN ('none', 'held', 'released')),
      -- Spoliation, unrepresentable. A tombstone that admits its target was
      -- under an active hold is a confession, not a record.
      CONSTRAINT memory_tombstones_not_under_hold
        CHECK (legal_hold_state <> 'held'),
      CONSTRAINT memory_tombstones_propagation_domain
        CHECK (cache_index_propagation IN ('not_started', 'in_progress',
                                           'complete', 'failed', 'unknown')),
      -- THERE IS NO ESCROW IN THIS REPOSITORY. Claiming a destroyed
      -- payload is restorable from an escrow that does not exist is the exact
      -- class of false assurance this whole path exists to remove.
      CONSTRAINT memory_tombstones_restoration_domain
        CHECK (restoration_eligibility_kind = 'ineligible_payload_destroyed'),
      CONSTRAINT memory_tombstones_versions_ordered
        CHECK (tombstone_version > target_version AND target_version >= 1),
      CONSTRAINT memory_tombstones_digest_form
        CHECK (tombstone_digest ~ '^sha256:[a-f0-9]{64}$'),
      CONSTRAINT memory_tombstones_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_tombstones_tenant_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id),
      CONSTRAINT memory_tombstones_workspace_binding
        CHECK (payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id),
      CONSTRAINT memory_tombstones_principal_binding
        CHECK (payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id),
      CONSTRAINT memory_tombstones_user_binding
        CHECK (payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_tombstones_id_binding
        CHECK (payload->>'tombstoneId' IS NOT NULL
               AND payload->>'tombstoneId' = tombstone_id),
      CONSTRAINT memory_tombstones_target_binding
        CHECK (payload->>'targetRecordId' IS NOT NULL
               AND payload->>'targetRecordId' = target_record_id),
      CONSTRAINT memory_tombstones_target_version_binding
        CHECK (payload->>'targetVersion' IS NOT NULL
               AND payload->>'targetVersion' = target_version::text),
      CONSTRAINT memory_tombstones_tombstone_version_binding
        CHECK (payload->>'tombstoneVersion' IS NOT NULL
               AND payload->>'tombstoneVersion' = tombstone_version::text),
      CONSTRAINT memory_tombstones_authorization_binding
        CHECK (payload->'deletionAuthority'->>'authorizationId' IS NOT NULL
               AND payload->'deletionAuthority'->>'authorizationId' = authorization_id),
      CONSTRAINT memory_tombstones_reason_binding
        CHECK (payload->>'reason' IS NOT NULL
               AND payload->>'reason' = reason),
      CONSTRAINT memory_tombstones_hold_state_binding
        CHECK (payload->'retention'->'legalHoldState'->>'state' IS NOT NULL
               AND payload->'retention'->'legalHoldState'->>'state' = legal_hold_state),
      CONSTRAINT memory_tombstones_propagation_binding
        CHECK (payload->>'cacheIndexPropagation' IS NOT NULL
               AND payload->>'cacheIndexPropagation' = cache_index_propagation),
      CONSTRAINT memory_tombstones_restoration_binding
        CHECK (payload->'restorationEligibility'->>'kind' IS NOT NULL
               AND payload->'restorationEligibility'->>'kind' = restoration_eligibility_kind),
      CONSTRAINT memory_tombstones_digest_binding
        CHECK (payload->>'tombstoneDigest' IS NOT NULL
               AND payload->>'tombstoneDigest' = tombstone_digest),
      CONSTRAINT memory_tombstones_destroyed_not_empty
        CHECK (jsonb_typeof(payload->'destroyedFieldNames') = 'array'
               AND jsonb_array_length(payload->'destroyedFieldNames') >= 1)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_tombstones_target
      ON memory_tombstones (tenant_id, workspace_id, target_record_id, id DESC);
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_tombstone_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        offending text;
        blocking text;
        obligation timestamptz;
        head_state text;
      BEGIN
        IF (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(NEW.payload)) <> 18
           OR NOT (NEW.payload ?& ARRAY[
             'schemaVersion','tombstoneId','scope','targetRecordId',
             'targetVersion','tombstoneVersion','deletionAuthority','reason',
             'reasonEvidenceRef','effectiveAt','retention','retainedFieldNames',
             'destroyedFieldNames','derivedData','cacheIndexPropagation',
             'downstreamPropagation','restorationEligibility','tombstoneDigest'])
        THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone must carry exactly the contract member set'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT k INTO offending
          FROM public.aaliyah_memory_jsonb_member_names(NEW.payload) AS t(k)
         WHERE pg_catalog.lower(k) IN ('content','payload','value','body','text',
                                       'note','data','plaintext','secret')
         LIMIT 1;
        IF offending IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone may not carry a payload-bearing member'
            USING ERRCODE = 'check_violation';
        END IF;
        IF public.aaliyah_memory_first_free_text(NEW.payload) IS NOT NULL THEN
          -- The VALUE is deliberately absent: see migration 033, M-4.
          RAISE EXCEPTION
            'aaliyah memory: a tombstone may not carry free-form text'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT v.state INTO head_state
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.target_record_id
           AND v.version = NEW.tombstone_version
         LIMIT 1;
        IF head_state IS DISTINCT FROM 'deleted' THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone must name a deleted version of its target record'
            USING ERRCODE = 'check_violation';
        END IF;
        blocking := public.aaliyah_memory_restricting_hold(
          NEW.tenant_id, NEW.workspace_id, NEW.target_record_id, NULL, 'delete');
        IF blocking IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: legal hold % restricts delete on this record'
            , blocking
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT pg_catalog.max(o.retain_until) INTO obligation
          FROM public.memory_retention_obligations AS o
         WHERE o.tenant_id = NEW.tenant_id
           AND o.workspace_id = NEW.workspace_id
           AND o.record_id = NEW.target_record_id
           AND o.retain_until > pg_catalog.now();
        IF obligation IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: an unexpired retention obligation forbids destroying this record'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_tombstones_structural ON memory_tombstones;
    CREATE TRIGGER memory_tombstones_structural
      BEFORE INSERT OR UPDATE ON memory_tombstones
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_tombstone_guard();
    DROP TRIGGER IF EXISTS memory_tombstones_append_only ON memory_tombstones;
    CREATE TRIGGER memory_tombstones_append_only
      BEFORE UPDATE OR DELETE ON memory_tombstones
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_tombstones_exact_numbers ON memory_tombstones;
    CREATE TRIGGER memory_tombstones_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_tombstones
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_reject_inexact_numbers();
    -- THE ONE PERMITTED REWRITE. Replaces the blanket refusal installed by
    -- migration 028 on this table, and keeps its message verbatim for every
    -- case that is not an erasure, because that message is the contract every
    -- existing caller and test matches on.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_version_rewrite_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah memory: % on % is forbidden; this table is append-only'
            , TG_OP, TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.content_erased_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: an erased record version is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.content_erased_at IS NULL OR NEW.erasure_tombstone_id IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: % on % is forbidden; this table is append-only'
            , TG_OP, TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.payload IS DISTINCT FROM
           pg_catalog.jsonb_set(OLD.payload, '{content}', 'null'::jsonb) THEN
          RAISE EXCEPTION
            'aaliyah memory: erasure may null the content and nothing else'
            USING ERRCODE = 'check_violation';
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - 'payload' - 'content_erased_at'
              - 'erasure_tombstone_id')
           IS DISTINCT FROM
           (pg_catalog.to_jsonb(OLD) - 'payload' - 'content_erased_at'
              - 'erasure_tombstone_id') THEN
          RAISE EXCEPTION
            'aaliyah memory: erasure may not rewrite the chain metadata'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1 FROM public.memory_tombstones AS t
           WHERE t.tenant_id = NEW.tenant_id
             AND t.workspace_id = NEW.workspace_id
             AND t.tombstone_id = NEW.erasure_tombstone_id
             AND t.target_record_id = NEW.record_id
             AND t.tombstone_version > NEW.version
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: no tombstone authorizes this erasure'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_append_only
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_append_only
      BEFORE UPDATE OR DELETE ON memory_record_versions
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_record_version_rewrite_guard();
    -- DELETION MUST BE ERASURE. Deferred to COMMIT, because the tombstone and
    -- the erasing UPDATE necessarily follow the insert of the deleted head
    -- inside the same transaction.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_deletion_is_erasure()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        survivor bigint;
      BEGIN
        IF NEW.state <> 'deleted' THEN RETURN NULL; END IF;
        SELECT v.id INTO survivor
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.record_id
           AND v.version < NEW.version
           AND v.content_erased_at IS NULL
         LIMIT 1;
        IF survivor IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: a deletion must erase every prior version of the record'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_deletion_erases
      ON memory_record_versions;
    CREATE CONSTRAINT TRIGGER memory_record_versions_deletion_erases
      AFTER INSERT ON memory_record_versions
      DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_deletion_is_erasure();
    -- THE DELETED HEAD CARRIES A DELETION ORDER, NOT THE RECORD.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_deletion_order_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        order_doc jsonb;
      BEGIN
        IF NEW.state <> 'deleted' THEN RETURN NULL; END IF;
        order_doc := NEW.payload->'content';
        IF pg_catalog.jsonb_typeof(order_doc) <> 'object'
           OR (SELECT pg_catalog.count(*)
                 FROM pg_catalog.jsonb_object_keys(order_doc)) <> 3
           OR NOT (order_doc ?& ARRAY['schemaVersion','reason','reasonEvidenceRef'])
           OR order_doc->>'schemaVersion'
              <> 'aaliyah.trusted-memory/v1#deletion-order'
           OR order_doc->>'reason' NOT IN
              ('subject_erasure_request', 'retention_expiry',
               'erroneous_record', 'policy_violation',
               'legal_requirement', 'duplicate_record')
           OR order_doc->>'reasonEvidenceRef' !~
              '^[a-z][a-z0-9_-]{1,31}:[a-z0-9][a-z0-9._:/-]{3,223}$'
        THEN
          RAISE EXCEPTION
            'aaliyah memory: the content of a deleted version must be a deletion order'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_witnessed_deletion_order
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_witnessed_deletion_order
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_deletion_order_guard();
    -- AN AUTHORIZATION FOR ONE ACTION CANNOT PERFORM ANOTHER, IN THE DATABASE.
    --
    -- The contract already binds the action into the nonce, so a relabelled
    -- receipt no longer matches its own token, and the store compares the
    -- stored action against the call site. Neither of those binds a writer
    -- that never comes through the store. This does: the action is read from
    -- the consumed nonce, and a delete authorization can then only produce a
    -- deleted version while a restore authorization can only produce an active
    -- one from a deleted head. A delete authorization is therefore
    -- structurally incapable of restoring, and a restore authorization of
    -- deleting, for every writer.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_action_state_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
        prior_state text;
      BEGIN
        SELECT n.action INTO acted
          FROM public.memory_authorization_nonces AS n
         WHERE n.tenant_id = NEW.tenant_id
           AND n.authorization_id = NEW.authorization_id
           AND n.target_record_id = NEW.record_id
           AND n.consumed_at IS NOT NULL
           AND n.consumed_by_mutation_receipt_id = NEW.mutation_receipt_id
         LIMIT 1;
        IF acted IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: the action of this append cannot be resolved, so its state transition cannot be checked'
            USING ERRCODE = 'check_violation';
        END IF;
        IF acted = 'delete' AND NEW.state <> 'deleted' THEN
          RAISE EXCEPTION
            'aaliyah memory: a delete authorization may only produce a deleted version'
            USING ERRCODE = 'check_violation';
        END IF;
        IF acted <> 'delete' AND NEW.state <> 'active' THEN
          RAISE EXCEPTION
            'aaliyah memory: only a delete authorization may produce a deleted version'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT v.state INTO prior_state
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.record_id
           AND v.id <> NEW.id
         ORDER BY v.version DESC
         LIMIT 1;
        IF acted = 'restore' AND prior_state IS DISTINCT FROM 'deleted' THEN
          RAISE EXCEPTION
            'aaliyah memory: restore may only follow a deleted head'
            USING ERRCODE = 'check_violation';
        END IF;
        IF acted <> 'restore' AND prior_state = 'deleted' THEN
          RAISE EXCEPTION
            'aaliyah memory: a deleted record may only be restored, and only under a restore authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_witnessed_action_state
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_witnessed_action_state
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_action_state_guard();
    -- ORDINARY RETRIEVAL, IN THE DATABASE. A deleted or erased record is not
    -- returned by this relation, so "excluded from retrieval" is a property of
    -- the store, not a filter a caller can forget to apply.
    CREATE OR REPLACE VIEW memory_records_retrievable AS
      SELECT v.tenant_id, v.workspace_id, v.principal_id, v.user_id,
             v.record_id, v.version, v.state, v.content_digest,
             v.predecessor_digest, v.authorization_id, v.mutation_receipt_id,
             v.payload
        FROM memory_record_versions AS v
       WHERE v.state = 'active'
         AND v.content_erased_at IS NULL
         AND v.id = (SELECT pg_catalog.max(w.id)
                       FROM memory_record_versions AS w
                      WHERE w.tenant_id = v.tenant_id
                        AND w.workspace_id = v.workspace_id
                        AND w.record_id = v.record_id);
    GRANT SELECT ON memory_tombstones
      TO aaliyah_memory_mutator, aaliyah_memory_reader,
         aaliyah_memory_issuer, aaliyah_memory_revoker,
         aaliyah_memory_hold_officer;
    GRANT INSERT ON memory_tombstones TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE memory_tombstones_id_seq
      TO aaliyah_memory_mutator;
    GRANT SELECT ON memory_records_retrievable
      TO aaliyah_memory_mutator, aaliyah_memory_reader;
    -- COLUMN-LEVEL, and the rewrite guard above is what makes it safe: the
    -- mutator may touch exactly these three columns, and the trigger refuses
    -- every value of them that is not the single erasure transition.
    GRANT UPDATE (payload, content_erased_at, erasure_tombstone_id)
      ON memory_record_versions TO aaliyah_memory_mutator`,
  },
  {
    // W1.3 PART B3, H-1 — ONE CONSUMED AUTHORIZATION WITNESSES EXACTLY ONE
    // MUTATION, AND A LAPSED CONSUMPTION WITNESSES NOTHING.
    //
    // THE CONFIRMED DEFECT THIS CLOSES, EXECUTED AS THE LEAST-PRIVILEGE
    // `aaliyah_memory_mutator` ROLE AGAINST A LIVE DATABASE.
    //
    // Migration 034 witnesses an appended record version by matching a
    // CONSUMED NONCE on tenant / authorization_id / target_record_id /
    // consumed_at IS NOT NULL / consumed_by_mutation_receipt_id. Nothing
    // anywhere bounded HOW MANY rows a single such nonce could witness:
    // `memory_record_versions` carried uniqueness only on `id` and on
    // (tenant_id, workspace_id, record_id, version). One nonce, obtained from
    // one legitimate mutation, therefore witnessed an UNBOUNDED number of
    // appended versions that all reused its `mutation_receipt_id`:
    //
    //     version | state  | digest       | authorization_id | mutation_receipt_id
    //           1 | active | sha256:aaaa. | A1               | MR1
    //           2 | active | sha256:bbbb. | A1               | MR1
    //     consumed_nonces = 1
    //
    // "Witnessed" was satisfied by one reused nonce; ONE-AUTHORIZATION-PER-
    // VERSION was not enforced. `memory_alias_bindings` had the same shape on
    // both of its witness columns, and `memory_tombstones` — added by
    // migration 037 — carried `authorization_id` and `mutation_receipt_id`
    // that NOTHING checked at all, so a tombstone's attribution was
    // decoration.
    //
    // SECOND HALF OF THE SAME FINDING: every witness predicate tested only
    // `consumed_at IS NOT NULL` and never looked at the nonce's validity
    // window, so a nonce consumed long after it lapsed still witnessed.
    //
    // THE FIX, AND WHY THIS SHAPE.
    //
    // 1. UNIQUENESS, NOT A TRIGGER, WHEREVER ONE COLUMN CAN CARRY IT. The
    //    falsifier offered two routes: a UNIQUE constraint on
    //    `mutation_receipt_id`, or a per-version freshness test inside the 034
    //    guard. A trigger predicate of the form "no other row already names
    //    this receipt" is defeated by two concurrent transactions, because an
    //    AFTER INSERT trigger under READ COMMITTED cannot see a sibling's
    //    uncommitted row. A UNIQUE INDEX is enforced by the storage engine at
    //    every isolation level, for every writer, with no argument about
    //    serialization required. It is therefore strictly the stronger of the
    //    two and is what is used here. Combined with the nonce's own
    //    single-use consumption (025's `memory_authorization_nonces_unique`
    //    plus 035's monotonicity), the chain is: one nonce -> one
    //    `consumed_by_mutation_receipt_id` -> AT MOST ONE witnessed row per
    //    witnessing table. That is one-authorization-per-version, enforced.
    //
    //    SCOPE OF THE UNIQUENESS IS PER TABLE, DELIBERATELY. One legitimate
    //    mutation writes to SEVERAL of these tables under one receipt id: an
    //    `assign_alias` appends a record version AND inserts an alias binding;
    //    a `delete` appends a record version AND writes a tombstone. A single
    //    global spend ledger would refuse the legitimate path. The invariant
    //    that is actually true is "one receipt id, at most one row in each
    //    witnessing table", and that is what is written.
    //
    // 2. THE ONE CASE AN INDEX CANNOT EXPRESS. `memory_alias_bindings` claims
    //    a spend from TWO different columns — `mutation_receipt_id` when a
    //    binding is created and `removed_by_mutation_receipt_id` when one is
    //    retired — and a b-tree index over a single table cannot make one
    //    receipt id collide across two columns of two different rows. Both
    //    columns get their own unique index, and the CROSS case (one receipt
    //    id binds one alias and retires another) is refused by a predicate in
    //    the two guards. That predicate IS race-safe here, and the argument is
    //    written out rather than assumed: both writes must be witnessed by the
    //    SAME nonce row, and a nonce can only be consumed once — the consuming
    //    UPDATE takes a row lock and 035 makes the transition irreversible —
    //    so the second write either happens in the same transaction as the
    //    first (statements are sequential and see each other) or in a later
    //    one (the first has committed). Two genuinely concurrent claimants
    //    cannot both see the consumption they both need.
    //
    // 3. THE VALIDITY WINDOW, STATED SO IT DOES NOT DECAY.
    //    `aaliyah_memory_spent_nonce` is now the ONLY place any guard resolves
    //    a spent nonce, and it requires the consumption to have happened
    //    INSIDE the nonce's window: `consumed_at >= issued_at` and
    //    `consumed_at < expires_at`. It deliberately does NOT test
    //    `expires_at > now()`. A predicate against the wall clock would be
    //    TRUE at insert time and FALSE an hour later, which would mean a
    //    terminal receipt appended after a read-back, or any re-evaluation,
    //    could no longer confirm a mutation that really was authorized. The
    //    window test above is a statement about a fact that already happened
    //    and never changes its answer.
    //
    // 4. WHAT MAKES THAT WINDOW TEST UNFORGEABLE. `consumed_at` is written by
    //    `aaliyah_memory_mutator`, which holds UPDATE on exactly that column,
    //    so the role that benefits from a backdated consumption is the role
    //    that writes the timestamp. `aaliyah_memory_consumption_stamped`
    //    refuses any consumption transition whose `consumed_at` is not the
    //    transaction clock, for every writer including the owner. Without it
    //    the window test would be a check on a number the attacker chooses.
    //
    //    CONSUMING A LAPSED NONCE IS STILL PERMITTED, ON PURPOSE. The nonce is
    //    burnt and can never witness anything, which is a denial of service
    //    against one approval — the same class 035 already discloses — not a
    //    forgery. Refusing the consumption instead would make the window test
    //    in the witness unreachable and therefore unkillable by any test, and
    //    an unkillable control is not evidence.
    //
    // 5. THE TOMBSTONE IS WITNESSED AT LAST. `memory_tombstones` now needs a
    //    consumed nonce naming its target record with action `delete`, exactly
    //    like the version it accounts for. The check is the LAST one in the
    //    guard so that every structural, hold and retention violation above it
    //    still reports its own message.
    //
    // 6. A COMMITTED OUTCOME NEEDS THE PENDING ROW IT CONCLUDES. The second
    //    supplied reproducer minted a `terminal` /
    //    `COMMITTED_AND_READ_BACK` receipt with no `pending` row anywhere:
    //    "success is never the residue of a crash" was a property of the
    //    STORE and of nothing else. It is now a property of the table.
    //
    // TABLES EXAMINED AND FOUND NOT TO CARRY THIS DEFECT, recorded so the next
    // reader does not have to re-derive it: `memory_mutation_receipts` is
    // already bounded to two rows per receipt id by
    // UNIQUE (tenant_id, workspace_id, mutation_receipt_id, phase), which is
    // the pending/terminal pair by design; the five legal-hold and retention
    // tables carry no `mutation_receipt_id` at all and are written by
    // `aaliyah_memory_hold_officer` under a different authority entirely; and
    // the erasure witness on `memory_record_versions` is a TOMBSTONE, bounded
    // by 037's guard to versions of the tombstone's own target record below
    // its own version — one tombstone erasing every prior version of one
    // record is the requirement, not a defect.
    //
    // NOT SOLVED, SAID PLAINLY. A superuser can drop every index and trigger
    // named here. Nothing inside the database defends against its owner.
    id: "038_memory_one_authorization_one_mutation",
    sql: `CREATE UNIQUE INDEX IF NOT EXISTS memory_record_versions_receipt_unique
      ON memory_record_versions (tenant_id, workspace_id, mutation_receipt_id);
    CREATE UNIQUE INDEX IF NOT EXISTS memory_tombstones_receipt_unique
      ON memory_tombstones (tenant_id, workspace_id, mutation_receipt_id);
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_bindings_receipt_unique
      ON memory_alias_bindings (tenant_id, workspace_id, mutation_receipt_id);
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_bindings_removal_receipt_unique
      ON memory_alias_bindings
      (tenant_id, workspace_id, removed_by_mutation_receipt_id)
      WHERE removed_by_mutation_receipt_id IS NOT NULL;
    -- THE SINGLE RESOLUTION EVERY WITNESS NOW SHARES. Returning SETOF lets
    -- each guard add the dimension only it knows about — the record id, the
    -- binding digest, the action — without any of them restating the window.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_spent_nonce(
      p_tenant text, p_authorization text, p_receipt text)
      RETURNS SETOF public.memory_authorization_nonces
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
        SELECT n.*
          FROM public.memory_authorization_nonces AS n
         WHERE n.tenant_id = p_tenant
           AND n.authorization_id = p_authorization
           AND n.consumed_at IS NOT NULL
           AND n.consumed_by_mutation_receipt_id = p_receipt
           AND n.consumed_at >= n.issued_at
           AND n.consumed_at < n.expires_at;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_consumption_stamped()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL
           AND NEW.consumed_at <> pg_catalog.now() THEN
          RAISE EXCEPTION
            'aaliyah memory: consumption must be stamped with the transaction clock'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_authorization_nonces_consumption_stamped
      ON memory_authorization_nonces;
    CREATE TRIGGER memory_authorization_nonces_consumption_stamped
      BEFORE UPDATE ON memory_authorization_nonces
      FOR EACH ROW
      EXECUTE FUNCTION public.aaliyah_memory_consumption_stamped();
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_version_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        prior public.memory_record_versions%ROWTYPE;
      BEGIN
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.authorization_id,
                   NEW.mutation_receipt_id) AS n
           WHERE n.target_record_id = NEW.record_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed authorization witnesses this record version'
            USING ERRCODE = 'check_violation';
        END IF;

        SELECT * INTO prior
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.record_id
           AND v.id <> NEW.id
         ORDER BY v.version DESC
         LIMIT 1;

        IF NOT FOUND THEN
          IF NEW.version <> 1 THEN
            RAISE EXCEPTION
              'aaliyah memory: a record chain must begin at version 1'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END IF;

        IF NEW.version <> prior.version + 1 THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must be exactly one past the head'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.predecessor_digest IS DISTINCT FROM prior.content_digest THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must link to the head content digest'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.principal_id <> prior.principal_id
           OR NEW.user_id <> prior.user_id THEN
          RAISE EXCEPTION
            'aaliyah memory: a record chain may not change principal or user'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_outcome_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        committed boolean;
        attempted boolean;
      BEGIN
        -- ABORTED_NO_MUTATION and UNKNOWN_PENDING_RECONCILIATION are what an
        -- attempt that consumed nothing is REQUIRED to be able to record, so
        -- they are deliberately not gated. The two statuses below are the
        -- only ones that CLAIM a commit.
        IF NEW.outcome_status NOT IN
             ('COMMITTED_AND_READ_BACK', 'COMMITTED_READ_BACK_DIVERGED') THEN
          RETURN NULL;
        END IF;
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.authorization_id,
                   NEW.mutation_receipt_id) AS n
           WHERE n.binding_digest = NEW.consumed_nonce_digest
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed outcome requires a consumed authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_record_versions AS v
           WHERE v.tenant_id = NEW.tenant_id
             AND v.workspace_id = NEW.workspace_id
             AND v.record_id = NEW.target_record_id
             AND v.mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO committed;
        IF NOT committed THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed outcome requires the record version it claims'
            USING ERRCODE = 'check_violation';
        END IF;
        -- THE PENDING ROW THE TERMINAL ROW CONCLUDES. The pending receipt is
        -- written INSIDE the mutation transaction and always carries UNKNOWN;
        -- a terminal success with no pending predecessor describes a mutation
        -- that never announced itself, which is the shape the H-1 reproducer
        -- minted directly.
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_mutation_receipts AS r
           WHERE r.tenant_id = NEW.tenant_id
             AND r.workspace_id = NEW.workspace_id
             AND r.mutation_receipt_id = NEW.mutation_receipt_id
             AND r.phase = 'pending'
        ) INTO attempted;
        IF NOT attempted THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed outcome requires the pending receipt it concludes'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_insert_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        crossed boolean;
      BEGIN
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.authorization_id,
                   NEW.mutation_receipt_id) AS n
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: no consumed authorization witnesses this binding'
            USING ERRCODE = 'check_violation';
        END IF;
        -- The cross-column half of one-authorization-one-mutation. The two
        -- unique indexes stop N bindings or N retirements under one receipt
        -- id; this stops one receipt id from binding here and retiring there.
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_alias_bindings AS b
           WHERE b.tenant_id = NEW.tenant_id
             AND b.workspace_id = NEW.workspace_id
             AND b.removed_by_mutation_receipt_id = NEW.mutation_receipt_id
        ) INTO crossed;
        IF crossed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: this authorization has already been spent on another binding'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        crossed boolean;
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah alias registry: DELETE on % is forbidden; a binding is retired, never erased'
            , TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.removed_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: a retired alias binding is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.removed_at IS NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement is the only permitted update'
            USING ERRCODE = 'check_violation';
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id')
           IS DISTINCT FROM
           (pg_catalog.to_jsonb(OLD) - 'removed_at' - 'removed_by_mutation_receipt_id'
              - 'removed_authorization_id') THEN
          RAISE EXCEPTION
            'aaliyah alias registry: retirement may not rewrite a binding'
            USING ERRCODE = 'check_violation';
        END IF;
        -- LAST, so every check above still reports its own violation.
        -- Retirement is a mutation and needs an authorization it has spent,
        -- exactly as binding does.
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.removed_authorization_id,
                   NEW.removed_by_mutation_receipt_id) AS n
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: no consumed authorization witnesses this retirement'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1
            FROM public.memory_alias_bindings AS b
           WHERE b.tenant_id = NEW.tenant_id
             AND b.workspace_id = NEW.workspace_id
             AND b.mutation_receipt_id = NEW.removed_by_mutation_receipt_id
        ) INTO crossed;
        IF crossed THEN
          RAISE EXCEPTION
            'aaliyah alias registry: this authorization has already been spent on another binding'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_tombstone_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        offending text;
        blocking text;
        obligation timestamptz;
        head_state text;
        witnessed boolean;
      BEGIN
        IF (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(NEW.payload)) <> 18
           OR NOT (NEW.payload ?& ARRAY[
             'schemaVersion','tombstoneId','scope','targetRecordId',
             'targetVersion','tombstoneVersion','deletionAuthority','reason',
             'reasonEvidenceRef','effectiveAt','retention','retainedFieldNames',
             'destroyedFieldNames','derivedData','cacheIndexPropagation',
             'downstreamPropagation','restorationEligibility','tombstoneDigest'])
        THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone must carry exactly the contract member set'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT k INTO offending
          FROM public.aaliyah_memory_jsonb_member_names(NEW.payload) AS t(k)
         WHERE pg_catalog.lower(k) IN ('content','payload','value','body','text',
                                       'note','data','plaintext','secret')
         LIMIT 1;
        IF offending IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone may not carry a payload-bearing member'
            USING ERRCODE = 'check_violation';
        END IF;
        IF public.aaliyah_memory_first_free_text(NEW.payload) IS NOT NULL THEN
          -- The VALUE is deliberately absent: see migration 033, M-4.
          RAISE EXCEPTION
            'aaliyah memory: a tombstone may not carry free-form text'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT v.state INTO head_state
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.target_record_id
           AND v.version = NEW.tombstone_version
         LIMIT 1;
        IF head_state IS DISTINCT FROM 'deleted' THEN
          RAISE EXCEPTION
            'aaliyah memory: a tombstone must name a deleted version of its target record'
            USING ERRCODE = 'check_violation';
        END IF;
        blocking := public.aaliyah_memory_restricting_hold(
          NEW.tenant_id, NEW.workspace_id, NEW.target_record_id, NULL, 'delete');
        IF blocking IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: legal hold % restricts delete on this record'
            , blocking
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT pg_catalog.max(o.retain_until) INTO obligation
          FROM public.memory_retention_obligations AS o
         WHERE o.tenant_id = NEW.tenant_id
           AND o.workspace_id = NEW.workspace_id
           AND o.record_id = NEW.target_record_id
           AND o.retain_until > pg_catalog.now();
        IF obligation IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: an unexpired retention obligation forbids destroying this record'
            USING ERRCODE = 'check_violation';
        END IF;
        -- LAST, so every violation above still reports its own message. The
        -- tombstone's authorization columns were pure decoration until here:
        -- nothing checked that the destruction it accounts for was ever
        -- approved, or approved as a DELETE.
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.authorization_id,
                   NEW.mutation_receipt_id) AS n
           WHERE n.target_record_id = NEW.target_record_id
             AND n.action = 'delete'
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed delete authorization witnesses this tombstone'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$`,
  },
  {
    // ------------------------------------------------------------------
    // GENESIS HAS AN OWNER, AND THE DATABASE IS WHAT SAYS SO.
    //
    // Found by an independent security review of the `create` operation and
    // reproduced on a live PostgreSQL 16 using the least-privilege
    // `aaliyah_memory_mutator` role — the role the store itself runs as.
    //
    // Migration 034 pins ownership CONTINUITY: version N+1 may not change
    // principal or user from version N. That check sits on the path taken
    // when a prior version is found, so version 1 never reaches it. The
    // witness — `aaliyah_memory_spent_nonce` plus the record id the guard
    // adds — resolves on tenant, authorization and receipt, and says nothing
    // about workspace, principal or user.
    //
    // The consequence, executed: a holder of the mutation role and ONE
    // legitimately issued `create` authorization for its OWN scope spends
    // that authorization and writes version 1 under somebody else's
    // principal and user, in a different workspace. The victim's own
    // `retrieve` then hands back attacker-chosen content as the victim's
    // record, and an ordinary protocol `correct()` over it succeeds, so the
    // forged root becomes an indistinguishable, digest-linked, receipted
    // chain. The identical forgery at version 2 is refused by 034.
    //
    // Every other ownership control in this module has a database twin,
    // explicitly for writers that never come through the store. Genesis had
    // only the application-side argument that the owner of a genesis IS the
    // authorization's scope. This is what makes that sentence enforceable.
    //
    // Read from `memory_authorization_receipts`, which already carries all
    // four dimensions NOT NULL, so this needs no new column and no change to
    // what an issuer writes.
    // ------------------------------------------------------------------
    id: "039_memory_genesis_owner_binding",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_version_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        witnessed boolean;
        prior public.memory_record_versions%ROWTYPE;
      BEGIN
        SELECT EXISTS (
          SELECT 1
            FROM public.aaliyah_memory_spent_nonce(
                   NEW.tenant_id, NEW.authorization_id,
                   NEW.mutation_receipt_id) AS n
           WHERE n.target_record_id = NEW.record_id
        ) INTO witnessed;
        IF NOT witnessed THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed authorization witnesses this record version'
            USING ERRCODE = 'check_violation';
        END IF;

        SELECT * INTO prior
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.record_id
           AND v.id <> NEW.id
         ORDER BY v.version DESC
         LIMIT 1;

        IF NOT FOUND THEN
          IF NEW.version <> 1 THEN
            RAISE EXCEPTION
              'aaliyah memory: a record chain must begin at version 1'
              USING ERRCODE = 'check_violation';
          END IF;
          -- THE GENESIS OWNER IS THE AUTHORIZATION'S OWNER. All four
          -- dimensions in one predicate: a partial match is a mismatch, and
          -- splitting them here would only produce three ways to say the
          -- same refusal.
          PERFORM 1
            FROM public.memory_authorization_receipts AS a
           WHERE a.authorization_id = NEW.authorization_id
             AND a.tenant_id = NEW.tenant_id
             AND a.workspace_id = NEW.workspace_id
             AND a.principal_id = NEW.principal_id
             AND a.user_id = NEW.user_id;
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a record chain must begin under the scope its authorization names'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END IF;

        IF NEW.version <> prior.version + 1 THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must be exactly one past the head'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.predecessor_digest IS DISTINCT FROM prior.content_digest THEN
          RAISE EXCEPTION
            'aaliyah memory: a record version must link to the head content digest'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.principal_id <> prior.principal_id
           OR NEW.user_id <> prior.user_id THEN
          RAISE EXCEPTION
            'aaliyah memory: a record chain may not change principal or user'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$`,
  },
  {
    // ------------------------------------------------------------------
    // RECONCILIATION IS A SEPARATE ARTEFACT, BECAUSE A RECEIPT CANNOT BE
    // REWRITTEN.
    //
    // `memory_mutation_receipts` is UNIQUE on
    // (tenant, workspace, mutation_receipt_id, phase) and carries an
    // append-only trigger. Once a mutation has emitted its terminal
    // UNKNOWN_PENDING_RECONCILIATION row, there is no second terminal row to
    // append and no UPDATE to perform. That is deliberate — a receipt that
    // could be revised is not evidence — and it is why reconciliation records
    // its verdict HERE instead. The contract already points at this artefact:
    // every unknown outcome carries a `reconciliationRef`.
    //
    // WHAT MAKES THE VERDICT DETERMINATE. The pending receipt is written on
    // the mutation's own transaction, immediately before COMMIT. So a durable
    // pending row is itself proof the transaction committed, and its absence
    // is proof the transaction did not. Reconciliation is therefore a reading
    // of authoritative state, never an inference from timing or a retry that
    // hopes to observe the same thing twice.
    //
    // THE RECONCILER CANNOT MUTATE, AND THAT IS ENFORCED RATHER THAN
    // PROMISED. `aaliyah_memory_reconciler` is granted SELECT on the evidence
    // tables and INSERT on this one. It holds no INSERT on
    // memory_record_versions, no INSERT on memory_mutation_receipts, and no
    // UPDATE on the nonce or receipt consumption columns. "Reconciliation
    // never produces a duplicate mutation" is thus a privilege, not a comment:
    // a reconciler that tried would be refused by PostgreSQL.
    //
    // UNIQUE (tenant, workspace, mutation_receipt_id) is what makes retries
    // idempotent — a second reconciliation of the same mutation is refused by
    // the database, so a duplicate worker, a restarted worker and a stale
    // worker all converge on one verdict instead of three.
    // ------------------------------------------------------------------
    id: "040_memory_reconciliation",
    sql: `CREATE TABLE IF NOT EXISTS memory_reconciliations (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      authorization_id text NOT NULL,
      action text NOT NULL,
      target_record_id text NOT NULL,
      verdict text NOT NULL,
      observed_version integer,
      observed_content_digest text,
      reconciled_at timestamptz NOT NULL,
      evidence jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_reconciliations_once
        UNIQUE (tenant_id, workspace_id, mutation_receipt_id),
      CONSTRAINT memory_reconciliations_verdict_domain CHECK (
        verdict IN ('COMMITTED_CONFIRMED','COMMITTED_DIVERGED',
                    'NOT_COMMITTED','IMPOSSIBLE_STATE')),
      -- A committed verdict MUST name what it observed. A verdict of
      -- "committed" with nothing observed is the ambiguity it claims to have
      -- resolved, wearing a resolved label.
      CONSTRAINT memory_reconciliations_committed_observes CHECK (
        (verdict IN ('COMMITTED_CONFIRMED','COMMITTED_DIVERGED'))
          = (observed_version IS NOT NULL AND observed_content_digest IS NOT NULL)),
      -- And a NOT_COMMITTED verdict must observe NOTHING, so the two cannot
      -- be filed with the same evidence.
      CONSTRAINT memory_reconciliations_not_committed_observes_nothing CHECK (
        verdict <> 'NOT_COMMITTED'
          OR (observed_version IS NULL AND observed_content_digest IS NULL)),
      CONSTRAINT memory_reconciliations_evidence_object CHECK (
        jsonb_typeof(evidence) = 'object'),
      CONSTRAINT memory_reconciliations_receipt_binding CHECK (
        evidence ->> 'mutationReceiptId' = mutation_receipt_id),
      CONSTRAINT memory_reconciliations_authorization_binding CHECK (
        evidence ->> 'authorizationId' = authorization_id)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_reconciliations_target
      ON memory_reconciliations (tenant_id, workspace_id, target_record_id, id DESC);
    DROP TRIGGER IF EXISTS memory_reconciliations_append_only
      ON memory_reconciliations;
    CREATE TRIGGER memory_reconciliations_append_only
      BEFORE UPDATE OR DELETE ON memory_reconciliations
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();
    DO $do$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_reconciler') THEN
          CREATE ROLE aaliyah_memory_reconciler NOLOGIN;
        END IF;
      END
      $do$;
    GRANT SELECT ON
      memory_record_versions,
      memory_authorization_receipts,
      memory_authorization_nonces,
      memory_mutation_receipts,
      memory_reconciliations
      TO aaliyah_memory_reconciler;
    GRANT INSERT ON memory_reconciliations TO aaliyah_memory_reconciler;
    GRANT USAGE, SELECT ON SEQUENCE memory_reconciliations_id_seq
      TO aaliyah_memory_reconciler;
    GRANT SELECT ON memory_reconciliations
      TO aaliyah_memory_reader, aaliyah_memory_mutator`,
  },
  {
    // ------------------------------------------------------------------
    // THE IDENTITY GRAPH, AND WHY IT IS A SEPARATE TABLE.
    //
    // A merge or a split re-shapes which records are which people. Neither can
    // append a version to BOTH records involved, because one authorization
    // produces exactly one record version and that is enforced three times
    // over: `memory_authorization_nonces` is UNIQUE on `authorization_id`, a
    // nonce carries one `consumed_by_mutation_receipt_id`, and migration 038
    // makes `(tenant, workspace, mutation_receipt_id)` unique on
    // `memory_record_versions`. That triple IS the H-1 fix, and an identity
    // operation is not a reason to weaken it.
    //
    // So the graph change lives here. One version on the record the
    // authorization targets, one edge, one transaction.
    //
    // THE EDGE CARRIES THE SAME WITNESS EVERY OTHER MUTATION CARRIES. Without
    // it, this table would be the one place a writer could re-shape the
    // identity graph with no consumed authorization behind it — the exact hole
    // migration 034 closed for record versions and 038 closed for tombstones
    // and alias bindings.
    //
    // A MERGED-AWAY RECORD IS FROZEN, NOT DELETED. Appending to a record that
    // has been merged into another is editing a ghost, so the guard refuses
    // it. It is not destroyed: a merge is not a deletion and must not become a
    // quiet one, and the absorbed record's history stays readable.
    // ------------------------------------------------------------------
    id: "041_memory_identity_graph",
    sql: `CREATE TABLE IF NOT EXISTS memory_identity_edges (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      kind text NOT NULL,
      from_record_id text NOT NULL,
      to_record_id text NOT NULL,
      from_version integer NOT NULL,
      authorization_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      reason text NOT NULL,
      reason_evidence_ref text NOT NULL,
      effective_at timestamptz NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_identity_edges_kind_domain
        CHECK (kind IN ('merged_into','split_to')),
      -- A record cannot be merged into, or split from, ITSELF. Without this a
      -- self-edge would freeze a record against every future mutation while
      -- reading as a legitimate graph entry.
      CONSTRAINT memory_identity_edges_not_self
        CHECK (from_record_id <> to_record_id),
      CONSTRAINT memory_identity_edges_version_positive
        CHECK (from_version > 0),
      -- One edge per mutation, the same shape migration 038 gives every other
      -- mutating table.
      CONSTRAINT memory_identity_edges_receipt_unique
        UNIQUE (tenant_id, workspace_id, mutation_receipt_id),
      CONSTRAINT memory_identity_edges_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_identity_edges_kind_binding
        CHECK (payload ->> 'kind' = kind),
      CONSTRAINT memory_identity_edges_from_binding
        CHECK (payload ->> 'fromRecordId' = from_record_id),
      CONSTRAINT memory_identity_edges_to_binding
        CHECK (payload ->> 'toRecordId' = to_record_id),
      CONSTRAINT memory_identity_edges_authorization_binding
        CHECK (payload ->> 'authorizationId' = authorization_id)
    );
    -- A record may be merged away AT MOST ONCE. Two survivors for one absorbed
    -- record is a graph that cannot be read, and it is how an identity ends up
    -- pointing two ways at once.
    CREATE UNIQUE INDEX IF NOT EXISTS memory_identity_edges_merged_once
      ON memory_identity_edges (tenant_id, workspace_id, from_record_id)
      WHERE kind = 'merged_into';
    CREATE INDEX IF NOT EXISTS idx_memory_identity_edges_to
      ON memory_identity_edges (tenant_id, workspace_id, to_record_id, id DESC);
    DROP TRIGGER IF EXISTS memory_identity_edges_append_only
      ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_append_only
      BEFORE UPDATE OR DELETE ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_identity_edges_exact_numbers
      ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_reject_inexact_numbers();

    -- EVERY EDGE IS WITNESSED BY A CONSUMED AUTHORIZATION, and the action that
    -- authorization was issued for must be the one this edge records.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_identity_edge_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
      BEGIN
        SELECT n.action INTO acted
          FROM public.aaliyah_memory_spent_nonce(
                 NEW.tenant_id, NEW.authorization_id,
                 NEW.mutation_receipt_id) AS n
         WHERE n.target_record_id = NEW.from_record_id
         LIMIT 1;
        IF acted IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed authorization witnesses this identity edge'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.kind = 'merged_into' AND acted <> 'merge_identity' THEN
          RAISE EXCEPTION
            'aaliyah memory: a merge edge requires a merge_identity authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.kind = 'split_to' AND acted <> 'split_identity' THEN
          RAISE EXCEPTION
            'aaliyah memory: a split edge requires a split_identity authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        -- BOTH ENDS MUST EXIST, IN THIS SCOPE. An edge naming a record that is
        -- not there re-shapes the graph around something unreadable, and an
        -- edge reaching into another principal's records is a graph-level
        -- version of the takeover migration 039 closed for genesis.
        PERFORM 1 FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.principal_id = NEW.principal_id
           AND v.user_id = NEW.user_id
           AND v.record_id = NEW.to_record_id
         LIMIT 1;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: an identity edge must name a record in the same scope'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_identity_edges_authorized
      ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_authorized
      AFTER INSERT ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_identity_edge_guard();

    -- A MERGED-AWAY RECORD ACCEPTS NO FURTHER VERSIONS.
    --
    -- Layered as its own AFTER INSERT trigger rather than folded into
    -- aaliyah_memory_record_version_guard, so migration 039's genesis
    -- binding and this freeze are independently killable by their own tests.
    -- Fires after the row, before the edge that the merge itself writes later
    -- in the same transaction, so a merge does not refuse its own version.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_merged_record_frozen()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        PERFORM 1 FROM public.memory_identity_edges AS e
         WHERE e.tenant_id = NEW.tenant_id
           AND e.workspace_id = NEW.workspace_id
           AND e.from_record_id = NEW.record_id
           AND e.kind = 'merged_into'
         LIMIT 1;
        IF FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a record merged into another accepts no further versions'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_record_versions_merged_frozen
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_merged_frozen
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_merged_record_frozen();

    GRANT SELECT ON memory_identity_edges
      TO aaliyah_memory_mutator, aaliyah_memory_reader,
         aaliyah_memory_issuer, aaliyah_memory_revoker,
         aaliyah_memory_reconciler;
    GRANT INSERT ON memory_identity_edges TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE memory_identity_edges_id_seq
      TO aaliyah_memory_mutator`,
  },
  {
    // ------------------------------------------------------------------
    // A MERGE MAY NOT POINT AT A RECORD THAT WAS ITSELF MERGED AWAY.
    //
    // Found while building the read-time canonical resolver, not by a test.
    // Migration 041 refuses a SECOND outgoing merge from one record, and it
    // freezes a record once it has been absorbed. Neither stops an edge
    // pointing INTO an absorbed record.
    //
    // Two consequences, both real. A merge into a ghost: the survivor named is
    // a record that no longer accepts mutations, so the identity resolves to
    // something already superseded. And a CYCLE: A merged into B, then B
    // merged into A. B is not frozen by its own outgoing edge, and A's head
    // state is still active — a merge freezes, it does not delete — so every
    // check in 041 passes and the graph closes a loop. A resolver walking that
    // graph never terminates.
    //
    // The resolver carries its own depth bound regardless, because a guard and
    // a bounded walk protect against different failures: this stops the cycle
    // being CREATED, the bound stops an existing one hanging a reader.
    // ------------------------------------------------------------------
    id: "042_memory_identity_no_merge_into_absorbed",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_identity_edge_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
      BEGIN
        SELECT n.action INTO acted
          FROM public.aaliyah_memory_spent_nonce(
                 NEW.tenant_id, NEW.authorization_id,
                 NEW.mutation_receipt_id) AS n
         WHERE n.target_record_id = NEW.from_record_id
         LIMIT 1;
        IF acted IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: no consumed authorization witnesses this identity edge'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.kind = 'merged_into' AND acted <> 'merge_identity' THEN
          RAISE EXCEPTION
            'aaliyah memory: a merge edge requires a merge_identity authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.kind = 'split_to' AND acted <> 'split_identity' THEN
          RAISE EXCEPTION
            'aaliyah memory: a split edge requires a split_identity authorization'
            USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1 FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.principal_id = NEW.principal_id
           AND v.user_id = NEW.user_id
           AND v.record_id = NEW.to_record_id
         LIMIT 1;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: an identity edge must name a record in the same scope'
            USING ERRCODE = 'check_violation';
        END IF;
        -- THE NEW PART. Only for merges: a split_to edge may legitimately name
        -- a record that is later absorbed, because a split records history
        -- rather than a redirect.
        IF NEW.kind = 'merged_into' THEN
          PERFORM 1 FROM public.memory_identity_edges AS e
           WHERE e.tenant_id = NEW.tenant_id
             AND e.workspace_id = NEW.workspace_id
             AND e.from_record_id = NEW.to_record_id
             AND e.kind = 'merged_into'
           LIMIT 1;
          IF FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a merge may not name a record that was itself merged away'
              USING ERRCODE = 'check_violation';
          END IF;
        END IF;
        RETURN NULL;
      END;
      $fn$`,
  },
];

/**
 * The numeric prefix of a migration id, as a number.
 *
 * Parsed rather than compared as text so a malformed id fails LOUDLY here
 * instead of sorting somewhere arbitrary and making the ordering check answer
 * confidently about nothing.
 */
function migrationOrdinal(id: string): number {
  const match = /^(\d{3})_/.exec(id);
  if (match === null) {
    throw new Error(`migration id ${id} does not begin with a three-digit ordinal`);
  }
  return Number(match[1]);
}

export async function runMailMigrations(pool: Pool): Promise<void> {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (
      id text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`,
  );
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Serialize concurrent migrators.
    await client.query("LOCK TABLE aaliyah_mail_migrations IN ACCESS EXCLUSIVE MODE");
    const applied = new Set(
      (await client.query("SELECT id FROM aaliyah_mail_migrations")).rows.map(
        (r: { id: string }) => r.id,
      ),
    );
    // ---- MIGRATIONS ARE NOT INDEPENDENTLY REPLAYABLE (W1BR-014) ----------
    //
    // Several migrations use CREATE OR REPLACE to HARDEN a definition an
    // earlier one introduced: 033 redefines the numeric-domain helpers
    // schema-qualified with a pinned `search_path`, where 027 defined them
    // unqualified. Replaying 027 after 033 therefore silently reverts that
    // hardening, and the only symptom is a search-path shadowing test going
    // red somewhere else entirely. Encountered exactly that way.
    //
    // The runner already skips applied ids, so this cannot happen on an
    // ordinary upgrade. It happens when a row is deleted and the runner is
    // re-run, when tooling replays by id, or after a partial restore — and in
    // every one of those cases the operator believes they are repairing
    // something. Refusing is the only safe answer: applying an older
    // definition over a newer one is not a repair.
    const highestApplied = [...applied]
      .map(migrationOrdinal)
      .reduce((high, ordinal) => (ordinal > high ? ordinal : high), -1);
    for (const migration of MIGRATIONS) {
      if (applied.has(migration.id)) continue;
      const ordinal = migrationOrdinal(migration.id);
      if (ordinal < highestApplied) {
        throw new Error(
          `migration ${migration.id} is older than migration ordinal ` +
            `${highestApplied}, which is already applied. Replaying it would ` +
            `revert any definition a later migration hardened. Refusing.`,
        );
      }
      await client.query(migration.sql);
      await client.query("INSERT INTO aaliyah_mail_migrations (id) VALUES ($1)", [migration.id]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
