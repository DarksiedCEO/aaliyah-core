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
];

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
    for (const migration of MIGRATIONS) {
      if (applied.has(migration.id)) continue;
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
