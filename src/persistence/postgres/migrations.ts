import * as crypto from "node:crypto";
import type { Pool } from "pg";
import {
  boundedQuery,
  isConnectionAmbiguous,
  MIGRATION_BOUNDS,
  releaseClient,
  type BoundedQuery,
} from "./pool";

/**
 * The digest of a migration's SQL, as the ledger records it.
 *
 * Over the SQL text exactly as this build carries it. That is the thing whose
 * change the integration review of 86d33c9 showed was undetectable: the ledger
 * held an id and nothing else, so an edited migration re-ran as a no-op and
 * reported success with the old definition still live.
 */
function migrationDigest(sql: string): string {
  return `sha256:${crypto.createHash("sha256").update(sql, "utf8").digest("hex")}`;
}

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
  {
    // ------------------------------------------------------------------
    // AN IDENTITY CHANGE IS SERIALIZED ON BOTH RECORDS IT TOUCHES.
    //
    // Falsified against b3efc82 by the red team, twice, with one root cause.
    // The store took its advisory lock on the FROM record only, and both the
    // store's checks and migration 042's trigger read the COUNTERPARTY
    // unlocked, under READ COMMITTED:
    //
    //   - `merge A->B` and `merge B->A`, each with its own valid authorization,
    //     fired together: a CYCLE on trial 1 of 25. Both records frozen, both
    //     identities unresolvable, and no repair path (`split_identity` is
    //     refused `record_merged_away`). W1BR-015 had been recorded CLOSED.
    //   - `merge A->B` and `delete B`: both committed. A redirected to a
    //     destroyed record, and every alias pointing at A resolved to nothing.
    //
    // The store now locks both records in a fixed order. THIS migration makes
    // the same serialization a property of the database, for writers that
    // never come through the store:
    //
    //   - the identity-edge guard takes the advisory lock of BOTH endpoints,
    //     in sorted key order, BEFORE it reads either, using the same key the
    //     store uses (tenant, workspace, record joined by U+001F). A PL/pgSQL
    //     statement after the lock takes a fresh snapshot, so it sees what the
    //     transaction it waited for committed;
    //   - the merged-away freeze on record versions takes the record's lock
    //     before it reads the graph, so a version racing an edge waits for it;
    //   - the counterparty must not merely EXIST: its head must be ACTIVE. An
    //     edge into a record whose head is `deleted` is an edge into nothing.
    // ------------------------------------------------------------------
    id: "043_memory_identity_serialized",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_lock(
        p_tenant text, p_workspace text, p_record text)
      RETURNS void
      LANGUAGE sql
      SET search_path = pg_catalog, public
      AS $fn$
        SELECT pg_advisory_xact_lock(
          hashtextextended(concat_ws(chr(31), p_tenant, p_workspace, p_record), 0));
      $fn$;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_identity_edge_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        acted text;
        to_state text;
      BEGIN
        -- BOTH ENDS, SORTED, BEFORE ANY READ. Sorted so two writers locking
        -- the same pair from opposite directions cannot deadlock on order.
        -- COLLATE "C" is byte order, which is the order the store's
        -- JavaScript sort produces for these ids. The database's default
        -- collation is not, and two different orders is a deadlock waiting.
        IF concat_ws(chr(31), NEW.tenant_id, NEW.workspace_id, NEW.from_record_id) COLLATE "C"
           < concat_ws(chr(31), NEW.tenant_id, NEW.workspace_id, NEW.to_record_id) COLLATE "C" THEN
          PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.from_record_id);
          PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.to_record_id);
        ELSE
          PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.to_record_id);
          PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.from_record_id);
        END IF;

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
        SELECT v.state INTO to_state
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.principal_id = NEW.principal_id
           AND v.user_id = NEW.user_id
           AND v.record_id = NEW.to_record_id
         ORDER BY v.version DESC
         LIMIT 1;
        IF to_state IS NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: an identity edge must name a record in the same scope'
            USING ERRCODE = 'check_violation';
        END IF;
        IF to_state <> 'active' THEN
          RAISE EXCEPTION
            'aaliyah memory: an identity edge may not name a record whose head is not active'
            USING ERRCODE = 'check_violation';
        END IF;
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
      $fn$;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_merged_record_frozen()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        -- The record's lock first, so a version racing a merge edge on this
        -- record waits for that edge's transaction and then sees it.
        PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.record_id);
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
      $fn$`,
  },
  {
    // ------------------------------------------------------------------
    // EVERY MUTATED ROW CARRIES THE SCOPE OF THE AUTHORIZATION THAT
    // WITNESSES IT.
    //
    // Found by the b3efc82 security review. Migration 041's comment, and the
    // store, claimed the identity-edge trigger "carries the same rule for
    // writers that never come through here" as migration 039's genesis owner
    // binding. It did not: the edge guard checked that the TO record existed
    // under the edge's CLAIMED principal, user and workspace, and never that
    // the claim was the authorization's. The witness a guard resolves
    // (`aaliyah_memory_spent_nonce`) carries tenant, authorization, receipt and
    // target — no principal, user or workspace. Executed as
    // `aaliyah_memory_mutator`:
    //
    //   - holding ONE merge authorization issued for its OWN scope and its OWN
    //     record, the attacker filed an identity edge under the VICTIM's
    //     principal, user and workspace — accepted;
    //   - with a merge authorization naming a foreign record (nothing in the
    //     database constrains a receipt's target to its scope), it planted an
    //     edge that redirected the victim's canonical-identity reads and froze
    //     the victim's own record against the victim's own corrections.
    //
    // The same gap is wider than edges. Migration 039 bound GENESIS to the
    // receipt's scope and left every later version bound only by continuity
    // with its predecessor — so a foreign-target authorization could append to
    // somebody else's chain under THEIR principal, and continuity would agree.
    //
    // So the rule is stated once, and attached to every table a mutation
    // writes: the row's (tenant, workspace, principal, user) must be exactly
    // the scope of the `memory_authorization_receipts` row its authorization
    // id resolves to. Separate triggers per table, so each is independently
    // killable by its own test.
    //
    // NAMED "_zz_" ON PURPOSE. PostgreSQL fires triggers of the same timing
    // in NAME order. These fire LAST, after every older guard on the table,
    // so each older guard still refuses its own case with its own message —
    // a scope refusal that pre-empted them would leave those guards with no
    // reachable input and no killing test.
    //
    // And an identity edge's FROM record must belong to the edge's owner: an
    // authorization scoped to one principal, naming another principal's
    // record, witnesses nothing about that record.
    // ------------------------------------------------------------------
    id: "044_memory_authorization_scope_binding",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_row_in_authorization_scope()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        PERFORM 1
          FROM public.memory_authorization_receipts AS a
         WHERE a.tenant_id = NEW.tenant_id
           AND a.authorization_id = NEW.authorization_id
           AND a.workspace_id = NEW.workspace_id
           AND a.principal_id = NEW.principal_id
           AND a.user_id = NEW.user_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a % row must carry the scope of the authorization that witnesses it',
            TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;

    DROP TRIGGER IF EXISTS memory_record_versions_zz_authorization_scope
      ON memory_record_versions;
    CREATE TRIGGER memory_record_versions_zz_authorization_scope
      AFTER INSERT ON memory_record_versions
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_row_in_authorization_scope();

    DROP TRIGGER IF EXISTS memory_identity_edges_zz_authorization_scope
      ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_zz_authorization_scope
      AFTER INSERT ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_row_in_authorization_scope();

    DROP TRIGGER IF EXISTS memory_tombstones_zz_authorization_scope
      ON memory_tombstones;
    CREATE TRIGGER memory_tombstones_zz_authorization_scope
      AFTER INSERT ON memory_tombstones
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_row_in_authorization_scope();

    DROP TRIGGER IF EXISTS memory_alias_bindings_zz_authorization_scope
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_zz_authorization_scope
      AFTER INSERT ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_row_in_authorization_scope();

    -- Retiring a binding is authorized separately, by removed_authorization_id.
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_removal_in_authorization_scope()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF NEW.removed_authorization_id IS NULL
           OR NEW.removed_authorization_id IS NOT DISTINCT FROM OLD.removed_authorization_id THEN
          RETURN NULL;
        END IF;
        PERFORM 1
          FROM public.memory_authorization_receipts AS a
         WHERE a.tenant_id = NEW.tenant_id
           AND a.authorization_id = NEW.removed_authorization_id
           AND a.workspace_id = NEW.workspace_id
           AND a.principal_id = NEW.principal_id
           AND a.user_id = NEW.user_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a binding may only be retired under the scope of the authorization that retires it'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_removal_authorization_scope
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_removal_authorization_scope
      AFTER UPDATE OF removed_authorization_id ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_removal_in_authorization_scope();

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_identity_edge_from_owner()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        owner_principal text;
        owner_user text;
      BEGIN
        SELECT v.principal_id, v.user_id INTO owner_principal, owner_user
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.from_record_id
         ORDER BY v.version DESC
         LIMIT 1;
        IF owner_principal IS NULL
           OR owner_principal <> NEW.principal_id
           OR owner_user <> NEW.user_id THEN
          RAISE EXCEPTION
            'aaliyah memory: an identity edge may only leave a record its owner holds'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_identity_edges_from_owner
      ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_from_owner
      AFTER INSERT ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_identity_edge_from_owner()`,
  },
  {
    // ------------------------------------------------------------------
    // AN ATTEMPT IS NOT A MUTATION RECEIPT, AND A RECONCILIATION IS NOT AN
    // OPINION.
    //
    // Red team BREAK 1 against b3efc82. Aborted and unresolved attempts were
    // filed in `memory_mutation_receipts` as TERMINAL rows under the caller's
    // `mutation_receipt_id`, and that table is UNIQUE on (tenant, workspace,
    // mutation_receipt_id, phase). So:
    //
    //   attempt 1 (stale head)  -> terminal ABORTED_NO_MUTATION
    //   attempt 2 (same id)     -> commits, reads back, AGREES — then its own
    //                              terminal row collides, the failure is
    //                              swallowed, and it reports UNKNOWN
    //   the reconciler          -> skips it forever: a terminal non-UNKNOWN
    //                              sibling exists, and it is the ABORTED one
    //
    // No attacker needed — that is the ordinary retry W1BR-004 asks callers
    // to implement. With one, a principal holding NO authorization planted the
    // ABORTED row under an id a victim later used, and the victim's genuine
    // genesis was durably filed as never having happened.
    //
    // Security MEDIUM against b3efc82: a reconciler-role writer filed
    // COMMITTED_CONFIRMED for a mutation with no record version at all, and the
    // database accepted it — the "committed" verdict was enforced only in the
    // reconciler's control flow. And the reconciler derived its verdict from a
    // CALLER-supplied authorization id (red team M2).
    //
    // This migration:
    //   - gives attempts their own append-only table, with no uniqueness on the
    //     receipt id: two failed attempts are two facts;
    //   - refuses ABORTED_NO_MUTATION in memory_mutation_receipts outright;
    //   - refuses a PENDING receipt for an id that already has a TERMINAL one
    //     (the id is spent), and a TERMINAL receipt that disagrees with the
    //     pending receipt of the same id about who, what, or under which
    //     authorization;
    //   - binds memory_mutation_receipts rows to their authorization's scope,
    //     as 044 does for every other table a mutation writes;
    //   - makes every reconciliation verdict DERIVABLE from stored state, in
    //     the database: it must answer an UNKNOWN receipt that exists, agree
    //     with it on authorization, action, target and scope, and its verdict
    //     must be exactly the one the pending receipt, the record version and
    //     the authorized digest imply.
    // ------------------------------------------------------------------
    id: "045_memory_attempts_and_derivable_reconciliation",
    sql: `CREATE TABLE IF NOT EXISTS memory_mutation_attempts (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      principal_id text NOT NULL,
      user_id text NOT NULL,
      mutation_receipt_id text NOT NULL,
      authorization_id text NOT NULL,
      action text NOT NULL,
      target_record_id text NOT NULL,
      rejection text NOT NULL,
      abort_reason text NOT NULL,
      attempted_at timestamptz NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_mutation_attempts_action_domain CHECK (action IN (
        'create','correct','delete','restore','promote',
        'assign_alias','remove_alias','merge_identity','split_identity')),
      CONSTRAINT memory_mutation_attempts_abort_reason_domain CHECK (abort_reason IN (
        'authorization_expired','authorization_revoked',
        'authorization_already_consumed','head_mismatch','legal_hold_active',
        'policy_rejected','storage_rejected')),
      CONSTRAINT memory_mutation_attempts_rejection_form
        CHECK (rejection ~ '^[a-z][a-z_]{2,63}$'),
      CONSTRAINT memory_mutation_attempts_payload_object
        CHECK (jsonb_typeof(payload) = 'object'),
      CONSTRAINT memory_mutation_attempts_status_is_aborted
        CHECK (payload->'outcome'->>'status' IS NOT NULL
               AND payload->'outcome'->>'status' = 'ABORTED_NO_MUTATION'),
      CONSTRAINT memory_mutation_attempts_receipt_binding
        CHECK (payload->>'mutationReceiptId' IS NOT NULL
               AND payload->>'mutationReceiptId' = mutation_receipt_id),
      CONSTRAINT memory_mutation_attempts_authorization_binding
        CHECK (payload->>'authorizationId' IS NOT NULL
               AND payload->>'authorizationId' = authorization_id),
      CONSTRAINT memory_mutation_attempts_action_binding
        CHECK (payload->>'action' IS NOT NULL AND payload->>'action' = action),
      CONSTRAINT memory_mutation_attempts_target_binding
        CHECK (payload->>'targetRecordId' IS NOT NULL
               AND payload->>'targetRecordId' = target_record_id),
      CONSTRAINT memory_mutation_attempts_scope_binding
        CHECK (payload->'scope'->>'tenantId' IS NOT NULL
               AND payload->'scope'->>'tenantId' = tenant_id
               AND payload->'scope'->>'workspaceId' IS NOT NULL
               AND payload->'scope'->>'workspaceId' = workspace_id
               AND payload->'scope'->>'principalId' IS NOT NULL
               AND payload->'scope'->>'principalId' = principal_id
               AND payload->'scope'->>'userId' IS NOT NULL
               AND payload->'scope'->>'userId' = user_id),
      CONSTRAINT memory_mutation_attempts_abort_reason_binding
        CHECK (payload->'outcome'->>'abortReason' IS NOT NULL
               AND payload->'outcome'->>'abortReason' = abort_reason)
    );
    CREATE INDEX IF NOT EXISTS idx_memory_mutation_attempts_receipt
      ON memory_mutation_attempts (tenant_id, workspace_id, mutation_receipt_id, id);
    CREATE INDEX IF NOT EXISTS idx_memory_mutation_attempts_actor
      ON memory_mutation_attempts (tenant_id, workspace_id, principal_id, user_id, id DESC);
    DROP TRIGGER IF EXISTS memory_mutation_attempts_append_only
      ON memory_mutation_attempts;
    CREATE TRIGGER memory_mutation_attempts_append_only
      BEFORE UPDATE OR DELETE ON memory_mutation_attempts
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();
    DROP TRIGGER IF EXISTS memory_mutation_attempts_exact_numbers
      ON memory_mutation_attempts;
    CREATE TRIGGER memory_mutation_attempts_exact_numbers
      BEFORE INSERT OR UPDATE ON memory_mutation_attempts
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_reject_inexact_numbers();
    GRANT SELECT, INSERT ON memory_mutation_attempts TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE memory_mutation_attempts_id_seq
      TO aaliyah_memory_mutator;
    GRANT SELECT ON memory_mutation_attempts
      TO aaliyah_memory_reader, aaliyah_memory_reconciler;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_receipt_id_discipline()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        pending public.memory_mutation_receipts%ROWTYPE;
      BEGIN
        IF NEW.outcome_status = 'ABORTED_NO_MUTATION' THEN
          RAISE EXCEPTION
            'aaliyah memory: an aborted attempt is not a mutation receipt; it belongs in memory_mutation_attempts'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.phase = 'pending' THEN
          PERFORM 1 FROM public.memory_mutation_receipts AS t
           WHERE t.tenant_id = NEW.tenant_id
             AND t.workspace_id = NEW.workspace_id
             AND t.mutation_receipt_id = NEW.mutation_receipt_id
             AND t.phase = 'terminal'
             AND t.id <> NEW.id
           LIMIT 1;
          IF FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a mutation receipt id that already carries a terminal receipt cannot begin another mutation'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END IF;
        SELECT * INTO pending FROM public.memory_mutation_receipts AS p
         WHERE p.tenant_id = NEW.tenant_id
           AND p.workspace_id = NEW.workspace_id
           AND p.mutation_receipt_id = NEW.mutation_receipt_id
           AND p.phase = 'pending'
         LIMIT 1;
        IF FOUND AND (pending.principal_id <> NEW.principal_id
                      OR pending.user_id <> NEW.user_id
                      OR pending.authorization_id <> NEW.authorization_id
                      OR pending.action <> NEW.action
                      OR pending.target_record_id <> NEW.target_record_id) THEN
          RAISE EXCEPTION
            'aaliyah memory: a terminal receipt must describe the same mutation as its pending receipt'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_mutation_receipts_id_discipline
      ON memory_mutation_receipts;
    -- AFTER, not BEFORE: a BEFORE trigger runs ahead of the table's CHECK
    -- constraints and would pre-empt every one of them, leaving their own
    -- refusals — and their killing tests — unreachable.
    CREATE TRIGGER memory_mutation_receipts_id_discipline
      AFTER INSERT ON memory_mutation_receipts
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_receipt_id_discipline();

    DROP TRIGGER IF EXISTS memory_mutation_receipts_zz_authorization_scope
      ON memory_mutation_receipts;
    CREATE TRIGGER memory_mutation_receipts_zz_authorization_scope
      AFTER INSERT ON memory_mutation_receipts
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_row_in_authorization_scope();

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_reconciliation_derivable()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      DECLARE
        pending_present boolean;
        version_row public.memory_record_versions%ROWTYPE;
        version_present boolean;
        authorized_digest text;
        implied text;
      BEGIN
        PERFORM 1 FROM public.memory_mutation_receipts AS r
         WHERE r.tenant_id = NEW.tenant_id
           AND r.workspace_id = NEW.workspace_id
           AND r.mutation_receipt_id = NEW.mutation_receipt_id
           AND r.outcome_status = 'UNKNOWN_PENDING_RECONCILIATION'
           AND r.principal_id = NEW.principal_id
           AND r.user_id = NEW.user_id
           AND r.authorization_id = NEW.authorization_id
           AND r.action = NEW.action
           AND r.target_record_id = NEW.target_record_id
         LIMIT 1;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a reconciliation must answer an unknown outcome that is on record, as recorded'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1 FROM public.memory_mutation_receipts AS p
           WHERE p.tenant_id = NEW.tenant_id
             AND p.workspace_id = NEW.workspace_id
             AND p.mutation_receipt_id = NEW.mutation_receipt_id
             AND p.phase = 'pending') INTO pending_present;
        SELECT * INTO version_row FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.mutation_receipt_id = NEW.mutation_receipt_id
         LIMIT 1;
        version_present := FOUND;
        SELECT a.payload ->> 'proposedContentDigest' INTO authorized_digest
          FROM public.memory_authorization_receipts AS a
         WHERE a.tenant_id = NEW.tenant_id
           AND a.authorization_id = NEW.authorization_id
         LIMIT 1;
        IF pending_present AND version_present THEN
          IF authorized_digest IS NOT NULL
             AND version_row.content_digest = authorized_digest THEN
            implied := 'COMMITTED_CONFIRMED';
          ELSE
            implied := 'COMMITTED_DIVERGED';
          END IF;
        ELSIF NOT pending_present AND NOT version_present THEN
          implied := 'NOT_COMMITTED';
        ELSE
          implied := 'IMPOSSIBLE_STATE';
        END IF;
        IF NEW.verdict <> implied THEN
          RAISE EXCEPTION
            'aaliyah memory: reconciliation verdict % is not the verdict stored state implies (%)',
            NEW.verdict, implied
            USING ERRCODE = 'check_violation';
        END IF;
        IF implied IN ('COMMITTED_CONFIRMED','COMMITTED_DIVERGED')
           AND (NEW.observed_version IS DISTINCT FROM version_row.version
                OR NEW.observed_content_digest IS DISTINCT FROM version_row.content_digest) THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed reconciliation must observe the record version that is actually stored'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_reconciliations_derivable
      ON memory_reconciliations;
    -- AFTER, for the same reason: the verdict-domain and observes CHECKs keep
    -- their own refusals. An ON CONFLICT DO NOTHING that inserts nothing
    -- fires no AFTER ROW trigger, which is correct: nothing was filed.
    CREATE TRIGGER memory_reconciliations_derivable
      AFTER INSERT ON memory_reconciliations
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_reconciliation_derivable()`,
  },
  {
    // ------------------------------------------------------------------
    // THE IDENTITY-EDGE PAYLOAD BINDINGS WERE VACUOUS AGAINST A NULL MEMBER.
    //
    // Red team M4 against b3efc82. Migration 041 wrote four bindings as
    // `CHECK (payload ->> 'x' = col)`. A CHECK passes when its expression is
    // NULL, and `payload ->> 'x'` is NULL when the member is absent or JSON
    // null — so an edge whose payload omitted `kind`, `fromRecordId`,
    // `toRecordId` or `authorizationId` satisfied the binding it claimed to
    // carry. Executed: both an absent and a null `kind` passed. Every
    // equivalent binding on the other memory tables carries the
    // `IS NOT NULL AND` prefix; these four did not, on the table W1.3 itself
    // introduced. Re-created with it.
    // ------------------------------------------------------------------
    id: "046_memory_identity_edge_bindings_not_vacuous",
    sql: `ALTER TABLE memory_identity_edges
      DROP CONSTRAINT IF EXISTS memory_identity_edges_kind_binding,
      DROP CONSTRAINT IF EXISTS memory_identity_edges_from_binding,
      DROP CONSTRAINT IF EXISTS memory_identity_edges_to_binding,
      DROP CONSTRAINT IF EXISTS memory_identity_edges_authorization_binding;
    ALTER TABLE memory_identity_edges
      ADD CONSTRAINT memory_identity_edges_kind_binding
        CHECK (payload ->> 'kind' IS NOT NULL AND payload ->> 'kind' = kind),
      ADD CONSTRAINT memory_identity_edges_from_binding
        CHECK (payload ->> 'fromRecordId' IS NOT NULL
               AND payload ->> 'fromRecordId' = from_record_id),
      ADD CONSTRAINT memory_identity_edges_to_binding
        CHECK (payload ->> 'toRecordId' IS NOT NULL
               AND payload ->> 'toRecordId' = to_record_id),
      ADD CONSTRAINT memory_identity_edges_authorization_binding
        CHECK (payload ->> 'authorizationId' IS NOT NULL
               AND payload ->> 'authorizationId' = authorization_id)`,
  },
  {
    // ------------------------------------------------------------------
    // THE ALIAS VAULT: NO PLAINTEXT PERSONAL IDENTIFIER IS STORED, AND
    // ERASURE DESTROYS RECOVERABILITY.
    //
    // Red team BREAK 4 against b3efc82. After a `subject_erasure_request`,
    // `memory_alias_bindings` still held the subject's email address in
    // cleartext — in `normalized_alias`, `skeleton`, `registrable_domain` and
    // twice more in the payload — still ACTIVE, still resolvable, and
    // `aaliyah_alias_binding_guard` refused both DELETE and redaction for every
    // writer including the table owner. The address was architecturally
    // indestructible, and that was disclosed nowhere.
    //
    // FOUNDER DECISION, LOCKED: erasure covers personally identifying aliases,
    // subject to independently enforced legal-hold and retention rules, and the
    // minimum non-PII evidence that an authorized erasure occurred survives.
    //
    // WHAT THIS MIGRATION MAKES TRUE, IN THE DATABASE:
    //
    //   - The three plaintext columns are GONE, and a binding's payload may not
    //     carry the alias in any of the members it used to. The alias lives
    //     only in `pii_envelope` — ciphertext under a per-binding data key
    //     whose material is held by a key provider OUTSIDE PostgreSQL.
    //   - Uniqueness and lookup are over BLIND INDEXES in
    //     `memory_alias_blind_indexes`: keyed HMAC values, one row per binding,
    //     purpose and key version, so a rotation keeps both old and new
    //     versions findable and colliding until the old one is retired.
    //   - ERASURE is the one change an erased-or-retired binding still accepts:
    //     the envelope is nulled, the binding is retired, and its index values
    //     are nulled and deactivated — witnessed by a tombstone that destroyed
    //     the participant record, refused under an applicable legal hold. The
    //     data key is then destroyed by the provider, and
    //     `memory_pii_key_erasures` records both steps as non-PII evidence, so
    //     "the database forgot" and "the key is gone" are separately provable
    //     and a crash between them is recoverable rather than silent.
    //
    // WHAT IT DOES NOT MAKE TRUE: the database cannot verify that an index
    // value is the correct HMAC of anything — it has no key. It enforces
    // presence, form, version agreement, uniqueness and erasure shape; a writer
    // holding the mutator role and the provider could still index garbage.
    //
    // NOT REPLAYED OVER PLAINTEXT. Existing plaintext bindings cannot be
    // encrypted here — the key is not in the database — so the migration
    // refuses to run over any, rather than dropping the columns and destroying
    // them unaccounted.
    // ------------------------------------------------------------------
    id: "047_memory_alias_pii_vault",
    sql: `DO $do$
      DECLARE
        plaintext bigint;
      BEGIN
        -- Only while the plaintext column still exists: re-applying this
        -- migration over vault rows (an interrupted-deploy re-run of the
        -- highest migration, W1BR-014) is not a refusal case.
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'memory_alias_bindings'
             AND column_name = 'normalized_alias') THEN
          RETURN;
        END IF;
        SELECT count(*) INTO plaintext FROM memory_alias_bindings;
        IF plaintext > 0 THEN
          RAISE EXCEPTION
            'aaliyah memory: % plaintext alias binding(s) exist; migration 047 will not drop personal identifiers it cannot first re-encrypt',
            plaintext;
        END IF;
      END
      $do$;

    ALTER TABLE memory_alias_bindings
      DROP COLUMN IF EXISTS normalized_alias CASCADE,
      DROP COLUMN IF EXISTS skeleton CASCADE,
      DROP COLUMN IF EXISTS registrable_domain CASCADE,
      ADD COLUMN IF NOT EXISTS pii_envelope jsonb,
      ADD COLUMN IF NOT EXISTS pii_key_ref text NOT NULL,
      ADD COLUMN IF NOT EXISTS pii_key_version integer NOT NULL,
      ADD COLUMN IF NOT EXISTS pii_erased_at timestamptz,
      ADD COLUMN IF NOT EXISTS pii_erasure_tombstone_id text;

    ALTER TABLE memory_alias_bindings
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_removal_witness,
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_pii_key_version_positive,
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_pii_present_or_erased,
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_erased_is_retired,
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_envelope_key_binding,
      DROP CONSTRAINT IF EXISTS memory_alias_bindings_payload_carries_no_alias;
    ALTER TABLE memory_alias_bindings
      ADD CONSTRAINT memory_alias_bindings_removal_witness CHECK (
        (removed_by_mutation_receipt_id IS NULL) = (removed_authorization_id IS NULL)
        AND (removed_by_mutation_receipt_id IS NULL OR removed_at IS NOT NULL)
        AND (removed_at IS NULL
             OR removed_by_mutation_receipt_id IS NOT NULL
             OR pii_erasure_tombstone_id IS NOT NULL)),
      ADD CONSTRAINT memory_alias_bindings_pii_key_version_positive
        CHECK (pii_key_version > 0),
      ADD CONSTRAINT memory_alias_bindings_pii_present_or_erased CHECK (
        (pii_erased_at IS NULL AND pii_erasure_tombstone_id IS NULL
         AND pii_envelope IS NOT NULL AND jsonb_typeof(pii_envelope) = 'object')
        OR (pii_erased_at IS NOT NULL AND pii_erasure_tombstone_id IS NOT NULL
            AND pii_envelope IS NULL)),
      ADD CONSTRAINT memory_alias_bindings_erased_is_retired
        CHECK (pii_erased_at IS NULL OR removed_at IS NOT NULL),
      ADD CONSTRAINT memory_alias_bindings_envelope_key_binding CHECK (
        pii_envelope IS NULL
        OR (pii_envelope ->> 'keyRef' IS NOT NULL
            AND pii_envelope ->> 'keyRef' = pii_key_ref
            AND pii_envelope ->> 'keyVersion' IS NOT NULL
            AND pii_envelope ->> 'keyVersion' = pii_key_version::text)),
      ADD CONSTRAINT memory_alias_bindings_payload_carries_no_alias CHECK (
        NOT (payload ?| ARRAY['normalizedAlias','skeleton','registrableDomain',
                              'claimed','observedAlias']));

    CREATE TABLE IF NOT EXISTS memory_alias_blind_indexes (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      scope_key text NOT NULL,
      alias_id text NOT NULL,
      binding_mutation_receipt_id text NOT NULL,
      purpose text NOT NULL,
      key_version integer NOT NULL,
      index_value text,
      active boolean NOT NULL DEFAULT true,
      erased_at timestamptz,
      erasure_tombstone_id text,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_alias_blind_indexes_purpose_domain
        CHECK (purpose IN ('alias.normalized','alias.skeleton')),
      CONSTRAINT memory_alias_blind_indexes_version_positive
        CHECK (key_version > 0),
      CONSTRAINT memory_alias_blind_indexes_value_form CHECK (
        index_value IS NULL
        OR index_value ~ '^bi1\\.[1-9][0-9]{0,5}\\.[A-Za-z0-9_-]{43}$'),
      CONSTRAINT memory_alias_blind_indexes_version_agreement CHECK (
        index_value IS NULL
        OR split_part(index_value, '.', 2) = key_version::text),
      CONSTRAINT memory_alias_blind_indexes_present_or_erased CHECK (
        (erased_at IS NULL AND erasure_tombstone_id IS NULL AND index_value IS NOT NULL)
        OR (erased_at IS NOT NULL AND erasure_tombstone_id IS NOT NULL
            AND index_value IS NULL AND NOT active)),
      CONSTRAINT memory_alias_blind_indexes_one_per_version
        UNIQUE (tenant_id, workspace_id, binding_mutation_receipt_id, purpose, key_version)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_blind_indexes_normalized_unique
      ON memory_alias_blind_indexes (tenant_id, scope_key, key_version, index_value)
      WHERE active AND purpose = 'alias.normalized';
    CREATE UNIQUE INDEX IF NOT EXISTS memory_alias_blind_indexes_skeleton_unique
      ON memory_alias_blind_indexes (tenant_id, scope_key, key_version, index_value)
      WHERE active AND purpose = 'alias.skeleton';
    CREATE INDEX IF NOT EXISTS idx_memory_alias_blind_indexes_binding
      ON memory_alias_blind_indexes (tenant_id, workspace_id, binding_mutation_receipt_id);

    -- An index entry belongs to an ACTIVE, UNERASED binding in its own scope.
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_index_insert_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF NOT NEW.active OR NEW.erased_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an index entry is written active and unerased'
            USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1 FROM public.memory_alias_bindings AS b
         WHERE b.tenant_id = NEW.tenant_id
           AND b.workspace_id = NEW.workspace_id
           AND b.alias_id = NEW.alias_id
           AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
           AND b.scope_key = NEW.scope_key
           AND b.removed_at IS NULL
           AND b.pii_erased_at IS NULL;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an index entry must belong to an active binding in its scope'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_blind_indexes_belongs ON memory_alias_blind_indexes;
    CREATE TRIGGER memory_alias_blind_indexes_belongs
      AFTER INSERT ON memory_alias_blind_indexes
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_index_insert_guard();

    -- Two transitions only: deactivation with the binding's retirement, and
    -- erasure with the binding's erasure. No DELETE, for anyone.
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_index_update_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF TG_OP = 'DELETE' THEN
          RAISE EXCEPTION
            'aaliyah alias registry: DELETE on memory_alias_blind_indexes is forbidden; an index entry is erased, never removed'
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.erased_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an erased index entry is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.erased_at IS NOT NULL THEN
          IF (pg_catalog.to_jsonb(NEW) - 'index_value' - 'active' - 'erased_at' - 'erasure_tombstone_id')
             IS DISTINCT FROM
             (pg_catalog.to_jsonb(OLD) - 'index_value' - 'active' - 'erased_at' - 'erasure_tombstone_id') THEN
            RAISE EXCEPTION
              'aaliyah alias registry: erasure may not rewrite an index entry'
              USING ERRCODE = 'check_violation';
          END IF;
          PERFORM 1 FROM public.memory_alias_bindings AS b
           WHERE b.tenant_id = NEW.tenant_id
             AND b.workspace_id = NEW.workspace_id
             AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
             AND b.pii_erasure_tombstone_id = NEW.erasure_tombstone_id;
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah alias registry: an index entry is erased only with its binding'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - 'active') IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'active')
           OR NEW.active OR NOT OLD.active THEN
          RAISE EXCEPTION
            'aaliyah alias registry: deactivation is the only other permitted update'
            USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1 FROM public.memory_alias_bindings AS b
         WHERE b.tenant_id = NEW.tenant_id
           AND b.workspace_id = NEW.workspace_id
           AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
           AND b.removed_at IS NOT NULL;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an index entry is deactivated only with its binding'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_blind_indexes_guard ON memory_alias_blind_indexes;
    CREATE TRIGGER memory_alias_blind_indexes_guard
      BEFORE UPDATE OR DELETE ON memory_alias_blind_indexes
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_index_update_guard();

    -- Retiring a binding deactivates its index entries in the same statement,
    -- so a retired alias can never keep a uniqueness claim or answer a lookup.
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_retirement_deactivates_indexes()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF OLD.removed_at IS NULL AND NEW.removed_at IS NOT NULL
           AND NEW.pii_erased_at IS NULL THEN
          UPDATE public.memory_alias_blind_indexes AS i
             SET active = false
           WHERE i.tenant_id = NEW.tenant_id
             AND i.workspace_id = NEW.workspace_id
             AND i.binding_mutation_receipt_id = NEW.mutation_receipt_id
             AND i.active;
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_retirement_deactivates
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_retirement_deactivates
      AFTER UPDATE OF removed_at ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_retirement_deactivates_indexes();

    -- A binding COMMITS with index entries for both purposes, or not at all:
    -- a binding with none would escape the uniqueness it exists under.
    CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_indexed()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF (SELECT count(DISTINCT i.purpose) FROM public.memory_alias_blind_indexes AS i
             WHERE i.tenant_id = NEW.tenant_id
               AND i.workspace_id = NEW.workspace_id
               AND i.binding_mutation_receipt_id = NEW.mutation_receipt_id) <> 2 THEN
          RAISE EXCEPTION
            'aaliyah alias registry: a binding must commit with blind index entries for both purposes'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_indexed ON memory_alias_bindings;
    CREATE CONSTRAINT TRIGGER memory_alias_bindings_indexed
      AFTER INSERT ON memory_alias_bindings
      DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_binding_indexed();

    -- THE RETIRE-ONLY GUARD, WITH ERASURE AS ITS ONE ADDITIONAL TRANSITION.
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
        IF OLD.pii_erased_at IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an erased alias binding is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.pii_erased_at IS NOT NULL THEN
          IF (pg_catalog.to_jsonb(NEW) - 'pii_envelope' - 'pii_erased_at'
                - 'pii_erasure_tombstone_id' - 'removed_at')
             IS DISTINCT FROM
             (pg_catalog.to_jsonb(OLD) - 'pii_envelope' - 'pii_erased_at'
                - 'pii_erasure_tombstone_id' - 'removed_at') THEN
            RAISE EXCEPTION
              'aaliyah alias registry: erasure may not rewrite a binding'
              USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.removed_at IS NOT NULL AND NEW.removed_at IS DISTINCT FROM OLD.removed_at THEN
            RAISE EXCEPTION
              'aaliyah alias registry: erasure may not move a retirement'
              USING ERRCODE = 'check_violation';
          END IF;
          PERFORM 1 FROM public.memory_tombstones AS t
           WHERE t.tenant_id = NEW.tenant_id
             AND t.workspace_id = NEW.workspace_id
             AND t.tombstone_id = NEW.pii_erasure_tombstone_id
             AND t.target_record_id = NEW.canonical_participant_id;
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah alias registry: no tombstone of this participant witnesses this erasure'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
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

    -- The hold guard, taught that an ERASURE is a delete of the participant.
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
        IF TG_OP = 'UPDATE' AND OLD.pii_erased_at IS NULL AND NEW.pii_erased_at IS NOT NULL THEN
          blocking := public.aaliyah_memory_restricting_hold(
            NEW.tenant_id, NEW.workspace_id, NEW.canonical_participant_id,
            NEW.canonical_participant_id, 'delete');
          IF blocking IS NOT NULL THEN
            RAISE EXCEPTION
              'aaliyah alias registry: legal hold % restricts erasure of this participant''s aliases'
              , blocking
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END IF;
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

    CREATE TABLE IF NOT EXISTS memory_pii_key_erasures (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      tombstone_id text NOT NULL,
      alias_id text NOT NULL,
      binding_mutation_receipt_id text NOT NULL,
      key_ref text NOT NULL,
      provider_id text NOT NULL,
      event text NOT NULL,
      recorded_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT memory_pii_key_erasures_event_domain
        CHECK (event IN ('erasure_committed','key_destroyed')),
      CONSTRAINT memory_pii_key_erasures_once
        UNIQUE (tenant_id, workspace_id, key_ref, event)
    );
    DROP TRIGGER IF EXISTS memory_pii_key_erasures_append_only ON memory_pii_key_erasures;
    CREATE TRIGGER memory_pii_key_erasures_append_only
      BEFORE UPDATE OR DELETE ON memory_pii_key_erasures
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();
    CREATE OR REPLACE FUNCTION public.aaliyah_pii_key_erasure_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        IF NEW.event = 'erasure_committed' THEN
          PERFORM 1 FROM public.memory_alias_bindings AS b
           WHERE b.tenant_id = NEW.tenant_id
             AND b.workspace_id = NEW.workspace_id
             AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
             AND b.alias_id = NEW.alias_id
             AND b.pii_key_ref = NEW.key_ref
             AND b.pii_erasure_tombstone_id = NEW.tombstone_id
             AND b.pii_envelope IS NULL;
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a committed erasure must name a binding erased under that tombstone and key'
              USING ERRCODE = 'check_violation';
          END IF;
        ELSE
          PERFORM 1 FROM public.memory_pii_key_erasures AS e
           WHERE e.tenant_id = NEW.tenant_id
             AND e.workspace_id = NEW.workspace_id
             AND e.key_ref = NEW.key_ref
             AND e.tombstone_id = NEW.tombstone_id
             AND e.event = 'erasure_committed';
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a key is recorded destroyed only after its erasure committed'
              USING ERRCODE = 'check_violation';
          END IF;
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_pii_key_erasures_witnessed ON memory_pii_key_erasures;
    CREATE TRIGGER memory_pii_key_erasures_witnessed
      AFTER INSERT ON memory_pii_key_erasures
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_pii_key_erasure_guard();

    -- A DELETION CANNOT COMMIT WHILE ITS SUBJECT'S ALIASES SURVIVE.
    -- Deferred to COMMIT, so the deleting transaction may write the tombstone
    -- first and erase the bindings after it; what it may not do is finish
    -- without having erased them. This is what makes the cascade a property of
    -- the database rather than of the store that happens to perform it.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_tombstone_erases_aliases()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public
      AS $fn$
      BEGIN
        PERFORM 1 FROM public.memory_alias_bindings AS b
         WHERE b.tenant_id = NEW.tenant_id
           AND b.workspace_id = NEW.workspace_id
           AND b.canonical_participant_id = NEW.target_record_id
           AND b.pii_erased_at IS NULL
         LIMIT 1;
        IF FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a deleted participant may not keep an unerased alias'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_tombstones_aliases_erased ON memory_tombstones;
    CREATE CONSTRAINT TRIGGER memory_tombstones_aliases_erased
      AFTER INSERT ON memory_tombstones
      DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_tombstone_erases_aliases();

    GRANT SELECT ON memory_alias_blind_indexes, memory_pii_key_erasures
      TO aaliyah_memory_mutator, aaliyah_memory_reader, aaliyah_memory_reconciler,
         aaliyah_memory_issuer, aaliyah_memory_revoker;
    GRANT INSERT ON memory_alias_blind_indexes, memory_pii_key_erasures
      TO aaliyah_memory_mutator;
    GRANT UPDATE (index_value, active, erased_at, erasure_tombstone_id)
      ON memory_alias_blind_indexes TO aaliyah_memory_mutator;
    GRANT UPDATE (pii_envelope, pii_erased_at, pii_erasure_tombstone_id)
      ON memory_alias_bindings TO aaliyah_memory_mutator;
    GRANT USAGE, SELECT ON SEQUENCE memory_alias_blind_indexes_id_seq,
      memory_pii_key_erasures_id_seq TO aaliyah_memory_mutator`,
  },
  {
    // ------------------------------------------------------------------
    // pg_temp IS SEARCHED LAST, EXPLICITLY, BY EVERY GUARD.
    //
    // Found while building the Priority 6 database attack matrix. Every
    // aaliyah_* function pins `search_path = pg_catalog, public` — and
    // PostgreSQL searches the session's TEMPORARY schema FIRST for relation
    // names unless `pg_temp` is named in the path. Every role in this database
    // holds TEMP. So an unqualified table reference inside a SECURITY DEFINER
    // guard would resolve to a temp table the CALLER created: a forged
    // authorization receipt, a nonce, a tombstone, answered by the guard as if
    // it were stored state.
    //
    // Today every relation reference in those bodies is `public.`-qualified,
    // which is why this was not exploitable. That is a property of how 48
    // migrations happened to be written, not an enforced one — the next
    // function could omit a qualifier and nothing would say so. Naming pg_temp
    // LAST makes the qualifier a second line rather than the only one, and the
    // attached test pins it for every function, present and future.
    // ------------------------------------------------------------------
    id: "048_memory_functions_pg_temp_last",
    sql: `DO $do$
      DECLARE
        fn record;
      BEGIN
        FOR fn IN
          SELECT p.oid::regprocedure AS signature
            FROM pg_catalog.pg_proc AS p
            JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.proname LIKE 'aaliyah\\_%'
        LOOP
          EXECUTE pg_catalog.format(
            'ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp',
            fn.signature);
        END LOOP;
      END
      $do$`,
  },
  {
    // ------------------------------------------------------------------
    // THE RECONCILIATION EVIDENCE BINDINGS WERE VACUOUS AGAINST A NULL MEMBER.
    //
    // The same defect class red team M4 found on identity edges (migration
    // 046), found here by the implementer while writing Priority 6 destroyers
    // for the CHECK constraints outside the original 81: migration 040 wrote
    // `CHECK (evidence ->> 'x' = col)`, which passes when the member is absent
    // or JSON null. A reconciliation whose evidence names no receipt or no
    // authorization satisfied the binding it claimed to carry.
    // ------------------------------------------------------------------
    id: "049_memory_reconciliation_bindings_not_vacuous",
    sql: `ALTER TABLE memory_reconciliations
      DROP CONSTRAINT IF EXISTS memory_reconciliations_receipt_binding,
      DROP CONSTRAINT IF EXISTS memory_reconciliations_authorization_binding;
    ALTER TABLE memory_reconciliations
      ADD CONSTRAINT memory_reconciliations_receipt_binding
        CHECK (evidence ->> 'mutationReceiptId' IS NOT NULL
               AND evidence ->> 'mutationReceiptId' = mutation_receipt_id),
      ADD CONSTRAINT memory_reconciliations_authorization_binding
        CHECK (evidence ->> 'authorizationId' IS NOT NULL
               AND evidence ->> 'authorizationId' = authorization_id)`,
  },
  {
    // ------------------------------------------------------------------
    // AN ALIAS BINDING OR RETIREMENT IS THE MUTATION ITS AUTHORIZATION NAMED.
    //
    // Red team BREAK C against 2b2e554. The binding guard asked only that SOME
    // spent nonce matched (authorization id, receipt id). It never asked what
    // that authorization was FOR. Run as the mutation role, a consumed
    // `correct` authorization for one record also witnessed a binding for a
    // different, already-erased participant: one authorization, two
    // mutations, and a blind index that answered "exists" for an address that
    // had been erased. Tombstones (B3) and identity edges already bind the
    // witness's action and target; bindings did not.
    //
    // Now a binding requires: a spent `assign_alias` authorization whose
    // target IS the binding's participant, and the record version that same
    // mutation appended to that participant. The version carries every
    // record-level guard with it — owner scope, head continuity, the merge
    // freeze, and no append after a deletion — so a binding cannot outlive
    // the participant it names. A retirement requires the same of
    // `remove_alias`.
    //
    // A separate AFTER trigger, named `zy_` to fire after the existing guards
    // (so each of their refusals is still reachable by its own killing test)
    // and before the `zz_` scope binding, which migration 044 keeps last.
    // ------------------------------------------------------------------
    id: "050_memory_alias_authorization_action_bound",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_alias_binding_action_bound()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      DECLARE
        v_authorization text;
        v_receipt text;
        v_action text;
      BEGIN
        IF TG_OP = 'INSERT' THEN
          v_authorization := NEW.authorization_id;
          v_receipt := NEW.mutation_receipt_id;
          v_action := 'assign_alias';
        ELSE
          IF NEW.removed_authorization_id IS NULL
             OR NEW.removed_authorization_id IS NOT DISTINCT FROM OLD.removed_authorization_id THEN
            RETURN NULL;
          END IF;
          v_authorization := NEW.removed_authorization_id;
          v_receipt := NEW.removed_by_mutation_receipt_id;
          v_action := 'remove_alias';
        END IF;
        PERFORM 1
          FROM public.aaliyah_memory_spent_nonce(NEW.tenant_id, v_authorization, v_receipt) AS n
         WHERE n.workspace_id = NEW.workspace_id
           AND n.action = v_action
           AND n.target_record_id = NEW.canonical_participant_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an alias % must be witnessed by a spent % authorization for its own participant',
            CASE WHEN TG_OP = 'INSERT' THEN 'binding' ELSE 'retirement' END, v_action
            USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1
          FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.record_id = NEW.canonical_participant_id
           AND v.mutation_receipt_id = v_receipt
           AND v.authorization_id = v_authorization
           AND v.state = 'active';
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah alias registry: an alias % must be accompanied by the participant record version its mutation appended',
            CASE WHEN TG_OP = 'INSERT' THEN 'binding' ELSE 'retirement' END
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_alias_bindings_zy_authorization_action
      ON memory_alias_bindings;
    CREATE TRIGGER memory_alias_bindings_zy_authorization_action
      AFTER INSERT OR UPDATE OF removed_authorization_id ON memory_alias_bindings
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_alias_binding_action_bound();`,
  },
  {
    // ------------------------------------------------------------------
    // A MERGE DOES NOT PUT A SUBJECT BEYOND ERASURE.
    //
    // Red team BREAK A against 2b2e554. After P merged into S, the subject
    // erasure of S reported verified with nothing erased, because only
    // bindings naming S were reached; and P — frozen by migration 043 — could
    // not be erased by anyone. The address bound to P stayed encrypted under a
    // live key, resolvable, forever.
    //
    // Founder-locked semantics hold: merge freezes the absorbed record against
    // ordinary mutation and is not deletion; ONE AUTHORIZATION → ONE MUTATION.
    // So erasure does not cascade from S. Instead:
    //
    //   1. The freeze admits exactly one further version on an absorbed
    //      record: a deletion whose order is a subject_erasure_request. Every
    //      deletion guard (content erasure, tombstone, alias erasure, hold,
    //      retention) applies to it unchanged.
    //   2. A subject_erasure_request tombstone is refused while ANY record
    //      merged into its target, transitively, still has a head that is not
    //      deleted or a binding whose address is not erased. Erasure proceeds
    //      absorbed-first, each under its own authorization, and a survivor's
    //      erasure can no longer report success over a subject's address that
    //      survives in a record merged into it.
    // ------------------------------------------------------------------
    id: "051_memory_erasure_reaches_merged_records",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_merged_record_frozen()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      BEGIN
        PERFORM public.aaliyah_memory_record_lock(NEW.tenant_id, NEW.workspace_id, NEW.record_id);
        PERFORM 1 FROM public.memory_identity_edges AS e
         WHERE e.tenant_id = NEW.tenant_id
           AND e.workspace_id = NEW.workspace_id
           AND e.from_record_id = NEW.record_id
           AND e.kind = 'merged_into'
         LIMIT 1;
        IF FOUND AND NOT (NEW.state = 'deleted'
                          AND NEW.payload -> 'content' ->> 'reason' = 'subject_erasure_request') THEN
          RAISE EXCEPTION
            'aaliyah memory: a record merged into another accepts no further versions'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_unerased_merged_records(
      p_tenant text, p_workspace text, p_record text)
      RETURNS SETOF text
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
        WITH RECURSIVE absorbed(record_id) AS (
          SELECT e.from_record_id
            FROM public.memory_identity_edges AS e
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.to_record_id = p_record AND e.kind = 'merged_into'
          UNION
          SELECT e.from_record_id
            FROM public.memory_identity_edges AS e
            JOIN absorbed AS a ON e.to_record_id = a.record_id
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.kind = 'merged_into'
        )
        SELECT a.record_id
          FROM absorbed AS a
         WHERE COALESCE((SELECT v.state
                           FROM public.memory_record_versions AS v
                          WHERE v.tenant_id = p_tenant AND v.workspace_id = p_workspace
                            AND v.record_id = a.record_id
                          ORDER BY v.version DESC LIMIT 1), 'active') <> 'deleted'
            OR EXISTS (SELECT 1 FROM public.memory_alias_bindings AS b
                        WHERE b.tenant_id = p_tenant AND b.workspace_id = p_workspace
                          AND b.canonical_participant_id = a.record_id
                          AND b.pii_erased_at IS NULL)
         ORDER BY a.record_id COLLATE "C";
      $fn$;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text)
      TO aaliyah_memory_mutator;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_erasure_reaches_merged()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      DECLARE
        remaining text;
      BEGIN
        IF NEW.reason <> 'subject_erasure_request' THEN
          RETURN NULL;
        END IF;
        SELECT string_agg(r, ', ') INTO remaining
          FROM public.aaliyah_memory_unerased_merged_records(
                 NEW.tenant_id, NEW.workspace_id, NEW.target_record_id) AS r;
        IF remaining IS NOT NULL THEN
          RAISE EXCEPTION
            'aaliyah memory: a subject erasure may not complete while a record merged into it is not erased (%)',
            remaining
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_tombstones_zy_erasure_reaches_merged ON memory_tombstones;
    CREATE TRIGGER memory_tombstones_zy_erasure_reaches_merged
      AFTER INSERT ON memory_tombstones
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_erasure_reaches_merged();`,
  },
  {
    // ------------------------------------------------------------------
    // AN ALIAS MUTATION IS RECONCILED AGAINST WHAT IT ACTUALLY AUTHORIZED.
    //
    // Red team BREAK B against 2b2e554. Migration 045 derives the verdict by
    // comparing the committed version's content digest with the
    // authorization's proposedContentDigest. For assign_alias and
    // remove_alias those are never equal by construction — the authorization
    // binds aliasAssignmentDigest / aliasRemovalDigest over the record, a
    // keyed alias commitment and the evidence — so a correct alias mutation
    // whose read-back failed could only be filed COMMITTED_DIVERGED, and the
    // once-only constraint made the false alarm permanent.
    //
    // DISCLOSED LIMIT: the keyed digest cannot be recomputed here, because the
    // key lives outside PostgreSQL by founder decision. For alias actions
    // CONFIRMED therefore attests the authorized head was extended by this
    // authorization's own version on its own target, and the authorized
    // alias effect is on record under the same receipt. That the record
    // content matched the keyed digest was verified inside the committing
    // transaction, before the consumption it shares a transaction with.
    // ------------------------------------------------------------------
    id: "052_memory_alias_reconciliation_derivable",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_alias_effect_present(
      p_tenant text, p_workspace text, p_action text, p_receipt text,
      p_authorization text, p_target text)
      RETURNS boolean
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
        SELECT CASE p_action
          WHEN 'assign_alias' THEN EXISTS (
            SELECT 1 FROM public.memory_alias_bindings AS b
             WHERE b.tenant_id = p_tenant AND b.workspace_id = p_workspace
               AND b.mutation_receipt_id = p_receipt
               AND b.authorization_id = p_authorization
               AND b.canonical_participant_id = p_target)
          WHEN 'remove_alias' THEN EXISTS (
            SELECT 1 FROM public.memory_alias_bindings AS b
             WHERE b.tenant_id = p_tenant AND b.workspace_id = p_workspace
               AND b.removed_by_mutation_receipt_id = p_receipt
               AND b.removed_authorization_id = p_authorization
               AND b.canonical_participant_id = p_target)
          ELSE false
        END;
      $fn$;
    -- The reconciler learns whether the effect is on record, and nothing
    -- else: it is not granted the binding table, which holds envelopes.
    REVOKE ALL ON FUNCTION public.aaliyah_memory_alias_effect_present(text, text, text, text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_alias_effect_present(text, text, text, text, text, text)
      TO aaliyah_memory_reconciler;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_reconciliation_derivable()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      DECLARE
        pending_present boolean;
        version_row public.memory_record_versions%ROWTYPE;
        version_present boolean;
        authorized_digest text;
        authorized_head_version integer;
        authorized_head_digest text;
        alias_effect_present boolean;
        implied text;
      BEGIN
        PERFORM 1 FROM public.memory_mutation_receipts AS r
         WHERE r.tenant_id = NEW.tenant_id
           AND r.workspace_id = NEW.workspace_id
           AND r.mutation_receipt_id = NEW.mutation_receipt_id
           AND r.outcome_status = 'UNKNOWN_PENDING_RECONCILIATION'
           AND r.principal_id = NEW.principal_id
           AND r.user_id = NEW.user_id
           AND r.authorization_id = NEW.authorization_id
           AND r.action = NEW.action
           AND r.target_record_id = NEW.target_record_id
         LIMIT 1;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a reconciliation must answer an unknown outcome that is on record, as recorded'
            USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
          SELECT 1 FROM public.memory_mutation_receipts AS p
           WHERE p.tenant_id = NEW.tenant_id
             AND p.workspace_id = NEW.workspace_id
             AND p.mutation_receipt_id = NEW.mutation_receipt_id
             AND p.phase = 'pending') INTO pending_present;
        SELECT * INTO version_row FROM public.memory_record_versions AS v
         WHERE v.tenant_id = NEW.tenant_id
           AND v.workspace_id = NEW.workspace_id
           AND v.mutation_receipt_id = NEW.mutation_receipt_id
         LIMIT 1;
        version_present := FOUND;
        SELECT a.payload ->> 'proposedContentDigest',
               (a.payload -> 'expectedHead' ->> 'version')::integer,
               a.payload -> 'expectedHead' ->> 'contentDigest'
          INTO authorized_digest, authorized_head_version, authorized_head_digest
          FROM public.memory_authorization_receipts AS a
         WHERE a.tenant_id = NEW.tenant_id
           AND a.authorization_id = NEW.authorization_id
         LIMIT 1;
        IF pending_present AND version_present AND NEW.action IN ('assign_alias','remove_alias') THEN
          -- An alias authorization binds a KEYED digest (the alias commitment
          -- is an HMAC under a key outside PostgreSQL), never the version's
          -- content digest, so that comparison could only ever say DIVERGED.
          -- What stored state can prove: the authorization's own mutation
          -- extended exactly the head it authorized, on its own target, and
          -- the alias effect it authorized is on record under it.
          alias_effect_present := public.aaliyah_memory_alias_effect_present(
            NEW.tenant_id, NEW.workspace_id, NEW.action, NEW.mutation_receipt_id,
            NEW.authorization_id, NEW.target_record_id);
          IF alias_effect_present
             AND version_row.record_id = NEW.target_record_id
             AND version_row.authorization_id = NEW.authorization_id
             AND version_row.state = 'active'
             AND authorized_head_version IS NOT NULL
             AND version_row.version = authorized_head_version + 1
             AND version_row.predecessor_digest IS NOT DISTINCT FROM authorized_head_digest THEN
            implied := 'COMMITTED_CONFIRMED';
          ELSE
            implied := 'COMMITTED_DIVERGED';
          END IF;
        ELSIF pending_present AND version_present THEN
          IF authorized_digest IS NOT NULL
             AND version_row.content_digest = authorized_digest THEN
            implied := 'COMMITTED_CONFIRMED';
          ELSE
            implied := 'COMMITTED_DIVERGED';
          END IF;
        ELSIF NOT pending_present AND NOT version_present THEN
          implied := 'NOT_COMMITTED';
        ELSE
          implied := 'IMPOSSIBLE_STATE';
        END IF;
        IF NEW.verdict <> implied THEN
          RAISE EXCEPTION
            'aaliyah memory: reconciliation verdict % is not the verdict stored state implies (%)',
            NEW.verdict, implied
            USING ERRCODE = 'check_violation';
        END IF;
        IF implied IN ('COMMITTED_CONFIRMED','COMMITTED_DIVERGED')
           AND (NEW.observed_version IS DISTINCT FROM version_row.version
                OR NEW.observed_content_digest IS DISTINCT FROM version_row.content_digest) THEN
          RAISE EXCEPTION
            'aaliyah memory: a committed reconciliation must observe the record version that is actually stored'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;`,
  },
  {
    // ------------------------------------------------------------------
    // NO MERGE MAY MAKE AN IDENTITY UNRESOLVABLE.
    //
    // Red team M3 against 2b2e554. The read-time resolver walks at most
    // MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH (16) merge hops, so that a cycle
    // from a replica or a dropped trigger cannot hang a reader. Nothing bounded
    // the chains the database ACCEPTED: 17 legitimate merges produced a chain
    // no identity on which could ever resolve again, with no un-merge to repair
    // it. (The resolver also refused a chain of exactly 16, an off-by-one fixed
    // in the service.)
    //
    // A merge is now refused when the chain through it — the longest chain
    // already merged into the absorbed record, this edge, and any chain beyond
    // the survivor — would exceed 16 hops.
    //
    // NO GRAPH LOCK IS NEEDED, and none is taken. Migration 042 refuses a merge
    // into an absorbed record, so a survivor is always canonical (nothing
    // beyond it) and a chain can only grow at its canonical end. The chain
    // into the absorbed record therefore changes only through an edge INTO
    // that record, and every such edge takes that record's lock (043), which
    // this edge's own guard already holds when this trigger runs.
    // ------------------------------------------------------------------
    id: "053_memory_merge_chain_bounded",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_merge_chain_hops(
      p_tenant text, p_workspace text, p_from text, p_to text)
      RETURNS integer
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
        WITH RECURSIVE incoming(record_id, hops) AS (
          SELECT p_from, 0
          UNION ALL
          SELECT e.from_record_id, i.hops + 1
            FROM public.memory_identity_edges AS e
            JOIN incoming AS i ON e.to_record_id = i.record_id
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.kind = 'merged_into' AND i.hops < 64
        ), outgoing(record_id, hops) AS (
          SELECT p_to, 0
          UNION ALL
          SELECT e.to_record_id, o.hops + 1
            FROM public.memory_identity_edges AS e
            JOIN outgoing AS o ON e.from_record_id = o.record_id
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.kind = 'merged_into' AND o.hops < 64
        )
        SELECT (SELECT max(hops) FROM incoming) + 1 + (SELECT max(hops) FROM outgoing);
      $fn$;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_merge_chain_hops(text, text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_merge_chain_hops(text, text, text, text)
      TO aaliyah_memory_mutator;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_merge_chain_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      DECLARE
        hops integer;
      BEGIN
        IF NEW.kind <> 'merged_into' THEN
          RETURN NULL;
        END IF;
        -- This edge is already visible to its own AFTER trigger, so the walk
        -- from the absorbed record forward counts it: measure from its two
        -- ends with the edge itself excluded by construction (incoming stops
        -- at the absorbed record, outgoing starts at the survivor).
        hops := public.aaliyah_memory_merge_chain_hops(
          NEW.tenant_id, NEW.workspace_id, NEW.from_record_id, NEW.to_record_id);
        IF hops > 16 THEN
          RAISE EXCEPTION
            'aaliyah memory: a merge may not make an identity chain longer than 16 hops (this one: %)', hops
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_identity_edges_zy_merge_chain_bounded ON memory_identity_edges;
    CREATE TRIGGER memory_identity_edges_zy_merge_chain_bounded
      AFTER INSERT ON memory_identity_edges
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_merge_chain_guard();`,
  },
  {
    // ------------------------------------------------------------------
    // A MERGED-IN RECORD IS NOT ERASED WHILE ITS DATA KEY LIVES.
    //
    // Security review of 03581a3, HIGH, executed (ATK-C1, ATK-C2). After a key
    // provider outage during the absorbed record's own erasure, the database
    // half committed (envelope nulled, erasure_committed recorded) while the
    // data key stayed live, and 051 counted that record as erased: the
    // survivor's subject erasure reported verified, and a pre-erasure
    // ciphertext copy still decrypted to the full address until a completion
    // pass ran — at boot. A merged-in erasure without key_destroyed evidence
    // now keeps the survivor's subject erasure refused, in the helper the
    // store's pre-check and the tombstone trigger both use. The store also asks
    // the provider about those keys, because the evidence row is writable by
    // the mutation role (W1BR-036).
    // ------------------------------------------------------------------
    id: "054_memory_merged_erasure_requires_destroyed_keys",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_unerased_merged_records(
      p_tenant text, p_workspace text, p_record text)
      RETURNS SETOF text
      LANGUAGE sql
      STABLE
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
        WITH RECURSIVE absorbed(record_id) AS (
          SELECT e.from_record_id
            FROM public.memory_identity_edges AS e
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.to_record_id = p_record AND e.kind = 'merged_into'
          UNION
          SELECT e.from_record_id
            FROM public.memory_identity_edges AS e
            JOIN absorbed AS a ON e.to_record_id = a.record_id
           WHERE e.tenant_id = p_tenant AND e.workspace_id = p_workspace
             AND e.kind = 'merged_into'
        )
        SELECT a.record_id
          FROM absorbed AS a
         WHERE COALESCE((SELECT v.state
                           FROM public.memory_record_versions AS v
                          WHERE v.tenant_id = p_tenant AND v.workspace_id = p_workspace
                            AND v.record_id = a.record_id
                          ORDER BY v.version DESC LIMIT 1), 'active') <> 'deleted'
            OR EXISTS (SELECT 1 FROM public.memory_alias_bindings AS b
                        WHERE b.tenant_id = p_tenant AND b.workspace_id = p_workspace
                          AND b.canonical_participant_id = a.record_id
                          AND b.pii_erased_at IS NULL)
            -- An erased binding whose data key has no destruction evidence is
            -- not erased: its ciphertext, wherever a copy survives, still
            -- decrypts (security review of 03581a3, ATK-C1).
            OR EXISTS (SELECT 1
                         FROM public.memory_alias_bindings AS b
                         JOIN public.memory_pii_key_erasures AS c
                           ON c.tenant_id = b.tenant_id AND c.workspace_id = b.workspace_id
                          AND c.binding_mutation_receipt_id = b.mutation_receipt_id
                          AND c.key_ref = b.pii_key_ref
                          AND c.event = 'erasure_committed'
                        WHERE b.tenant_id = p_tenant AND b.workspace_id = p_workspace
                          AND b.canonical_participant_id = a.record_id
                          AND NOT EXISTS (
                            SELECT 1 FROM public.memory_pii_key_erasures AS d
                             WHERE d.tenant_id = c.tenant_id AND d.workspace_id = c.workspace_id
                               AND d.key_ref = c.key_ref AND d.event = 'key_destroyed'))
         ORDER BY a.record_id COLLATE "C";
      $fn$;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text)
      TO aaliyah_memory_mutator;`,
  },
  {
    // ------------------------------------------------------------------
    // AN UNPROVABLE KEY IS UNRESOLVED, NOT ERASED — AND IT HAS A WAY OUT.
    //
    // Founder decision, OPTION B, locked: when a merged-in key cannot be
    // authoritatively confirmed destroyed, the subject MUST NOT be
    // represented as erased. Before this migration the store had only two
    // answers, and both were wrong for that case:
    //
    //   - integration review of 8a0bf05, CRITICAL, executed (K-01): with
    //     `piiKeys: null` — the ACTUAL production wiring at src/server.ts,
    //     because no production KMS is provisioned — `state` is forced to
    //     null, null is never 'destroyed', and every survivor of a merge
    //     whose absorbed record ever carried a PII binding is refused
    //     `merged_records_not_erased` PERMANENTLY, including erasure of the
    //     survivor's OWN content, even when the merged-in key was genuinely
    //     destroyed years ago with matching evidence;
    //   - security review of 8a0bf05, LOW, undisclosed (K-09): the same
    //     permanent refusal for a lost key or a provider migration, where the
    //     store's provider answers `unknown`.
    //
    // A permanent refusal is not "fail closed". It is an unresolved state
    // that lies about being a decision, with no operator path and — as both
    // reviewers noted — no disclosure.
    //
    // THREE THINGS THIS ADDS, AND WHAT EACH IS FOR.
    //
    // 1. `memory_key_destruction_obligations` — the durable unresolved state.
    //    KEY_DESTRUCTION_NOT_PROVEN is recorded per key, with WHY it could not
    //    be proven, so "we do not know" is a row an operator can find rather
    //    than a rejection an operator can only guess at. It never satisfies
    //    anything.
    //
    // 2. `memory_key_destruction_settlements` — the bounded way out. NOT an
    //    administrative bypass: a settlement is evidence-bound, scoped,
    //    independently authorized, independently verified, replay-safe,
    //    idempotent, versioned and immutable once written, and only its
    //    PROVEN_DESTROYED decision may satisfy the key-destruction portion of
    //    a verified erasure. STILL_UNKNOWN stays unresolved BY CONSTRUCTION:
    //    it cannot produce destruction evidence, because the trigger below
    //    refuses it.
    //
    //    No self-verification, as a CHECK and not as a convention: the
    //    settling authority and the verifier are different principals, and a
    //    row that names one principal as both is refused by the database.
    //    A separate role owns the table, so the mutation role — which can
    //    already write erasure evidence, which is why the provider is asked
    //    at all — cannot settle anything.
    //
    // 3. `memory_pii_key_audits` — round-robin audit state, so the completion
    //    pass's re-confirmation of historically destroyed keys is BOUNDED
    //    (reliability review of 8a0bf05, HIGH, K-04: 150 seeded keys produced
    //    exactly 150 provider calls on every pass, forever, and server.ts
    //    awaits that pass before app.listen()). Ordering by least-recently
    //    audited is what keeps it honest: a forged row cannot hide behind
    //    volume the way it did when the audit shared one LIMIT with the
    //    pending work (security review of 03581a3, F2).
    //
    // DATABASE EVIDENCE ALONE STILL DOES NOT SUBSTITUTE FOR PROOF. A
    // `key_destroyed` row remains writable by the mutation role, which is
    // exactly why the store asks the provider. A settlement-sourced row is
    // DISTINGUISHABLE — it carries `settlement_receipt_id` — so an auditor can
    // always tell a provider confirmation from a settled one, and the store
    // treats them differently: the provider's own answer always wins, and a
    // settlement stands in only where the provider structurally cannot answer.
    // ------------------------------------------------------------------
    id: "055_memory_key_destruction_settlement",
    sql: `CREATE TABLE IF NOT EXISTS memory_key_destruction_settlements (
      id bigserial PRIMARY KEY,
      settlement_receipt_id text NOT NULL,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      subject_record_id text NOT NULL,
      alias_id text NOT NULL,
      key_ref text NOT NULL,
      key_version integer NOT NULL,
      provider_id text NOT NULL,
      binding_mutation_receipt_id text NOT NULL,
      erasure_authorization_id text NOT NULL,
      erasure_tombstone_id text NOT NULL,
      destruction_attempt_id text NOT NULL,
      evidence jsonb NOT NULL,
      evidence_digest text NOT NULL,
      settlement_authority_id text NOT NULL,
      verifier_principal_id text NOT NULL,
      decision text NOT NULL,
      policy_version text NOT NULL,
      nonce text NOT NULL,
      predecessor_state text NOT NULL,
      successor_state text NOT NULL,
      decided_at timestamptz NOT NULL,
      recorded_at timestamptz NOT NULL DEFAULT now(),
      -- The seven outcomes the founder decision enumerates. Only the first
      -- may satisfy the key-destruction portion of a verified erasure.
      CONSTRAINT memory_key_destruction_settlements_decision_domain
        CHECK (decision IN ('PROVEN_DESTROYED','PROVEN_NOT_DESTROYED','STILL_UNKNOWN',
                            'RETENTION_BLOCKED','PROVIDER_UNAVAILABLE',
                            'EVIDENCE_INSUFFICIENT','CONTRADICTORY_EVIDENCE')),
      -- NO SELF-VERIFICATION. Enforced here rather than trusted to a caller:
      -- the whole point of a settlement is that someone other than the
      -- settling authority checked the evidence.
      CONSTRAINT memory_key_destruction_settlements_independent_verifier
        CHECK (settlement_authority_id <> verifier_principal_id),
      -- BOTH STATES COME FROM THE KNOWN VOCABULARY, and they are allowed to
      -- be the SAME one. The first version of this constraint required them to
      -- differ, which looked like rigour and was simply wrong: a settlement
      -- whose decision is STILL_UNKNOWN records that the evidence did NOT
      -- settle the question, so the state legitimately does not move — and
      -- refusing to record that would leave the one outcome the founder
      -- decision names as "remains unresolved" unrecordable. Caught by S-3.
      CONSTRAINT memory_key_destruction_settlements_states_known
        CHECK (predecessor_state IN ('ERASURE_REQUESTED','ERASURE_PENDING_SETTLEMENT',
                                     'PROVEN_DESTROYED','PROVEN_NOT_DESTROYED')
           AND successor_state IN ('ERASURE_REQUESTED','ERASURE_PENDING_SETTLEMENT',
                                   'PROVEN_DESTROYED','PROVEN_NOT_DESTROYED')),
      -- A digest is a digest. Free text here would be a place for a subject's
      -- address to survive a settlement.
      CONSTRAINT memory_key_destruction_settlements_digest_shape
        CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
      -- Red team B8: a settlement decided in the year 2099 was accepted. The
      -- tolerance is for clock skew between the application and the database,
      -- not for the future.
      CONSTRAINT memory_key_destruction_settlements_decided_not_future
        CHECK (decided_at <= now() + interval '1 minute'),
      -- Red team B7: policy_version had no constraint at all, so "versioned"
      -- was a column rather than a property. A new policy version is added
      -- here deliberately, which is the point of naming one.
      CONSTRAINT memory_key_destruction_settlements_policy_known
        CHECK (policy_version IN ('aaliyah.key-destruction-settlement/v1')),
      -- IDEMPOTENT: replaying the same settlement receipt is the same row.
      CONSTRAINT memory_key_destruction_settlements_receipt_unique
        UNIQUE (settlement_receipt_id),
      -- REPLAY-SAFE: a nonce is spent once per tenant, whatever it is aimed at.
      CONSTRAINT memory_key_destruction_settlements_nonce_unique
        UNIQUE (tenant_id, nonce),
      -- ACTION-SPECIFIC: one settlement per key per erasure request, so a
      -- single authorization cannot be reused to settle a second key.
      CONSTRAINT memory_key_destruction_settlements_scope_unique
        UNIQUE (tenant_id, workspace_id, key_ref, erasure_authorization_id)
    );
    -- IMMUTABLE AFTER COMPLETION. A settlement that could be rewritten is a
    -- settlement that proves whatever the last writer wanted it to.
    DROP TRIGGER IF EXISTS memory_key_destruction_settlements_append_only
      ON memory_key_destruction_settlements;
    CREATE TRIGGER memory_key_destruction_settlements_append_only
      BEFORE UPDATE OR DELETE ON memory_key_destruction_settlements
      FOR EACH ROW EXECUTE FUNCTION aaliyah_memory_forbid_row_rewrite();

    -- A settlement must name a key that REALLY was erased under that tombstone
    -- and really does belong to that provider and version. Otherwise a
    -- settlement is a free-standing assertion about nothing, and "evidence
    -- bound" is a word rather than a property.
    CREATE OR REPLACE FUNCTION public.aaliyah_memory_settlement_binds_real_key()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      -- pg_temp LAST, EXPLICITLY: PostgreSQL searches it FIRST when it is
      -- not named, and migration 048 ALTERs every aaliyah_* function to say
      -- so. A later CREATE OR REPLACE carrying the older header silently
      -- reverts that hardening — which is W1BR-014's whole class of defect,
      -- and T-1 caught this exact revert in review.
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      BEGIN
        PERFORM 1
           FROM public.memory_alias_bindings AS b
          WHERE b.tenant_id = NEW.tenant_id
            AND b.workspace_id = NEW.workspace_id
            AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
            AND b.alias_id = NEW.alias_id
            AND b.pii_key_ref = NEW.key_ref
            AND b.canonical_participant_id = NEW.subject_record_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a settlement must name a real binding of that subject, alias and key'
            USING ERRCODE = 'check_violation';
        END IF;
        PERFORM 1
           FROM public.memory_pii_key_erasures AS c
          WHERE c.tenant_id = NEW.tenant_id
            AND c.workspace_id = NEW.workspace_id
            AND c.key_ref = NEW.key_ref
            AND c.provider_id = NEW.provider_id
            AND c.tombstone_id = NEW.erasure_tombstone_id
            AND c.event = 'erasure_committed';
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a settlement must name a key whose erasure actually committed under that tombstone'
            USING ERRCODE = 'check_violation';
        END IF;
        -- ---- THE ERASURE REQUEST MUST BE A REAL ONE -------------------
        --
        -- Red team against 86d33c9, HIGH (B1): erasure_authorization_id was
        -- unverified free text. memory_key_destruction_settlements_scope_unique
        -- is UNIQUE (tenant, workspace, key_ref, erasure_authorization_id) and
        -- is the whole of "action-specific" — so a settlement already refused
        -- as settlement_already_resolved was accepted by editing that one
        -- string to an id nobody ever issued, and a STILL_UNKNOWN key became
        -- ERASED. Observed: 0 rows in the nonce table, 0 in the receipts
        -- table, {recorded:true}, survivor erasure verified:true.
        --
        -- The tombstone already records the authorization that witnessed the
        -- erasure, so the settlement is bound to THAT rather than to whatever
        -- the caller typed.
        PERFORM 1
           FROM public.memory_tombstones AS t
          WHERE t.tenant_id = NEW.tenant_id
            AND t.workspace_id = NEW.workspace_id
            AND t.tombstone_id = NEW.erasure_tombstone_id
            AND t.authorization_id = NEW.erasure_authorization_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a settlement must name the authorization that actually witnessed that erasure'
            USING ERRCODE = 'check_violation';
        END IF;
        -- ---- AND THE VERSION, WHICH THE COMMENT ALREADY CLAIMED -------
        -- Red team B8: key_version was accepted as anything (999999 for a
        -- version-1 key), while this function's own header claimed the key
        -- "really does belong to that provider and version".
        PERFORM 1
           FROM public.memory_alias_bindings AS b
          WHERE b.tenant_id = NEW.tenant_id
            AND b.workspace_id = NEW.workspace_id
            AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
            AND b.pii_key_ref = NEW.key_ref
            AND b.pii_key_version = NEW.key_version;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'aaliyah memory: a settlement must name the key VERSION the binding actually carries'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
      END;
      $fn$;
    DROP TRIGGER IF EXISTS memory_key_destruction_settlements_bound
      ON memory_key_destruction_settlements;
    CREATE TRIGGER memory_key_destruction_settlements_bound
      AFTER INSERT ON memory_key_destruction_settlements
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_settlement_binds_real_key();

    -- THE UNRESOLVED STATE, AS A ROW.
    CREATE TABLE IF NOT EXISTS memory_key_destruction_obligations (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      subject_record_id text NOT NULL,
      alias_id text NOT NULL,
      key_ref text NOT NULL,
      provider_id text NOT NULL,
      binding_mutation_receipt_id text NOT NULL,
      erasure_tombstone_id text NOT NULL,
      state text NOT NULL,
      not_proven_reason text NOT NULL,
      observations integer NOT NULL DEFAULT 1,
      first_observed_at timestamptz NOT NULL DEFAULT now(),
      last_observed_at timestamptz NOT NULL DEFAULT now(),
      -- HOW an obligation stopped being unresolved. There are exactly two
      -- ways, and conflating them was the first version's mistake: a
      -- SETTLEMENT is the bounded operator path, and a PROVIDER answer is the
      -- ordinary case where a transient outage ends and the completion pass
      -- simply gets its answer. A ledger that could only record the first
      -- would leave every provider-healed row sitting open forever, and an
      -- operator could not tell a real unresolved state from a stale one.
      resolved_by text,
      settled_by text,
      CONSTRAINT memory_key_destruction_obligations_state_domain
        CHECK (state IN ('KEY_DESTRUCTION_NOT_PROVEN','PROVEN_DESTROYED','PROVEN_NOT_DESTROYED')),
      CONSTRAINT memory_key_destruction_obligations_reason_domain
        CHECK (not_proven_reason IN ('NO_PROVIDER_CONFIGURED','PROVIDER_UNAVAILABLE',
                                     'PROVIDER_TIMEOUT','PROVIDER_DOES_NOT_OWN_KEY',
                                     'PROVIDER_ANSWERED_UNKNOWN','CONTRADICTORY_EVIDENCE',
                                     'SETTLED')),
      -- An unresolved obligation names one key once. Observing it again bumps
      -- the count; it does not accumulate rows nobody can reconcile.
      CONSTRAINT memory_key_destruction_obligations_key_unique
        UNIQUE (tenant_id, workspace_id, key_ref),
      -- A row may not claim to be resolved without naming HOW, and a
      -- settlement resolution must name WHICH settlement.
      CONSTRAINT memory_key_destruction_obligations_resolution_named
        CHECK (
          (state = 'KEY_DESTRUCTION_NOT_PROVEN'
             AND resolved_by IS NULL AND settled_by IS NULL)
          OR (state <> 'KEY_DESTRUCTION_NOT_PROVEN'
             AND resolved_by IN ('PROVIDER', 'SETTLEMENT')
             AND (resolved_by = 'SETTLEMENT') = (settled_by IS NOT NULL))
        )
    );

    -- ROUND-ROBIN AUDIT STATE. A key with no row here sorts ahead of every key
    -- that has one, so a key never audited is always audited next.
    CREATE TABLE IF NOT EXISTS memory_pii_key_audits (
      tenant_id text NOT NULL,
      workspace_id text NOT NULL,
      key_ref text NOT NULL,
      last_audited_at timestamptz NOT NULL DEFAULT now(),
      last_state text NOT NULL,
      audits integer NOT NULL DEFAULT 1,
      PRIMARY KEY (tenant_id, workspace_id, key_ref),
      CONSTRAINT memory_pii_key_audits_state_domain
        CHECK (last_state IN ('active','destroyed','unknown','unreachable'))
    );

    -- A SETTLEMENT-SOURCED DESTRUCTION IS LABELLED AS ONE.
    ALTER TABLE memory_pii_key_erasures
      ADD COLUMN IF NOT EXISTS settlement_receipt_id text;

    -- ... and it may only exist where a PROVEN_DESTROYED settlement for that
    -- exact key exists. This is the clause that makes STILL_UNKNOWN unable to
    -- become erased: there is no way to write destruction evidence from it.
    CREATE OR REPLACE FUNCTION public.aaliyah_pii_key_erasure_guard()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      -- pg_temp LAST, EXPLICITLY: PostgreSQL searches it FIRST when it is
      -- not named, and migration 048 ALTERs every aaliyah_* function to say
      -- so. A later CREATE OR REPLACE carrying the older header silently
      -- reverts that hardening — which is W1BR-014's whole class of defect,
      -- and T-1 caught this exact revert in review.
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      BEGIN
        IF NEW.event = 'erasure_committed' THEN
          IF NEW.settlement_receipt_id IS NOT NULL THEN
            RAISE EXCEPTION
              'aaliyah memory: a committed erasure is not settled evidence'
              USING ERRCODE = 'check_violation';
          END IF;
          PERFORM 1 FROM public.memory_alias_bindings AS b
           WHERE b.tenant_id = NEW.tenant_id
             AND b.workspace_id = NEW.workspace_id
             AND b.mutation_receipt_id = NEW.binding_mutation_receipt_id
             AND b.alias_id = NEW.alias_id
             AND b.pii_key_ref = NEW.key_ref
             AND b.pii_erasure_tombstone_id = NEW.tombstone_id
             AND b.pii_envelope IS NULL;
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a committed erasure must name a binding erased under that tombstone and key'
              USING ERRCODE = 'check_violation';
          END IF;
        ELSE
          PERFORM 1 FROM public.memory_pii_key_erasures AS e
           WHERE e.tenant_id = NEW.tenant_id
             AND e.workspace_id = NEW.workspace_id
             AND e.key_ref = NEW.key_ref
             AND e.tombstone_id = NEW.tombstone_id
             AND e.event = 'erasure_committed';
          IF NOT FOUND THEN
            RAISE EXCEPTION
              'aaliyah memory: a key is recorded destroyed only after its erasure committed'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.settlement_receipt_id IS NOT NULL THEN
            PERFORM 1 FROM public.memory_key_destruction_settlements AS s
             WHERE s.settlement_receipt_id = NEW.settlement_receipt_id
               AND s.tenant_id = NEW.tenant_id
               AND s.workspace_id = NEW.workspace_id
               AND s.key_ref = NEW.key_ref
               AND s.provider_id = NEW.provider_id
               AND s.decision = 'PROVEN_DESTROYED';
            IF NOT FOUND THEN
              RAISE EXCEPTION
                'aaliyah memory: settled destruction evidence needs a PROVEN_DESTROYED settlement for that exact key'
                USING ERRCODE = 'check_violation';
            END IF;
          END IF;
        END IF;
        RETURN NULL;
      END;
      $fn$;

    -- A SETTLER IS NOT A MUTATOR. The mutation role can already write erasure
    -- evidence — that is the whole reason the provider is asked — so it must
    -- not also be able to write the artifact that stands in for the provider.
    DO $do$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aaliyah_memory_settler') THEN
        CREATE ROLE aaliyah_memory_settler NOLOGIN;
      END IF;
    END
    $do$;

    -- ---- GRANTS: EXACTLY WHAT THE CODE USES, AND NOTHING NEAR IT --------
    -- Security review F5 (K-17) confirmed by execution that the existing
    -- grants were wider than the callers needed. These are written against
    -- the call sites rather than against the tables: the mutation role runs
    -- the store's proof and completion passes, the read-back role serves
    -- listKeyDestructionObligations, and the settler runs settlement. No
    -- role gets a table it never names.

    -- The store asks, under the MUTATION role, whether a settlement proves a
    -- key it could not ask the provider about. It reads settlements; it can
    -- never write one.
    GRANT SELECT ON memory_key_destruction_settlements TO aaliyah_memory_mutator;
    -- Only the settler writes settlements, and it must read them back for
    -- idempotency.
    GRANT SELECT, INSERT ON memory_key_destruction_settlements
      TO aaliyah_memory_settler;
    GRANT USAGE, SELECT ON SEQUENCE memory_key_destruction_settlements_id_seq
      TO aaliyah_memory_settler;
    -- ---- THE SETTLER CANNOT WRITE EVIDENCE DIRECTLY -------------------
    --
    -- Red team against 86d33c9, HIGH (B2): 055 put the PROVEN_DESTROYED check
    -- inside IF NEW.settlement_receipt_id IS NOT NULL, so the settler simply
    -- left the label NULL and the row was ACCEPTED — after which
    -- aaliyah_memory_unerased_merged_records() returned 0 rows for a subject
    -- whose key was still active. The clause guarded the labelling
    -- CONVENTION, not the evidence.
    --
    -- So the settler gets SELECT only, and the labelled row is written by a
    -- SECURITY DEFINER function that always supplies the label. There is no
    -- unlabelled row the settler can write, because there is no INSERT it can
    -- issue. (An unlabelled forged row from the MUTATION role remains the
    -- disclosed W1BR-036 condition, whose answer is the store asking the
    -- provider — that is unchanged and is not what B2 was about.)
    GRANT SELECT ON memory_pii_key_erasures TO aaliyah_memory_settler;

    CREATE OR REPLACE FUNCTION public.aaliyah_memory_record_settled_destruction(
      p_settlement_receipt_id text)
      RETURNS integer
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      DECLARE
        v_settlement public.memory_key_destruction_settlements;
        v_written integer;
      BEGIN
        SELECT * INTO v_settlement
          FROM public.memory_key_destruction_settlements
         WHERE settlement_receipt_id = p_settlement_receipt_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'aaliyah memory: no such settlement'
            USING ERRCODE = 'check_violation';
        END IF;
        IF v_settlement.decision <> 'PROVEN_DESTROYED' THEN
          RAISE EXCEPTION
            'aaliyah memory: only a PROVEN_DESTROYED settlement records destruction'
            USING ERRCODE = 'check_violation';
        END IF;
        INSERT INTO public.memory_pii_key_erasures
          (tenant_id, workspace_id, tombstone_id, alias_id,
           binding_mutation_receipt_id, key_ref, provider_id, event,
           settlement_receipt_id)
        VALUES (v_settlement.tenant_id, v_settlement.workspace_id,
                v_settlement.erasure_tombstone_id, v_settlement.alias_id,
                v_settlement.binding_mutation_receipt_id, v_settlement.key_ref,
                v_settlement.provider_id, 'key_destroyed',
                v_settlement.settlement_receipt_id)
        ON CONFLICT ON CONSTRAINT memory_pii_key_erasures_once DO NOTHING;
        GET DIAGNOSTICS v_written = ROW_COUNT;
        RETURN v_written;
      END;
      $fn$;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_record_settled_destruction(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_record_settled_destruction(text)
      TO aaliyah_memory_settler;
    -- The obligation ledger: the store records what it could not prove, the
    -- settler closes rows out, and the SELECT-only read-back role lists them
    -- for an operator.
    GRANT SELECT, INSERT ON memory_key_destruction_obligations
      TO aaliyah_memory_mutator;
    -- NOT settled_by. Security review of 86d33c9, LOW, executed: with it,
    -- the mutation role could rewrite an obligation to claim a settlement that
    -- does not exist. No mutator code path writes it: recordObligations
    -- writes the observation columns, and clearHealedObligations writes
    -- resolved_by = PROVIDER, which the CHECK requires to leave settled_by
    -- NULL. Only the settler names a settlement.
    GRANT UPDATE (state, not_proven_reason, observations, last_observed_at,
                  resolved_by)
      ON memory_key_destruction_obligations TO aaliyah_memory_mutator;
    GRANT SELECT ON memory_key_destruction_obligations
      TO aaliyah_memory_reader, aaliyah_memory_settler;
    GRANT UPDATE (state, not_proven_reason, resolved_by, settled_by, last_observed_at)
      ON memory_key_destruction_obligations TO aaliyah_memory_settler;
    GRANT USAGE, SELECT ON SEQUENCE memory_key_destruction_obligations_id_seq
      TO aaliyah_memory_mutator;
    -- Round-robin audit state, maintained only by the pass that audits.
    GRANT SELECT, INSERT ON memory_pii_key_audits TO aaliyah_memory_mutator;
    GRANT UPDATE (last_audited_at, last_state, audits) ON memory_pii_key_audits
      TO aaliyah_memory_mutator`,
  },
  {
    // ------------------------------------------------------------------
    // PUBLIC EXECUTE ON A SECURITY DEFINER FUNCTION IS A READ PRIMITIVE.
    //
    // Security review of 8a0bf05, F4, CONFIRMED by execution (K-16): with
    // `proacl` NULL, EXECUTE is PUBLIC by default, and two SECURITY DEFINER
    // helpers return data rather than a trigger. A role created with NO GRANTS
    // AT ALL (atk_outsider) called them and got:
    //
    //   aaliyah_memory_restricting_hold  -> 'hold-secret-matter-777', the hold
    //                                       id for a held participant, while
    //                                       SELECT on memory_legal_holds was
    //                                       denied;
    //   aaliyah_memory_spent_nonce       -> the full nonce row for a known
    //                                       (tenant, authorization, receipt)
    //                                       triple — action, target record id,
    //                                       binding digest, consumed_at —
    //                                       while SELECT on the nonce table
    //                                       was denied.
    //
    // Rated LOW because it needs a database login and known or guessed ids.
    // It is still a SECURITY DEFINER function handing rows to a principal the
    // table privileges refuse, which is the definition of a privilege boundary
    // that is not where it is documented to be.
    //
    // WHO ACTUALLY NEEDS THEM, from the call sites rather than from the tables:
    //   - `aaliyah_memory_restricting_hold` is called directly by the trusted
    //     memory store under the MUTATION role and by the legal-hold store's
    //     read path under the READER role;
    //   - `aaliyah_memory_spent_nonce` is called from nowhere but inside other
    //     SECURITY DEFINER guards, which run as the function OWNER and so need
    //     no grant at all. No memory role gets it.
    //
    // Also here: security review F5, CONFIRMED by execution (K-17). The
    // reconciler's SELECT on `memory_alias_blind_indexes` and
    // `memory_pii_key_erasures`, and the issuer's and revoker's SELECT on
    // bindings, blind indexes and key erasures, were revoked and the suites
    // ran 266/266. No runtime code in src/ uses the issuer or revoker roles at
    // all. The reconciler keeps its erasure SELECT: it resolves alias
    // mutations and reads that evidence.
    //
    // And the new settlement guard, revoked from PUBLIC for the same reason as
    // every other trigger function — it returns `trigger` and cannot be called
    // usefully, but "cannot be called usefully today" is not a boundary.
    // ------------------------------------------------------------------
    id: "056_memory_least_privilege_trim",
    sql: `REVOKE ALL ON FUNCTION public.aaliyah_memory_restricting_hold(text, text, text, text, text)
      FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.aaliyah_memory_restricting_hold(text, text, text, text, text)
      TO aaliyah_memory_mutator, aaliyah_memory_reader, aaliyah_memory_hold_officer;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_spent_nonce(text, text, text) FROM PUBLIC;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_settlement_binds_real_key() FROM PUBLIC;

    REVOKE SELECT ON memory_alias_blind_indexes FROM aaliyah_memory_reconciler;
    REVOKE SELECT ON memory_alias_bindings, memory_alias_blind_indexes, memory_pii_key_erasures
      FROM aaliyah_memory_issuer, aaliyah_memory_revoker`,
  },
  {
    // ------------------------------------------------------------------
    // AN APPLIED MIGRATION'S CONTENT CANNOT CHANGE UNDER THE LEDGER.
    //
    // Integration review of 86d33c9, HIGH, executed against the real compiled
    // runner: the ledger recorded only an id, so EDITING an already-applied
    // migration's SQL was completely silent. The reviewer migrated a scratch
    // database through 055, weakened 055's trigger function to a no-op, re-ran
    // the real `runMailMigrations` — and it returned successfully with the
    // weakened function still live and nothing reported.
    //
    // W1BR-014 already covers the neighbouring hazard — a ledger ROW deleted
    // and the migration replayed — and refuses an older ordinal over a newer
    // one. It does not cover "row present, content edited", and that variant
    // is not hypothetical: it happened during this very round. Migration 055
    // was edited after being applied to the implementation database, and the
    // only reason anyone noticed was that T-1 happens to assert a property of
    // one of the functions 055 redefines. Nothing was checking.
    //
    // So the ledger now records a digest of the SQL that was applied, and the
    // runner refuses to proceed when an applied migration's content no longer
    // matches it.
    //
    // DISCLOSED LIMIT: rows written before this migration have no digest, so
    // the runner BACKFILLS them from the current source on its next run. A
    // database whose migration content was already edited before 057 has that
    // edit blessed, once, silently — there is nothing to compare it against.
    // Only edits made after the backfill are detectable.
    // ------------------------------------------------------------------
    id: "057_migration_content_digest",
    sql: `ALTER TABLE aaliyah_mail_migrations
      ADD COLUMN IF NOT EXISTS sql_digest text;
    ALTER TABLE aaliyah_mail_migrations
      DROP CONSTRAINT IF EXISTS aaliyah_mail_migrations_digest_shape;
    ALTER TABLE aaliyah_mail_migrations
      ADD CONSTRAINT aaliyah_mail_migrations_digest_shape
        CHECK (sql_digest IS NULL OR sql_digest ~ '^sha256:[0-9a-f]{64}$')`,
  },
  {
    /*
     * A SETTLED OBLIGATION'S RESOLUTION IS IMMUTABLE, ENFORCED BY THE DATABASE.
     *
     * The founder's settlement requirements say a receipt must be "immutable
     * after completion". That held for the settlement ROW (the append-only
     * trigger on memory_key_destruction_settlements), but the OBLIGATION it
     * resolves was protected only by application code: two redundant guards,
     * a `continue` that keeps a settled key out of the provider-healing list
     * and a `state = 'KEY_DESTRUCTION_NOT_PROVEN'` filter on the UPDATE.
     *
     * The seventh pass's sweep found BOTH of them surviving, and found out why:
     * `provenDestroyed` has exactly one consumer, so each guard masks the
     * other. Remove either alone and nothing changes; remove both and a key
     * proven by a SETTLEMENT is recorded as resolved by a PROVIDER that was
     * never asked. Neither is individually falsifiable, which by this
     * register's standard means neither is a control.
     *
     * So the invariant moves to where it can be enforced against any caller
     * and any future code path, and where one statement can falsify it. The
     * two application guards stay as defense in depth; what they are no longer
     * asked to do is BE the enforcement.
     *
     * Observational columns stay writable on purpose: `observations` and
     * `last_observed_at` record that a pass looked again, which is not a
     * change to the resolution.
     */
    id: "058_settled_obligation_resolution_immutable",
    sql: `CREATE OR REPLACE FUNCTION public.aaliyah_memory_settled_obligation_frozen()
      RETURNS trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog, public, pg_temp
      AS $fn$
      BEGIN
        IF OLD.settled_by IS NULL THEN
          RETURN NEW;
        END IF;
        IF NEW.settled_by IS DISTINCT FROM OLD.settled_by
           OR NEW.resolved_by IS DISTINCT FROM OLD.resolved_by
           OR NEW.state IS DISTINCT FROM OLD.state
           OR NEW.not_proven_reason IS DISTINCT FROM OLD.not_proven_reason THEN
          RAISE EXCEPTION
            'aaliyah memory: a settled obligation resolution is immutable'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $fn$;

    ALTER FUNCTION public.aaliyah_memory_settled_obligation_frozen()
      OWNER TO CURRENT_USER;
    REVOKE ALL ON FUNCTION public.aaliyah_memory_settled_obligation_frozen()
      FROM PUBLIC;

    DROP TRIGGER IF EXISTS memory_key_destruction_obligations_settled_frozen
      ON memory_key_destruction_obligations;
    CREATE TRIGGER memory_key_destruction_obligations_settled_frozen
      BEFORE UPDATE ON memory_key_destruction_obligations
      FOR EACH ROW EXECUTE FUNCTION public.aaliyah_memory_settled_obligation_frozen()`,
  },
  {
    /*
     * EVIDENCE MUST ACTUALLY BE EVIDENCE.
     *
     * Red team against a9d203d, HIGH, executed end to end: `evidence` was
     * typed `unknown` in the request, validated nowhere in the store, and
     * constrained only by `evidence jsonb NOT NULL` here — which accepts the
     * jsonb value `null`, because JSON null IS a value. So a settlement
     * carrying NO evidence was recorded, digested to sha256("null"), counted
     * sound by `settlementProven`, wrote destruction evidence carrying its
     * receipt id, and produced
     * `{verified:true, keysDestroyed:1, keysNotProven:0}` for a subject whose
     * key the provider still reported as ACTIVE, with
     * `aaliyah_memory_unerased_merged_records` returning 0. The founder's
     * decision says a settlement must be EVIDENCE-BOUND and that no
     * settlement authority may fabricate provider evidence; nothing enforced
     * either half.
     *
     * Enforced HERE and only here, with the store's catch translating the
     * constraint into a named rejection. That is deliberate: a store
     * pre-check returning the same rejection value would be masked by the
     * translation, which is the defect this project has now hit six times
     * (M-40, M-47, M-55, M-50, M-51, and the self-verification pre-check the
     * a9d203d test review found dead). One enforcement, one translation, one
     * falsifier each.
     *
     * ---- AND IT IS A REFERENCE, NOT PROSE (SEC-04) -------------------
     *
     * The first version of this constraint required a `statement` of at least
     * twenty characters, which INVITED the defect security found in the
     * unconstrained column it replaced: this table is append-only, so any
     * plaintext written here survives for ever in the artifact that COMPLETES
     * an erasure. The reviewer's scan of every text and jsonb column:
     *
     *     sightings of the erased address BEFORE: []
     *     sightings AFTER:  ["memory_key_destruction_settlements.evidence"]
     *     UPDATE (redact) as the owner -> refused: append-only
     *     DELETE as the owner          -> refused: append-only
     *
     * Migration 055 named this hazard six lines from the column — "free text
     * here would be a place for a subject's address to survive a settlement" —
     * and then constrained the DIGEST instead.
     *
     * So the evidence is now a POINTER plus a digest: which kind of proof,
     * WHERE it lives, the sha256 of the document, and when it was witnessed.
     * The `reference` pattern forbids whitespace, so a sentence cannot be
     * written in it. Four members exactly, nothing else, so nothing can be
     * smuggled alongside.
     *
     * RESIDUAL, STATED: a determined operator can still put a short
     * identifier-shaped string in `reference`. That is a bound, not an
     * elimination, and the register says so rather than claiming this ends
     * the class.
     */
    id: "059_settlement_evidence_bound",
    sql: `ALTER TABLE memory_key_destruction_settlements
      DROP CONSTRAINT IF EXISTS memory_key_destruction_settlements_evidence_bound;
    ALTER TABLE memory_key_destruction_settlements
      ADD CONSTRAINT memory_key_destruction_settlements_evidence_bound
        CHECK (
          jsonb_typeof(evidence) = 'object'
          -- EXACTLY these four members and nothing else. Subtracting the known
          -- keys and requiring an empty object is how a CHECK can say "no
          -- other keys", since it cannot contain a subquery over
          -- jsonb_object_keys.
          AND evidence - 'kind' - 'reference' - 'referenceDigest'
                       - 'witnessedAt' = '{}'::jsonb
          AND evidence ?& array['kind','reference','referenceDigest','witnessedAt']
          AND jsonb_typeof(evidence -> 'kind') = 'string'
          AND (evidence ->> 'kind') IN (
                'provider_decommission_certificate',
                'provider_destruction_receipt',
                'hsm_partition_destruction_record',
                'key_custodian_attestation')
          -- A REFERENCE, not prose. No whitespace, so a sentence cannot be
          -- written here, and bounded so a blob cannot either.
          AND jsonb_typeof(evidence -> 'reference') = 'string'
          AND (evidence ->> 'reference') ~ '^[A-Za-z0-9._:/-]{8,200}$'
          -- The DIGEST is what binds the decision to a document this database
          -- deliberately does not hold.
          AND jsonb_typeof(evidence -> 'referenceDigest') = 'string'
          AND (evidence ->> 'referenceDigest') ~ '^sha256:[0-9a-f]{64}$'
          AND jsonb_typeof(evidence -> 'witnessedAt') = 'string'
          AND (evidence ->> 'witnessedAt') ~
              '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
        )`,
  },
  {
    /*
     * A SETTLEMENT POINTER MUST POINT AT A SETTLEMENT.
     *
     * Security review of a9d203d, HIGH, executed. Migration 055 withholds
     * `settled_by` from the mutation role's UPDATE grant and says exactly why:
     * "with it, the mutation role could rewrite an obligation to claim a
     * settlement that does not exist". The grant one line ABOVE that comment
     * is `GRANT SELECT, INSERT` — TABLE-level, which covers every column. So
     * the mutation role could not UPDATE `settled_by`, and could INSERT it
     * freely. Observed:
     *
     *     forged settled obligation INSERTED by the mutation role: true
     *     settlements matching that receipt id: 0
     *     ledger: state PROVEN_DESTROYED, resolvedBy SETTLEMENT,
     *             settledBy "settlement-that-never-existed"
     *     the key really is: active
     *
     * And because `UNIQUE (tenant, workspace, key_ref)` means one row per key,
     * the forgery PRE-EMPTS the slot: the honest completion pass can never
     * record the real state afterwards. Migration 058 then made that row
     * unrepairable by anyone, including the owner — so the previous round's
     * fix turned a forgeable row into a permanent one.
     *
     * Three changes, none of which relies on the others:
     *
     *   1. A FOREIGN KEY. `settled_by` must name a real settlement receipt.
     *      This is the one that closes the forgery outright, whatever any
     *      grant says, and it needs no trigger and no application code.
     *   2. COLUMN-LEVEL INSERT for the mutation role, so the asymmetry between
     *      its INSERT and UPDATE grants is gone. `settled_by` and
     *      `resolved_by` are simply not insertable by it; both default NULL,
     *      which is the only state an honest first observation has.
     *   3. The same for `aaliyah_memory_reconciler`, which holds no INSERT
     *      here today but would inherit the same hole if it ever did.
     *
     * The FK is added VALIDATED deliberately: a row whose `settled_by` names
     * no settlement is corrupt, and a migration that tolerates it while
     * claiming to fix this finding would be the same defect one layer up. If
     * this migration fails on a populated database, that database HAS a forged
     * or orphaned obligation and an operator must look at it.
     */
    id: "060_obligation_settlement_pointer_real",
    sql: `REVOKE INSERT ON memory_key_destruction_obligations
      FROM aaliyah_memory_mutator;
    GRANT INSERT (tenant_id, workspace_id, subject_record_id, alias_id, key_ref,
                  provider_id, binding_mutation_receipt_id, erasure_tombstone_id,
                  state, not_proven_reason, observations,
                  first_observed_at, last_observed_at)
      ON memory_key_destruction_obligations TO aaliyah_memory_mutator;

    ALTER TABLE memory_key_destruction_obligations
      DROP CONSTRAINT IF EXISTS memory_key_destruction_obligations_settled_by_real;
    ALTER TABLE memory_key_destruction_obligations
      ADD CONSTRAINT memory_key_destruction_obligations_settled_by_real
        FOREIGN KEY (settled_by)
        REFERENCES memory_key_destruction_settlements (settlement_receipt_id)`,
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

/**
 * Apply every migration not yet applied, in order.
 *
 * `through` stops after the named migration. It exists for UPGRADE tests: a
 * database populated at an earlier schema and then migrated forward is the
 * shape a real deployment meets, and a fresh apply never exercises it (the
 * 3ba769f integration review). A name that is not a migration id is refused
 * before anything is applied.
 */
/**
 * SQLSTATEs a LOST race to create the same table produces. PostgreSQL does not
 * make `CREATE TABLE IF NOT EXISTS` atomic against a concurrent creator, so
 * the loser sees one of:
 *   `42P07` duplicate_table — the `IF NOT EXISTS` check and the creation are
 *           not one step, and another session finished in between;
 *   `23505` unique_violation — the same race one layer down, on a catalog
 *           index. The observed one is `pg_type_typname_nsp_index`: a
 *           duplicate row for the table's implicit ROW TYPE.
 */
const LEDGER_RACE_LOST = new Set(["42P07", "23505"]);

/**
 * CREATE THE LEDGER, AND DO NOT MIND LOSING THE RACE TO CREATE IT.
 *
 * Reliability review of 86d33c9, HIGH: the previous fix serialized migrators
 * on a session advisory lock and then claimed `LOCK TABLE` would bind anything
 * running an OLDER build. It does not. An advisory lock binds only the
 * participants that take it, and an older build races this statement directly
 * — 10 trials out of 10 on a fresh database, and the instance that died was
 * the NEW one.
 *
 * An older build cannot be bound, so it is not the thing to fix. What matters
 * is that losing the race is HARMLESS: whoever won created the same table with
 * the same definition, so the loser's job is to notice that and carry on. The
 * `PRIMARY KEY` on `id` means the two definitions cannot disagree in a way
 * that matters here, and the ledger's contents are read under `LOCK TABLE`
 * afterwards.
 *
 * Deliberately OUTSIDE any transaction: inside one, a duplicate-object error
 * aborts the transaction that was about to apply the migrations, which is how
 * a tolerable race becomes a failed deployment.
 */
async function createLedgerToleratingARace(bounded: BoundedQuery): Promise<void> {
  try {
    await bounded(
      `CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (
        id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`,
    );
    return;
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (typeof code !== "string" || !LEDGER_RACE_LOST.has(code)) throw error;
    // Lost the race. Confirm the winner actually left a ledger behind rather
    // than assuming it: a duplicate-object error from something that is NOT
    // this table would otherwise be swallowed here.
    const present = await bounded(
      `SELECT to_regclass('public.aaliyah_mail_migrations') IS NOT NULL AS present`,
    );
    if (present.rows[0]?.present !== true) throw error;
  }
}

export async function runMailMigrations(
  pool: Pool,
  options: { through?: string } = {},
): Promise<void> {
  if (options.through !== undefined && !MIGRATIONS.some((m) => m.id === options.through)) {
    throw new Error(`runMailMigrations: no migration named ${options.through}`);
  }
  const client = await pool.connect();
  // BOUNDED, AND WIDER THAN THE POOL'S DEFAULTS ON PURPOSE. A second instance
  // booting during a rolling deploy legitimately waits here for the first
  // one's migrations; DDL over populated tables legitimately takes longer than
  // an ordinary statement. Neither is allowed to wait forever — and the
  // CLIENT's ceiling is raised with the server's, because a 35s client timeout
  // over a 300s server bound would abandon a healthy migration mid-DDL and
  // leave the operator with an ambiguous outcome (03581a3 reliability, K-05).
  const bounded = boundedQuery(client, MIGRATION_BOUNDS.queryTimeoutMs);
  let ambiguous: unknown;
  let inTransaction = false;
  try {
    await bounded(`SET lock_timeout = '${MIGRATION_BOUNDS.lockTimeoutMs}ms'`);
    // ---- CONCURRENT MIGRATORS SERIALIZE BEFORE THE LEDGER EXISTS --------
    //
    // Found by the 03581a3 reliability review (K-06), executed: this runner
    // used to issue `CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations` as
    // its FIRST statement, outside any lock, and only then take the table
    // lock that serializes migrators. `IF NOT EXISTS` is not atomic against a
    // concurrent creator: 2-way and 3-way concurrent runs on a fresh database
    // crashed N-1 instances with `23505` on `pg_type_typname_nsp_index` — a
    // duplicate row for the table's implicit ROW TYPE, raised before the
    // ledger it was about to lock existed at all — and `src/server.ts` turns
    // that into `process.exit(1)`. So every instance of a fresh rolling
    // deploy but one died at boot.
    //
    //
    // ---- AND AN OLDER BUILD CANNOT BE BOUND AT ALL ---------------------
    //
    // The first version of this fix claimed `LOCK TABLE` would "bind a
    // migrator running an OLDER build of this function, which knows nothing
    // about this key." The reliability review of 86d33c9 falsified that, 10
    // trials out of 10 on a fresh database, and it was simply wrong: an
    // advisory lock serializes only the participants that take it, an older
    // build races the CREATE TABLE directly, and LOCK TABLE cannot protect a
    // table that does not exist yet. The build that died was THIS one, with
    // the original defect's exact error.
    //
    // So this build no longer tries to WIN that race — it TOLERATES it. The
    // creation happens outside any transaction, and the duplicate-object
    // errors a lost race produces are swallowed after confirming the ledger
    // really is there. Outside a transaction, losing the race poisons
    // nothing; inside one, the same error would abort the transaction that
    // was about to apply the migrations.
    //
    // ---- AND THE ADVISORY LOCK IS GONE, BECAUSE IT IS REDUNDANT ------
    //
    // It was added to cover the ledger's creation. Now that the creation
    // TOLERATES a lost race, the lock covers nothing that `LOCK TABLE` does
    // not: once the table exists — which it does by the time the transaction
    // below opens — `LOCK TABLE ... ACCESS EXCLUSIVE` serializes every
    // migrator that reaches it, old build or new.
    //
    // Removed rather than kept, because this round's own mutation sweep found
    // it UNFALSIFIABLE after the tolerance fix: deleting the lock broke no
    // test, and there is no property left for a test to hold it to. A
    // mechanism nothing can falsify is a claim, not a control, and this
    // register's standard is the other way round.
    await createLedgerToleratingARace(bounded);

    // ---- ONE CLEANUP PATH, NOT TWO -----------------------------------
    //
    // Reliability review of a9d203d, HIGH, reproduced live with a role
    // lacking CREATE on schema public (42501): this used to be TWO try
    // blocks. The first covered the session `SET lock_timeout` and the
    // ledger creation and had a catch that did
    // `releaseClient(client, error); throw error;` with NO finally — so a
    // real, non-race, non-ambiguous failure of the CREATE returned a
    // perfectly healthy connection to the pool still carrying a 120s
    // `lock_timeout`. Only the SECOND block's finally reset it, and the
    // test written for that reset ("success AND refusal") exercised the
    // success path and the in-transaction ordering refusal — both of which
    // are inside the second block. The one path that leaked was the one
    // path neither covered.
    //
    // The phases still have to be separate (the ledger must be created
    // outside a transaction), but they do NOT need separate cleanup. The
    // transaction starts here, inside the same try, and `inTransaction`
    // tells the catch whether there is anything to roll back.
    await bounded("BEGIN");
    inTransaction = true;
    await bounded(`SET LOCAL lock_timeout = '${MIGRATION_BOUNDS.lockTimeoutMs}ms'`);
    await bounded(`SET LOCAL statement_timeout = '${MIGRATION_BOUNDS.statementTimeoutMs}ms'`);
    // Serialize concurrent migrators, including one running an older build:
    // by here the ledger exists, so there is something to lock.
    await bounded("LOCK TABLE aaliyah_mail_migrations IN ACCESS EXCLUSIVE MODE");
    // The digest column exists only from 057 onward, so a pre-057 database is
    // read without it rather than refused.
    const hasDigest =
      ((
        await bounded(
          `SELECT count(*)::int AS n FROM information_schema.columns
            WHERE table_name = 'aaliyah_mail_migrations' AND column_name = 'sql_digest'`,
        )
      ).rows[0].n as number) === 1;
    const appliedRows = (
      await bounded(
        hasDigest
          ? "SELECT id, sql_digest FROM aaliyah_mail_migrations"
          : "SELECT id, NULL::text AS sql_digest FROM aaliyah_mail_migrations",
      )
    ).rows as Array<{ id: string; sql_digest: string | null }>;
    const applied = new Set(appliedRows.map((r) => r.id));
    const recordedDigest = new Map(appliedRows.map((r) => [r.id, r.sql_digest]));

    // ---- AN APPLIED MIGRATION'S CONTENT MUST NOT HAVE CHANGED --------
    //
    // Integration review of 86d33c9, HIGH: the ledger recorded only an id, so
    // editing an already-applied migration's SQL was silent — proven against
    // the real runner by weakening a trigger function 055 defines and re-running
    // this function, which reported success with the weakened definition live.
    //
    // Checked BEFORE anything is applied, because the point is to refuse the
    // run rather than to notice afterwards.
    for (const migration of MIGRATIONS) {
      const recorded = recordedDigest.get(migration.id);
      if (recorded === undefined || recorded === null) continue;
      const actual = migrationDigest(migration.sql);
      if (recorded !== actual) {
        throw new Error(
          `migration ${migration.id} was applied with different content ` +
            `(${recorded}) than this build carries (${actual}). The database ` +
            `does not hold what this source says it holds. Refusing.`,
        );
      }
    }
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
      if (applied.has(migration.id)) {
        if (migration.id === options.through) break;
        continue;
      }
      const ordinal = migrationOrdinal(migration.id);
      if (ordinal < highestApplied) {
        throw new Error(
          `migration ${migration.id} is older than migration ordinal ` +
            `${highestApplied}, which is already applied. Replaying it would ` +
            `revert any definition a later migration hardened. Refusing.`,
        );
      }
      await bounded(migration.sql);
      await bounded(
        hasDigest
          ? "INSERT INTO aaliyah_mail_migrations (id, sql_digest) VALUES ($1, $2)"
          : "INSERT INTO aaliyah_mail_migrations (id) VALUES ($1)",
        hasDigest ? [migration.id, migrationDigest(migration.sql)] : [migration.id],
      );
      if (migration.id === options.through) break;
    }
    // ---- BACKFILL, ONCE, AND DISCLOSED -------------------------------
    // Rows written before 057 have no digest. They are filled in from the
    // current source, which means a content edit made BEFORE 057 existed is
    // blessed here — there is nothing to compare it against. Only edits after
    // this point are detectable, and the register says so.
    //
    // The column's presence is re-read HERE rather than reused from the top of
    // the run. On a fresh database, 001..056 are applied before 057 exists, so
    // their inserts cannot carry a digest and `hasDigest` was false when they
    // ran — checking again afterwards is what makes a first apply end up fully
    // digested instead of waiting for a second run. A failed statement would
    // abort this transaction, so this asks rather than catching.
    const digestColumnNow =
      ((
        await bounded(
          `SELECT count(*)::int AS n FROM information_schema.columns
            WHERE table_name = 'aaliyah_mail_migrations' AND column_name = 'sql_digest'`,
        )
      ).rows[0].n as number) === 1;
    if (digestColumnNow) {
      for (const migration of MIGRATIONS) {
        await bounded(
          `UPDATE aaliyah_mail_migrations SET sql_digest = $2
            WHERE id = $1 AND sql_digest IS NULL`,
          [migration.id, migrationDigest(migration.sql)],
        );
      }
    }
    await bounded("COMMIT");
  } catch (error) {
    ambiguous = error;
    // ONLY if a transaction was actually opened. The ledger-creation phase
    // runs before `BEGIN`, and issuing `ROLLBACK` there would be a no-op
    // carrying a server warning — harmless, but it would also say this code
    // does not know which phase it failed in, and it does.
    //
    // The rollback itself is bounded and allowed to fail: on a dead backend
    // there is nothing to roll back, and the connection is destroyed below.
    if (inTransaction) {
      await bounded("ROLLBACK").catch(() => undefined);
    }
    throw error;
  } finally {
    // The session `lock_timeout` this runner raised outlives the transaction
    // and would ride back into the pool on this connection unless it is reset.
    //
    // The distinction is the CONNECTION's health, NOT whether the migration
    // failed. An ordinary refusal — W1BR-014's "replaying an older migration"
    // for instance — leaves a perfectly healthy session that must be cleaned
    // up before it is reused; the first version of this cleanup was gated on
    // "did anything throw" and returned a healthy connection to the pool with
    // state still set on it. A BROKEN connection is destroyed instead, which
    // drops the session and everything on it, and must not be spoken to first.
    const broken = ambiguous !== undefined && isConnectionAmbiguous(ambiguous);
    if (!broken) {
      await bounded("RESET lock_timeout").catch(() => undefined);
    }
    releaseClient(client, ambiguous);
  }
}
