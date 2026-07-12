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
