import type { Pool } from "pg";

/**
 * EVERY PRIVILEGE A MEMORY ROLE HOLDS, READ FROM THE CATALOG.
 *
 * Tables and views, columns, sequences, the aaliyah_* functions (including
 * what PUBLIC may execute) and role membership, in public only — shadow
 * schemas that tests create are not part of the deployed surface.
 */
export async function memoryPrivilegeMap(pool: Pool): Promise<Record<string, string[]>> {
  const q = async (sql: string) => (await pool.query(sql)).rows.map((r) => r.entry as string);
  return {
    tables: await q(`
      SELECT grantee || ' ' || table_name || ' ' || string_agg(privilege_type, ',' ORDER BY privilege_type) AS entry
        FROM information_schema.role_table_grants
       WHERE grantee LIKE 'aaliyah\\_%' AND table_schema = 'public'
       GROUP BY grantee, table_name ORDER BY 1`),
    columns: await q(`
      SELECT c.grantee || ' ' || c.table_name || '.' || c.column_name || ' ' || c.privilege_type AS entry
        FROM information_schema.column_privileges AS c
       WHERE c.grantee LIKE 'aaliyah\\_%' AND c.table_schema = 'public'
         AND NOT EXISTS (
           SELECT 1 FROM information_schema.role_table_grants AS t
            WHERE t.grantee = c.grantee AND t.table_schema = c.table_schema
              AND t.table_name = c.table_name AND t.privilege_type = c.privilege_type)
       ORDER BY 1`),
    sequences: await q(`
      SELECT r.rolname || ' ' || s.relname || ' ' ||
             concat_ws(',', CASE WHEN has_sequence_privilege(r.oid, s.oid, 'USAGE') THEN 'USAGE' END,
                            CASE WHEN has_sequence_privilege(r.oid, s.oid, 'UPDATE') THEN 'UPDATE' END) AS entry
        FROM pg_class AS s
        JOIN pg_namespace AS n ON n.oid = s.relnamespace AND n.nspname = 'public'
        CROSS JOIN pg_roles AS r
       WHERE s.relkind = 'S' AND s.relname LIKE 'memory\\_%' AND r.rolname LIKE 'aaliyah\\_memory\\_%'
         AND (has_sequence_privilege(r.oid, s.oid, 'USAGE') OR has_sequence_privilege(r.oid, s.oid, 'UPDATE'))
         AND NOT r.rolsuper
       ORDER BY 1`),
    functions: await q(`
      SELECT COALESCE(grantee.rolname, 'PUBLIC') || ' ' || p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND n.nspname = 'public'
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS acl
        LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
       WHERE p.proname LIKE 'aaliyah\\_%' AND acl.privilege_type = 'EXECUTE'
         AND (acl.grantee = 0 OR grantee.rolname LIKE 'aaliyah\\_%')
       ORDER BY 1`),
    memberships: await q(`
      SELECT m.rolname || ' IN ' || r.rolname AS entry
        FROM pg_auth_members AS am
        JOIN pg_roles AS r ON r.oid = am.roleid
        JOIN pg_roles AS m ON m.oid = am.member
       WHERE r.rolname LIKE 'aaliyah\\_%' OR m.rolname LIKE 'aaliyah\\_%'
       ORDER BY 1`),
  };
}
