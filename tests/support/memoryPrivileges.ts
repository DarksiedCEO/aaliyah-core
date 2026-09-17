import type { Pool } from "pg";

/**
 * EVERY PRIVILEGE THAT REACHES A MEMORY ROLE, READ FROM THE ACLS THEMSELVES.
 *
 * Read from pg_class / pg_attribute / pg_namespace / pg_proc / pg_default_acl
 * with aclexplode, not from information_schema, so a grant to PUBLIC — which
 * every memory role inherits — is an entry like any other, and WITH GRANT
 * OPTION is recorded (a trailing `*`). The test-falsifiability and security
 * reviews of 03581a3 showed the information_schema version, filtered to
 * `aaliyah_*` grantees, blind to five widenings: table and column grants to
 * PUBLIC, schema CREATE, default privileges, and a grant option re-granted to
 * PUBLIC. Role attributes and SECURITY DEFINER functions of any name in
 * public are included for the same reason.
 *
 * Only grantees that reach a memory role are listed: PUBLIC and aaliyah_*.
 * The owner's own implicit privileges are not.
 */
export async function memoryPrivilegeMap(pool: Pool): Promise<Record<string, string[]>> {
  const q = async (sql: string) => (await pool.query(sql)).rows.map((r) => r.entry as string);
  const grantee = `COALESCE((SELECT rolname FROM pg_roles WHERE oid = acl.grantee), 'PUBLIC')`;
  const reaches = `(acl.grantee = 0 OR (SELECT rolname FROM pg_roles WHERE oid = acl.grantee) LIKE 'aaliyah\\_%')`;
  return {
    tables: await q(`
      SELECT ${grantee} || ' ' || c.relname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND n.nspname = 'public'
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
       WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f') AND ${reaches}
       GROUP BY acl.grantee, c.relname ORDER BY 1`),
    columns: await q(`
      SELECT ${grantee} || ' ' || c.relname || '.' || a.attname || ' ' ||
             acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END AS entry
        FROM pg_attribute AS a
        JOIN pg_class AS c ON c.oid = a.attrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND n.nspname = 'public'
        CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
       WHERE a.attnum > 0 AND NOT a.attisdropped AND ${reaches}
       ORDER BY 1`),
    sequences: await q(`
      SELECT ${grantee} || ' ' || c.relname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND n.nspname = 'public'
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
       WHERE c.relkind = 'S' AND ${reaches}
       GROUP BY acl.grantee, c.relname ORDER BY 1`),
    schemas: await q(`
      SELECT ${grantee} || ' ' || n.nspname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_namespace AS n
        CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) AS acl
       WHERE n.nspname = 'public' AND ${reaches}
       GROUP BY acl.grantee, n.nspname ORDER BY 1`),
    defaultPrivileges: await q(`
      SELECT COALESCE((SELECT rolname FROM pg_roles WHERE oid = d.defaclrole), '?') || ' ' ||
             COALESCE((SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace), '*') || ' ' ||
             d.defaclobjtype::text || ' ' || ${grantee} || ' ' || acl.privilege_type AS entry
        FROM pg_default_acl AS d
        CROSS JOIN LATERAL aclexplode(d.defaclacl) AS acl
       ORDER BY 1`),
    functions: await q(`
      SELECT ${grantee} || ' ' || p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND n.nspname = 'public'
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS acl
       WHERE acl.privilege_type = 'EXECUTE' AND ${reaches}
       ORDER BY 1`),
    securityDefiner: await q(`
      SELECT p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND n.nspname = 'public'
       WHERE p.prosecdef
       ORDER BY 1`),
    roleAttributes: await q(`
      SELECT rolname || ' ' || concat_ws(',',
               CASE WHEN rolsuper THEN 'SUPERUSER' END, CASE WHEN rolcreaterole THEN 'CREATEROLE' END,
               CASE WHEN rolcreatedb THEN 'CREATEDB' END, CASE WHEN rolcanlogin THEN 'LOGIN' END,
               CASE WHEN rolreplication THEN 'REPLICATION' END, CASE WHEN rolbypassrls THEN 'BYPASSRLS' END,
               CASE WHEN rolinherit THEN 'INHERIT' END) AS entry
        FROM pg_roles WHERE rolname LIKE 'aaliyah\\_%' ORDER BY 1`),
    memberships: await q(`
      SELECT m.rolname || ' IN ' || r.rolname AS entry
        FROM pg_auth_members AS am
        JOIN pg_roles AS r ON r.oid = am.roleid
        JOIN pg_roles AS m ON m.oid = am.member
       WHERE r.rolname LIKE 'aaliyah\\_%' OR m.rolname LIKE 'aaliyah\\_%'
       ORDER BY 1`),
  };
}
