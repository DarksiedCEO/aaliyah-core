import type { Pool } from "pg";

/**
 * EVERY PRIVILEGE THAT REACHES A MEMORY ROLE, READ FROM THE ACLS THEMSELVES.
 *
 * Read from pg_database / pg_class / pg_attribute / pg_namespace / pg_proc /
 * pg_default_acl with aclexplode, not from information_schema, so a grant to
 * PUBLIC — which every memory role inherits — is an entry like any other, and
 * WITH GRANT OPTION is recorded (a trailing `*`). The test-falsifiability and
 * security reviews of 03581a3 showed the information_schema version, filtered
 * to `aaliyah_*` grantees, blind to five widenings: table and column grants to
 * PUBLIC, schema CREATE, default privileges, and a grant option re-granted to
 * PUBLIC. Role attributes and SECURITY DEFINER functions of any name are
 * included for the same reason.
 *
 * ---- WHAT THE REWRITE AT 8a0bf05 STILL COULD NOT SEE -------------------
 *
 * Red team B2 and security map2.ts against 8a0bf05, each with a working
 * proof of concept (K-07, K-08). Every section filtered `nspname = 'public'`
 * and nothing read `pg_database.datacl`, so FIVE more widenings produced NO
 * DIFF AT ALL:
 *
 *   W1  `GRANT CREATE ON DATABASE` — the mutator then created a schema named
 *       after itself, which `"$user"` resolves to FIRST, shadowed
 *       `memory_identity_edges`, and a survivor's erasure verified over a LIVE
 *       key with forged evidence. The single most consequential one.
 *   W2  a VIEW over `memory_alias_bindings` in another schema, granted to the
 *       reconciler. It read from it.
 *   W3  a SECURITY DEFINER function in another schema, granted to the reader.
 *       It ran.
 *   W4  `GRANT EXECUTE ON pg_catalog.pg_read_file(text)` to the reader. It
 *       read 29,950 bytes of postgresql.conf.
 *   W5  a function OWNER change — which silently changes whose privileges a
 *       SECURITY DEFINER function runs with.
 *
 * Plus, present and undeclared at that SHA: every memory role held TEMP and
 * CONNECT on the database through PUBLIC, and `pg_temp.memory_identity_edges`
 * resolved unqualified.
 *
 * So the scans below cover EVERY non-system schema and name it in the entry,
 * the database ACL is a section of its own, explicitly granted `pg_catalog`
 * functions are a section of their own, and owners are recorded.
 *
 * `pg_temp_*` and `pg_toast*` are excluded from the object scans on purpose:
 * they are session-local, so including them would make the declared map
 * depend on which backends happen to exist. The property that matters about
 * pg_temp is that nothing resolves there unintentionally, which the stores now
 * carry by pinning `search_path` with `pg_temp` LAST (see `enterMemoryRole`),
 * and the TEMP privilege that allows it at all is declared in `databases`.
 *
 * Only grantees that reach a memory role are listed: PUBLIC and aaliyah_*.
 * The owner's own implicit privileges are not.
 */
export async function memoryPrivilegeMap(pool: Pool): Promise<Record<string, string[]>> {
  const q = async (sql: string) => (await pool.query(sql)).rows.map((r) => r.entry as string);
  const grantee = `COALESCE((SELECT rolname FROM pg_roles WHERE oid = acl.grantee), 'PUBLIC')`;
  const reaches = `(acl.grantee = 0 OR (SELECT rolname FROM pg_roles WHERE oid = acl.grantee) LIKE 'aaliyah\\_%')`;
  // Every schema a memory role could resolve an unqualified name in, except
  // the session-local ones. See the header.
  const userSchema = `n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_temp\\_%' AND n.nspname NOT LIKE 'pg\\_toast%'`;
  return {
    /**
     * W1 AND THE UNDECLARED TEMP/CONNECT. `datacl` is NULL on a freshly
     * created database and that does NOT mean "no privileges" — it means the
     * built-in default, which grants CONNECT and TEMPORARY to PUBLIC.
     * `acldefault('d', ...)` is what makes the implicit grant visible, so the
     * declared map states it instead of being silent about it.
     */
    databases: await q(`
      -- The literal '<current>' rather than the name: the declared map is a
      -- statement about THIS database's privileges, and a reviewer running on
      -- a differently named database is not a widening.
      SELECT ${grantee} || ' <current> ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_database AS d
        CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) AS acl
       WHERE d.datname = current_database() AND ${reaches}
       GROUP BY acl.grantee ORDER BY 1`),
    tables: await q(`
      SELECT ${grantee} || ' ' || n.nspname || '.' || c.relname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND ${userSchema}
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
       WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f') AND ${reaches}
       GROUP BY acl.grantee, n.nspname, c.relname ORDER BY 1`),
    columns: await q(`
      SELECT ${grantee} || ' ' || n.nspname || '.' || c.relname || '.' || a.attname || ' ' ||
             acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END AS entry
        FROM pg_attribute AS a
        JOIN pg_class AS c ON c.oid = a.attrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND ${userSchema}
        CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
       WHERE a.attnum > 0 AND NOT a.attisdropped AND ${reaches}
       ORDER BY 1`),
    sequences: await q(`
      SELECT ${grantee} || ' ' || n.nspname || '.' || c.relname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND ${userSchema}
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
       WHERE c.relkind = 'S' AND ${reaches}
       GROUP BY acl.grantee, n.nspname, c.relname ORDER BY 1`),
    /**
     * Every non-system schema, not just `public`. A schema a memory role can
     * USE or CREATE in is a schema it can resolve a name in (W1, W2, W3).
     */
    schemas: await q(`
      SELECT ${grantee} || ' ' || n.nspname || ' ' ||
             string_agg(acl.privilege_type || CASE WHEN acl.is_grantable THEN '*' ELSE '' END, ',' ORDER BY acl.privilege_type) AS entry
        FROM pg_namespace AS n
        CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) AS acl
       WHERE ${userSchema} AND ${reaches}
       GROUP BY acl.grantee, n.nspname ORDER BY 1`),
    defaultPrivileges: await q(`
      SELECT COALESCE((SELECT rolname FROM pg_roles WHERE oid = d.defaclrole), '?') || ' ' ||
             COALESCE((SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace), '*') || ' ' ||
             d.defaclobjtype::text || ' ' || ${grantee} || ' ' || acl.privilege_type AS entry
        FROM pg_default_acl AS d
        CROSS JOIN LATERAL aclexplode(d.defaclacl) AS acl
       ORDER BY 1`),
    functions: await q(`
      SELECT ${grantee} || ' ' || n.nspname || '.' || p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND ${userSchema}
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS acl
       WHERE acl.privilege_type = 'EXECUTE' AND ${reaches}
       ORDER BY 1`),
    /**
     * W4. Catalog functions are PUBLIC-executable by default, which is why
     * only an EXPLICIT `proacl` is interesting here: a non-NULL ACL on a
     * `pg_catalog` function means somebody granted it deliberately, and
     * `pg_read_file` reached the reader exactly that way.
     */
    catalogFunctions: await q(`
      SELECT ${grantee} || ' ' || p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND n.nspname = 'pg_catalog'
        CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
       WHERE p.proacl IS NOT NULL AND acl.privilege_type = 'EXECUTE' AND ${reaches}
       ORDER BY 1`),
    /**
     * W3 and W5: schema AND owner, because a SECURITY DEFINER function runs
     * with its owner's privileges — so repointing the owner changes what the
     * function can do without changing one byte of its body or its ACL.
     */
    securityDefiner: await q(`
      SELECT n.nspname || '.' || p.oid::regprocedure::text || ' OWNER ' ||
             COALESCE((SELECT rolname FROM pg_roles WHERE oid = p.proowner), '?') AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND ${userSchema}
       WHERE p.prosecdef
       ORDER BY 1`),
    /** W5, for the rest: who owns the functions this schema's guards live in. */
    functionOwners: await q(`
      SELECT COALESCE((SELECT rolname FROM pg_roles WHERE oid = p.proowner), '?') || ' OWNS ' ||
             n.nspname || '.' || p.oid::regprocedure::text AS entry
        FROM pg_proc AS p
        JOIN pg_namespace AS n ON n.oid = p.pronamespace AND ${userSchema}
       WHERE p.proname LIKE 'aaliyah\\_%'
       ORDER BY 1`),
    /**
     * EVERY GUARD, AND WHETHER IT IS TURNED ON.
     *
     * The register discloses this hazard and says there is no structural
     * defense: "DDL state left behind by a SIGKILLed test — a test killed
     * while it has a trigger disabled leaves that state for the next run."
     * This section IS the structural defense, and it was added because the
     * hazard fired for real during this round's remediation — not from a
     * SIGKILL but from an ordinary bug: a helper that stood two tombstone
     * triggers down inside a transaction and then COMMITTED, which is
     * persistent DDL. `memory_tombstones_structural` and
     * `memory_tombstones_zz_authorization_scope` stayed `tgenabled = 'D'` in
     * the shared database afterwards, and three guard tests then failed with
     * unrelated constraint errors — because the guards they exist to prove
     * were simply not running any more. Silent, and indistinguishable from a
     * product defect while you are reading the failure.
     *
     * `tgenabled` is part of the declared surface, so a disabled guard is a
     * DIFF rather than a mystery. `O` is enabled for origin, which is what
     * every one of these must be.
     */
    triggers: await q(`
      SELECT n.nspname || '.' || c.relname || ' ' || t.tgname || ' ' || t.tgenabled::text AS entry
        FROM pg_trigger AS t
        JOIN pg_class AS c ON c.oid = t.tgrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace AND ${userSchema}
       WHERE NOT t.tgisinternal AND c.relname LIKE 'memory\\_%'
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
