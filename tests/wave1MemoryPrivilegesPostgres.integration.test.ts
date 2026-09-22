import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { memoryPrivilegeMap } from "./support/memoryPrivileges";
import { lockSharedMemoryTables } from "./support/sharedMemoryTables";

/**
 * EVERY PRIVILEGE OF EVERY MEMORY ROLE IS EXACTLY WHAT IS DECLARED.
 *
 * Found by the confirming sweep at f59a6f7: G-13 (UPDATE/DELETE on attempts to
 * the mutation role) and G-16 (SELECT on alias bindings to the reconciler)
 * survived, because the append-only triggers masked the first and no test ever
 * read bindings as the reconciler. Per-grant tests had closed G-01..G-19 one
 * mutant at a time; this closes the class. Any widening or narrowing of a
 * table, column, sequence or function privilege, and any role membership, is a
 * difference from the declared map, reported by name.
 *
 * The map is declared, not regenerated: tests/support/memoryPrivileges.expected.json
 * is reviewed as code. The named assertions below state the boundaries the
 * register relies on, so a regenerated map that silently absorbed a widening
 * would still fail here.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const EXPECTED = JSON.parse(
  fs.readFileSync(path.join(__dirname, "support/memoryPrivileges.expected.json"), "utf8"),
) as Record<string, string[]>;

let pool: Pool;

before(async () => {
  pool = new Pool({ connectionString: DB_URL, max: 2 });
  await runMailMigrations(pool);
});

after(async () => {
  await pool.end();
});

test("the privilege map of every memory role equals the declared map, section by section", async () => {
  // ---- WHY THIS TAKES THE SHARED-TABLE LOCK -------------------------
  // The map now scans EVERY non-public schema, because objects hidden in
  // another schema were one of the widenings it could not see (red team B2
  // W2/W3, K-08). Several other memory files legitimately create shadow
  // schemas as fixtures — that is how they prove this store never reports
  // success on a read-back that disagrees with the commit — and they hold this
  // lock for their whole run. Comparing without it would read another file's
  // fixture as a privilege widening, which is a flake AND a false accusation.
  const lock = await lockSharedMemoryTables(pool);
  try {
    await compareDeclaredMap();
  } finally {
    await lock.release();
  }
});

async function compareDeclaredMap(): Promise<void> {
  const actual = await memoryPrivilegeMap(pool);
  for (const section of Object.keys(EXPECTED)) {
    const want = new Set(EXPECTED[section]);
    const have = new Set(actual[section]);
    const widened = [...have].filter((entry) => !want.has(entry));
    const narrowed = [...want].filter((entry) => !have.has(entry));
    assert.deepEqual({ section, widened, narrowed }, { section, widened: [], narrowed: [] });
  }
  assert.deepEqual(Object.keys(actual).sort(), Object.keys(EXPECTED).sort());
}

test("the declared map itself keeps the boundaries the register relies on", () => {
  // Entries are `role schema.object privileges`: the schema is part of the
  // identity now, because an object of the same name in ANOTHER schema was one
  // of the widenings the first map could not see (K-08).
  const tables = new Map(
    EXPECTED.tables!.map((entry) => {
      const [role, table, privileges] = entry.split(" ");
      return [`${role} ${table}`, new Set(privileges!.split(","))];
    }),
  );
  const holds = (role: string, table: string, privilege: string) =>
    tables.get(`${role} public.${table}`)?.has(privilege) ?? false;
  // AND NOTHING LIVES OUTSIDE `public`. The migrations create every memory
  // object there, so a declared entry in another schema is either a fixture
  // that leaked into the declaration or a real widening — W2's falsifier.
  for (const section of ["tables", "columns", "sequences", "functions", "securityDefiner", "functionOwners", "triggers"]) {
    for (const entry of EXPECTED[section]!) {
      assert.ok(
        entry.includes("public."),
        `${section} entry outside public: ${entry}`,
      );
    }
  }
  // EVERY GUARD IS TURNED ON. `O` is enabled-for-origin; anything else means a
  // trigger was left disabled, which is how a committed `ALTER TABLE ...
  // DISABLE TRIGGER` in a test helper silently stood two tombstone guards down
  // during this round's own remediation.
  for (const entry of EXPECTED.triggers!) {
    assert.ok(entry.endsWith(" O"), `trigger not enabled: ${entry}`);
  }
  // W1BR-034: the reconciler learns an alias effect through one function, never the binding table.
  assert.equal(holds("aaliyah_memory_reconciler", "memory_alias_bindings", "SELECT"), false);
  // Positive control on the same role: what it must read, it can.
  assert.equal(holds("aaliyah_memory_reconciler", "memory_record_versions", "SELECT"), true);
  assert.equal(holds("aaliyah_memory_reconciler", "memory_reconciliations", "INSERT"), true);
  // Append-only evidence is append-only by PRIVILEGE, not only by trigger.
  for (const table of [
    "memory_mutation_attempts",
    "memory_mutation_receipts",
    "memory_pii_key_erasures",
    "memory_tombstones",
    "memory_identity_edges",
    "memory_reconciliations",
  ]) {
    for (const role of ["aaliyah_memory_mutator", "aaliyah_memory_reconciler", "aaliyah_memory_reader"]) {
      assert.equal(holds(role, table, "UPDATE"), false, `${role} UPDATE ${table}`);
      assert.equal(holds(role, table, "DELETE"), false, `${role} DELETE ${table}`);
    }
  }
  // The mutation role cannot issue authorizations, and the reader writes nothing.
  assert.equal(holds("aaliyah_memory_mutator", "memory_authorization_receipts", "INSERT"), false);
  for (const entry of EXPECTED.tables!) {
    if (entry.startsWith("aaliyah_memory_reader ")) assert.equal(entry.split(" ")[2], "SELECT", entry);
    if (entry.startsWith("aaliyah_memory_settler ")) {
      // The settler writes settlements and the destruction evidence a
      // PROVEN_DESTROYED settlement produces, and reads nothing else.
      assert.match(entry, /^aaliyah_memory_settler public\.(memory_key_destruction_settlements|memory_key_destruction_obligations|memory_pii_key_erasures) /, entry);
    }
  }
  // No memory role is a member of another.
  assert.deepEqual(EXPECTED.memberships, []);
  // Test-falsifiability and security reviews of 03581a3: the boundaries below
  // were invisible to the first map.
  for (const section of ["tables", "columns", "sequences"]) {
    for (const entry of EXPECTED[section]!) {
      assert.ok(!entry.startsWith("PUBLIC "), `PUBLIC holds ${entry}`);
    }
  }
  for (const section of Object.keys(EXPECTED)) {
    for (const entry of EXPECTED[section]!) assert.ok(!entry.includes("*"), `grant option: ${entry}`);
  }
  assert.deepEqual(EXPECTED.schemas, ["PUBLIC public USAGE"]);
  assert.deepEqual(EXPECTED.defaultPrivileges, []);
  for (const entry of EXPECTED.roleAttributes!) {
    assert.doesNotMatch(entry, /SUPERUSER|CREATEROLE|CREATEDB|LOGIN|REPLICATION|BYPASSRLS/, entry);
  }
  for (const fn of EXPECTED.securityDefiner!) assert.match(fn, /^public\.aaliyah_/, fn);
  // A SECURITY DEFINER function runs with its OWNER's privileges, so an owner
  // that is not the table owner is a privilege change with no ACL diff (W5).
  for (const fn of EXPECTED.securityDefiner!) {
    assert.match(fn, / OWNER postgres$/, `unexpected SECURITY DEFINER owner: ${fn}`);
  }
  // The database grants nothing beyond PostgreSQL's own default. `CREATE ON
  // DATABASE` is the grant that made ATK-P1 work, and it must show up here.
  assert.deepEqual(EXPECTED.databases, ["PUBLIC <current> CONNECT,TEMPORARY"]);
  // No catalog function has been granted to a memory role (W4:
  // `pg_read_file` reached the reader exactly that way).
  assert.deepEqual(EXPECTED.catalogFunctions, []);
  // ---- THE FIVE THE RED TEAM FOUND STILL INVISIBLE (B4) ------------
  // A RULE can swallow a write without firing a single trigger — the class
  // `tgenabled` was added for and does not cover.
  assert.deepEqual(EXPECTED.rules, []);
  assert.deepEqual(EXPECTED.parameterPrivileges, []);
  assert.deepEqual(EXPECTED.typePrivileges, []);
  assert.deepEqual(EXPECTED.membershipOptions, []);
  // Every guard still pins its own path, declared here and not only asserted
  // by T-1: `ALTER FUNCTION ... RESET search_path` changes no ACL and no body.
  for (const entry of EXPECTED.functionConfig!) {
    assert.match(entry, /search_path=pg_catalog, public, pg_temp$/, entry);
  }
  // Each new helper is executable only by the one role that needs it.
  const executes = (fn: string) =>
    EXPECTED.functions!.filter((entry) => entry.endsWith(` public.${fn}`)).map((entry) => entry.split(" ")[0]).sort();
  assert.deepEqual(executes("aaliyah_memory_alias_effect_present(text,text,text,text,text,text)"), ["aaliyah_memory_reconciler"]);
  assert.deepEqual(executes("aaliyah_memory_unerased_merged_records(text,text,text)"), ["aaliyah_memory_mutator"]);
  assert.deepEqual(executes("aaliyah_memory_merge_chain_hops(text,text,text,text)"), ["aaliyah_memory_mutator"]);
});

test("POSITIVE CONTROL: each widening the first map could not see IS reported, then removed", async () => {
  // The five widenings the test-falsifiability review of 03581a3 left
  // surviving, plus the grant option and role attribute from the security
  // review. Each is applied, must change the map, and is reverted.
  const widenings: Array<{ apply: string; revert: string; section: string; entry: string }> = [
    { apply: `GRANT SELECT ON memory_authorization_receipts TO PUBLIC`, revert: `REVOKE SELECT ON memory_authorization_receipts FROM PUBLIC`, section: "tables", entry: "PUBLIC public.memory_authorization_receipts SELECT" },
    { apply: `GRANT INSERT ON memory_tombstones TO PUBLIC`, revert: `REVOKE INSERT ON memory_tombstones FROM PUBLIC`, section: "tables", entry: "PUBLIC public.memory_tombstones INSERT" },
    { apply: `GRANT UPDATE (state) ON memory_record_versions TO PUBLIC`, revert: `REVOKE UPDATE (state) ON memory_record_versions FROM PUBLIC`, section: "columns", entry: "PUBLIC public.memory_record_versions.state UPDATE" },
    { apply: `GRANT CREATE ON SCHEMA public TO aaliyah_memory_reader`, revert: `REVOKE CREATE ON SCHEMA public FROM aaliyah_memory_reader`, section: "schemas", entry: "aaliyah_memory_reader public CREATE" },
    { apply: `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO aaliyah_memory_mutator`, revert: `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM aaliyah_memory_mutator`, section: "defaultPrivileges", entry: "postgres public r aaliyah_memory_mutator SELECT" },
    { apply: `GRANT SELECT ON memory_alias_bindings TO aaliyah_memory_issuer WITH GRANT OPTION`, // The FULL revoke, not just the option: migration 056 trimmed the
      // issuer's SELECT on bindings away entirely (security F5, K-17), so
      // revoking only the grant option would leave a privilege behind that
      // the declared map no longer contains — and the next run of the
      // comparison test would report it as a widening this test caused.
      revert: `REVOKE SELECT ON memory_alias_bindings FROM aaliyah_memory_issuer`, section: "tables", entry: "aaliyah_memory_issuer public.memory_alias_bindings SELECT*" },
    { apply: `ALTER ROLE aaliyah_memory_reconciler BYPASSRLS`, revert: `ALTER ROLE aaliyah_memory_reconciler NOBYPASSRLS`, section: "roleAttributes", entry: "aaliyah_memory_reconciler BYPASSRLS,INHERIT" },

    // ---- THE FIVE THE SECOND MAP COULD NOT SEE EITHER ----------------
    // Red team B2 and security map2.ts against 8a0bf05 (K-08). Each of these
    // produced NO DIFF AT ALL, and W1 is the one that let a survivor's
    // erasure verify over a live key.
    //
    // W1: CREATE ON DATABASE. The grant that makes a `"$user"` shadow schema
    // possible in the first place, and the reason `enterMemoryRole` now
    // strips `"$user"` from the path.
    {
      apply: `DO $do$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO aaliyah_memory_mutator', current_database()); END $do$`,
      revert: `DO $do$ BEGIN EXECUTE format('REVOKE CREATE ON DATABASE %I FROM aaliyah_memory_mutator', current_database()); END $do$`,
      section: "databases",
      entry: "aaliyah_memory_mutator <current> CREATE",
    },
    // W4: a pg_catalog function granted deliberately. `pg_read_file` reached
    // the reader exactly this way and read 29,950 bytes of postgresql.conf.
    {
      apply: `GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO aaliyah_memory_reader`,
      revert: `REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM aaliyah_memory_reader`,
      section: "catalogFunctions",
      entry: "aaliyah_memory_reader pg_read_file(text)",
    },
    // W5: an OWNER change on a SECURITY DEFINER function. No ACL moves, and
    // the function now runs with a different role's privileges.
    {
      apply: `ALTER FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) OWNER TO aaliyah_memory_reader`,
      revert: `ALTER FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) OWNER TO postgres`,
      section: "securityDefiner",
      entry: "public.aaliyah_memory_unerased_merged_records(text,text,text) OWNER aaliyah_memory_reader",
    },
  ];
  const sharedTableLock = await lockSharedMemoryTables(pool);
  try {
    for (const widening of widenings) {
      await pool.query(widening.apply);
      try {
        const actual = await memoryPrivilegeMap(pool);
        assert.ok(actual[widening.section]!.includes(widening.entry), `${widening.apply}: ${JSON.stringify(actual[widening.section])}`);
        assert.ok(!EXPECTED[widening.section]!.includes(widening.entry), widening.entry);
      } finally {
        await pool.query(widening.revert);
      }
    }
    // ---- COMPARED INSIDE THE LOCK ---------------------------------
    // The test-falsifiability review of 86d33c9 caught this as a real
    // NONDETERMINISM, empirically: this comparison used to run AFTER
    // `sharedTableLock.release()`, and the K-10 boot test in
    // wave1PoolResiliencePostgres takes the SAME advisory key and transiently
    // revokes exactly two privileges mid-test. One run in four came back with
    // a diff naming precisely those two privileges and nothing else. The suite
    // was reporting a privilege narrowing that no code had made.
    const restored = await memoryPrivilegeMap(pool);
    for (const section of Object.keys(EXPECTED)) {
      assert.deepEqual([...restored[section]!].sort(), [...EXPECTED[section]!].sort(), section);
    }
  } finally {
    await sharedTableLock.release();
  }
});

test("POSITIVE CONTROL: W2/W3 — an object HIDDEN IN ANOTHER SCHEMA is reported, then removed", async () => {
  // Red team B2 against 8a0bf05 (K-08). Both of these produced NO DIFF while
  // every section of the map filtered `nspname = 'public'`, and both WORKED:
  // the reconciler read the view, and the reader executed the function.
  const lock = await lockSharedMemoryTables(pool);
  try {
    await pool.query(`DROP SCHEMA IF EXISTS w23_probe CASCADE`);
    await pool.query(`CREATE SCHEMA w23_probe`);
    await pool.query(`GRANT USAGE ON SCHEMA w23_probe TO aaliyah_memory_reconciler, aaliyah_memory_reader`);
    // W2: a view over the binding table, in another schema.
    await pool.query(
      `CREATE VIEW w23_probe.borrowed_bindings AS SELECT * FROM public.memory_alias_bindings`,
    );
    await pool.query(`GRANT SELECT ON w23_probe.borrowed_bindings TO aaliyah_memory_reconciler`);
    // W3: a SECURITY DEFINER function, in another schema.
    await pool.query(
      `CREATE FUNCTION w23_probe.borrowed_reader() RETURNS bigint
         LANGUAGE sql SECURITY DEFINER
         SET search_path = pg_catalog, public, pg_temp
         AS $fn$ SELECT count(*) FROM public.memory_alias_bindings $fn$`,
    );
    await pool.query(`GRANT EXECUTE ON FUNCTION w23_probe.borrowed_reader() TO aaliyah_memory_reader`);

    const actual = await memoryPrivilegeMap(pool);
    assert.ok(
      actual.tables!.includes("aaliyah_memory_reconciler w23_probe.borrowed_bindings SELECT"),
      `W2 not reported: ${JSON.stringify(actual.tables!.filter((e) => e.includes("w23_probe")))}`,
    );
    assert.ok(
      actual.functions!.includes("aaliyah_memory_reader w23_probe.w23_probe.borrowed_reader()") ||
        actual.functions!.some((e) => e.startsWith("aaliyah_memory_reader ") && e.includes("borrowed_reader")),
      `W3 not reported in functions: ${JSON.stringify(actual.functions!.filter((e) => e.includes("borrowed")))}`,
    );
    assert.ok(
      actual.securityDefiner!.some((e) => e.includes("w23_probe.borrowed_reader")),
      `W3 not reported in securityDefiner: ${JSON.stringify(actual.securityDefiner!.filter((e) => e.includes("borrowed")))}`,
    );
    // And none of it is in the DECLARED map.
    for (const section of ["tables", "functions", "securityDefiner"]) {
      for (const entry of EXPECTED[section]!) {
        assert.ok(!entry.includes("w23_probe"), `declared map already contains ${entry}`);
      }
    }
    // Removed: the map is back to the declared one. Compared INSIDE the lock,
    // because another memory file may be legitimately mid-privilege-change of
    // its own — the K-10 boot test revokes and restores two grants — and a
    // comparison outside the lock reads that window as a narrowing this test
    // caused. Seen exactly that way in a full-suite run.
    await pool.query(`DROP SCHEMA IF EXISTS w23_probe CASCADE`);
    await compareDeclaredMap();
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS w23_probe CASCADE`);
    await lock.release();
  }
});

test("POSITIVE CONTROL: B4 — a RULE, a RESET search_path, and a parameter grant are all reported", async () => {
  // Red team against 86d33c9, MEDIUM (B4). Each of these produced NO DIFF
  // while the map had no section for it, and the first one is the dangerous
  // one: a rule does not disable a trigger, it removes the write the trigger
  // would have seen. The reviewer watched an insert the guard exists to reject
  // disappear with the trigger never firing.
  const lock = await lockSharedMemoryTables(pool);
  const cases: Array<{ apply: string; revert: string; section: string; match: RegExp }> = [
    {
      apply: `CREATE RULE zz_b4_swallow AS ON INSERT TO memory_pii_key_erasures DO INSTEAD NOTHING`,
      revert: `DROP RULE IF EXISTS zz_b4_swallow ON memory_pii_key_erasures`,
      section: "rules",
      match: /^public\.memory_pii_key_erasures zz_b4_swallow$/,
    },
    {
      apply: `ALTER FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) RESET search_path`,
      revert: `ALTER FUNCTION public.aaliyah_memory_unerased_merged_records(text, text, text) SET search_path = pg_catalog, public, pg_temp`,
      section: "functionConfig",
      match: /aaliyah_memory_unerased_merged_records\(text,text,text\) <none>$/,
    },
    {
      apply: `GRANT SET ON PARAMETER statement_timeout TO aaliyah_memory_reader`,
      revert: `REVOKE SET ON PARAMETER statement_timeout FROM aaliyah_memory_reader`,
      section: "parameterPrivileges",
      match: /^aaliyah_memory_reader statement_timeout SET$/,
    },
    {
      apply: `GRANT aaliyah_memory_reader TO aaliyah_memory_reconciler WITH ADMIN OPTION`,
      revert: `REVOKE aaliyah_memory_reader FROM aaliyah_memory_reconciler`,
      section: "membershipOptions",
      match: /^aaliyah_memory_reconciler IN aaliyah_memory_reader .*ADMIN/,
    },
  ];
  try {
    for (const one of cases) {
      await pool.query(one.apply);
      try {
        const actual = await memoryPrivilegeMap(pool);
        assert.ok(
          actual[one.section]!.some((entry) => one.match.test(entry)),
          `${one.apply}: ${JSON.stringify(actual[one.section])}`,
        );
        assert.ok(
          !EXPECTED[one.section]!.some((entry) => one.match.test(entry)),
          `the declared map already contains it: ${one.apply}`,
        );
      } finally {
        await pool.query(one.revert);
      }
    }
    await compareDeclaredMap();
  } finally {
    await lock.release();
  }
});

test("POSITIVE CONTROL: a widened grant IS reported as a difference, then removed", async () => {
  // A GRANT rewrites the table's catalog row. Under the suite's shared
  // memory-table lock, like every file that changes shared tables, so it never
  // races another file's DDL ("tuple concurrently updated", seen at 3569122).
  const sharedTableLock = await lockSharedMemoryTables(pool);
  await pool.query(`GRANT SELECT ON memory_alias_bindings TO aaliyah_memory_reconciler`);
  try {
    const actual = await memoryPrivilegeMap(pool);
    assert.ok(
      actual.tables!.includes("aaliyah_memory_reconciler public.memory_alias_bindings SELECT"),
      JSON.stringify(actual.tables),
    );
    assert.ok(!EXPECTED.tables!.includes("aaliyah_memory_reconciler public.memory_alias_bindings SELECT"));
    // Removed, checked inside the lock for the same reason as above.
    await pool.query(`REVOKE SELECT ON memory_alias_bindings FROM aaliyah_memory_reconciler`);
    assert.ok(
      !(await memoryPrivilegeMap(pool)).tables!.includes(
        "aaliyah_memory_reconciler public.memory_alias_bindings SELECT",
      ),
    );
  } finally {
    await pool.query(`REVOKE SELECT ON memory_alias_bindings FROM aaliyah_memory_reconciler`);
    await sharedTableLock.release();
  }
});

test("R3.4 / G-07: the databases section reads BOTH branches of its NULL-datacl fallback — reached by construction, not by luck", async () => {
  // ---- A PUBLISHED UNREACHABILITY PROOF, FALSIFIED (candidate-4 RT4-6) ----
  // The register classified the `COALESCE(d.datacl, acldefault(...))`
  // fallback STRUCTURALLY_UNREACHABLE_WITH_PROOF: "every database created with
  // CREATE DATABASE inherits a non-null ACL from template1". False — the red
  // team showed a freshly created database has datacl NULL, including the
  // harness's own. So the suite only ever took the NULL branch, and never the
  // other. Both are driven here, on a database this test creates.
  const name = "aaliyah_datacl_probe";
  const admin = new Pool({ connectionString: DB_URL, max: 1 });
  admin.on("error", () => undefined);
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${name}`);
  const probe = new Pool({ connectionString: DB_URL.replace(/\/[^/]+$/, `/${name}`), max: 1 });
  probe.on("error", () => undefined);
  const datacl = async () =>
    (await admin.query(`SELECT datacl IS NULL AS unset FROM pg_database WHERE datname = $1`, [name])).rows[0].unset as boolean;
  try {
    // BRANCH 1 — datacl NULL: the implicit default must be VISIBLE, not silent.
    assert.equal(await datacl(), true, "fixture precondition: a freshly created database has datacl NULL");
    assert.deepEqual((await memoryPrivilegeMap(probe)).databases, ["PUBLIC <current> CONNECT,TEMPORARY"]);

    // BRANCH 2 — datacl set by an explicit grant: the stored ACL is what is read.
    await admin.query(`GRANT CONNECT ON DATABASE ${name} TO aaliyah_memory_reader`);
    assert.equal(await datacl(), false, "fixture precondition: an explicit grant sets datacl");
    assert.deepEqual((await memoryPrivilegeMap(probe)).databases, [
      "PUBLIC <current> CONNECT,TEMPORARY",
      "aaliyah_memory_reader <current> CONNECT",
    ]);
    // ...and a REVOKE from PUBLIC must disappear from it: a fallback that
    // ignored the stored ACL would still report the default here.
    await admin.query(`REVOKE CONNECT, TEMPORARY ON DATABASE ${name} FROM PUBLIC`);
    assert.deepEqual((await memoryPrivilegeMap(probe)).databases, ["aaliyah_memory_reader <current> CONNECT"]);
  } finally {
    await probe.end().catch(() => undefined);
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`).catch(() => undefined);
    await admin.end();
  }
});
