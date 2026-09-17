import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { memoryPrivilegeMap } from "./support/memoryPrivileges";

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
  const actual = await memoryPrivilegeMap(pool);
  for (const section of Object.keys(EXPECTED)) {
    const want = new Set(EXPECTED[section]);
    const have = new Set(actual[section]);
    const widened = [...have].filter((entry) => !want.has(entry));
    const narrowed = [...want].filter((entry) => !have.has(entry));
    assert.deepEqual({ section, widened, narrowed }, { section, widened: [], narrowed: [] });
  }
  assert.deepEqual(Object.keys(actual).sort(), Object.keys(EXPECTED).sort());
});

test("the declared map itself keeps the boundaries the register relies on", () => {
  const tables = new Map(
    EXPECTED.tables!.map((entry) => {
      const [role, table, privileges] = entry.split(" ");
      return [`${role} ${table}`, new Set(privileges!.split(","))];
    }),
  );
  const holds = (role: string, table: string, privilege: string) =>
    tables.get(`${role} ${table}`)?.has(privilege) ?? false;
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
  }
  // No memory role is a member of another.
  assert.deepEqual(EXPECTED.memberships, []);
  // Each new helper is executable only by the one role that needs it.
  const executes = (fn: string) =>
    EXPECTED.functions!.filter((entry) => entry.endsWith(` ${fn}`)).map((entry) => entry.split(" ")[0]).sort();
  assert.deepEqual(executes("aaliyah_memory_alias_effect_present(text,text,text,text,text,text)"), ["aaliyah_memory_reconciler"]);
  assert.deepEqual(executes("aaliyah_memory_unerased_merged_records(text,text,text)"), ["aaliyah_memory_mutator"]);
  assert.deepEqual(executes("aaliyah_memory_merge_chain_hops(text,text,text,text)"), ["aaliyah_memory_mutator"]);
});

test("POSITIVE CONTROL: a widened grant IS reported as a difference, then removed", async () => {
  await pool.query(`GRANT SELECT ON memory_alias_bindings TO aaliyah_memory_reconciler`);
  try {
    const actual = await memoryPrivilegeMap(pool);
    assert.ok(actual.tables!.includes("aaliyah_memory_reconciler memory_alias_bindings SELECT"));
    assert.ok(!EXPECTED.tables!.includes("aaliyah_memory_reconciler memory_alias_bindings SELECT"));
  } finally {
    await pool.query(`REVOKE SELECT ON memory_alias_bindings FROM aaliyah_memory_reconciler`);
  }
  assert.ok(!(await memoryPrivilegeMap(pool)).tables!.includes("aaliyah_memory_reconciler memory_alias_bindings SELECT"));
});
