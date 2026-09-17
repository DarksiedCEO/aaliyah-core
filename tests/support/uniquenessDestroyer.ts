import assert from "node:assert/strict";
import type { Pool } from "pg";

/**
 * A UNIQUE INDEX, DESTROYED BY THE ONE ROW IT EXISTS TO REFUSE.
 *
 * Found by the b3efc82 mutation sweep: 14 of the unique constraints on the
 * memory tables — including the (tenant, workspace, record, version) index the
 * whole compare-and-swap rests on — could be DROPPED with the suite still
 * green. The store never produces a duplicate, which is the point of the store,
 * so nothing ever reached the index; and every other layer (the advisory lock,
 * the witness triggers) refused first. A replica, a restored backup or a writer
 * that bypasses the store has none of those layers.
 *
 * Method, per index:
 *
 *   1. Start from a REAL row the workflow under test actually wrote — not a
 *      hand-built one, which would test the fixture rather than the schema.
 *   2. In a transaction that is always rolled back, stand the table's triggers
 *      down. Uniqueness is decided when the index entry is inserted, after
 *      BEFORE triggers and CHECK constraints and before AFTER triggers, so the
 *      triggers can only ever pre-empt it; standing them down is what makes the
 *      index the ONLY thing that can refuse.
 *   3. Re-insert the row with every OTHER unique key freshened (`freshen`), so
 *      exactly one index can collide, and assert the refusal is 23505 NAMING
 *      that index.
 *   4. POSITIVE CONTROL: re-insert again with the target key freshened too
 *      (`positive`), and assert it is ACCEPTED — so the refusal in step 3 was
 *      the index, and not a CHECK the overrides broke.
 *
 * Overrides are column values; `payload` overrides are deep-merged into the
 * row's jsonb payload, because most memory tables bind columns to payload
 * members with CHECK constraints.
 */

type Json = Record<string, unknown>;

export type UniquenessCase = {
  table: string;
  /** The unique index (or constraint) name the collision must report. */
  index: string;
  /** Selects the real source row. */
  where: string;
  params: unknown[];
  /** Overrides that freshen every unique key EXCEPT the target. */
  freshen: (row: Json) => Json;
  /** Overrides that ALSO freshen the target key. */
  positive: (row: Json) => Json;
};

function deepMerge(base: unknown, patch: unknown): unknown {
  if (
    patch === null ||
    typeof patch !== "object" ||
    Array.isArray(patch) ||
    base === null ||
    typeof base !== "object" ||
    Array.isArray(base)
  ) {
    return patch;
  }
  const out: Json = { ...(base as Json) };
  for (const [key, value] of Object.entries(patch as Json)) {
    out[key] = deepMerge((base as Json)[key], value);
  }
  return out;
}

function applyOverrides(row: Json, overrides: Json): Json {
  const out: Json = { ...row };
  for (const [column, value] of Object.entries(overrides)) {
    out[column] = column === "payload" || column === "evidence"
      ? deepMerge(row[column], value)
      : value;
  }
  return out;
}

export async function assertUniqueIndexKills(pool: Pool, spec: UniquenessCase): Promise<void> {
  if (!/^memory_[a-z_]+$/.test(spec.table)) {
    throw new Error(`uniqueness destroyer: unsafe table name ${spec.table}`);
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const source = await client.query(
      `SELECT to_jsonb(t) AS row FROM ${spec.table} AS t WHERE ${spec.where} LIMIT 2`,
      spec.params,
    );
    assert.equal(source.rowCount, 1, `${spec.index}: the source row must exist exactly once`);
    const row = source.rows[0].row as Json;
    delete row.id;

    const columns = (
      await client.query(
        `SELECT column_name FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1 AND column_name <> 'id'
          ORDER BY ordinal_position`,
        [spec.table],
      )
    ).rows.map((r: { column_name: string }) => r.column_name);
    const list = columns.join(", ");
    const insert = `INSERT INTO ${spec.table} (${list})
      SELECT ${list} FROM jsonb_populate_record(NULL::public.${spec.table}, $1::jsonb)`;

    await client.query(`ALTER TABLE ${spec.table} DISABLE TRIGGER USER`);

    await client.query("SAVEPOINT duplicate");
    let refused: { code?: string; constraint?: string } | null = null;
    try {
      await client.query(insert, [JSON.stringify(applyOverrides(row, spec.freshen(row)))]);
    } catch (error) {
      refused = error as { code?: string; constraint?: string };
    }
    await client.query("ROLLBACK TO SAVEPOINT duplicate");
    assert.ok(refused !== null, `${spec.index}: a duplicate on this key was ACCEPTED`);
    assert.equal(refused.code, "23505", `${spec.index}: refused, but not as a unique violation: ${String(refused)}`);
    assert.equal(refused.constraint, spec.index, `${spec.index}: refused by a different index`);

    // Positive control: the same row with the target key fresh as well lands.
    await client.query(insert, [JSON.stringify(applyOverrides(row, spec.positive(row)))]);
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

export type CheckDestroyerCase = {
  /** The CHECK constraint the violating row must be refused by, by name. */
  constraint: string;
  /** Overrides (applied on top of `fresh`) that violate exactly this constraint. */
  violate: (row: Json) => Json;
};

/**
 * EVERY CHECK ON A TABLE, DESTROYED FROM A REAL ROW.
 *
 * The CHECK-destroyer suite built base rows by hand for five tables; the
 * Priority 6 sweep then dropped every other CHECK on the memory tables and
 * many survived, because no test ever wrote a row that could reach them.
 * This does for those tables what `assertUniqueIndexKills` does for unique
 * indexes: start from a row the workflow actually wrote, stand triggers down
 * in a transaction that is always rolled back (CHECKs are evaluated before
 * AFTER triggers and after BEFORE triggers, so triggers can only pre-empt
 * them), and prove —
 *
 *   POSITIVE CONTROL: the row with its unique keys freshened is ACCEPTED;
 *   each case: that row plus one violation is refused with 23514 NAMING the
 *   constraint.
 */
export async function assertCheckConstraintsKill(
  pool: Pool,
  spec: {
    table: string;
    where: string;
    params: unknown[];
    fresh: (row: Json) => Json;
    cases: readonly CheckDestroyerCase[];
    /**
     * A jsonb column whose `_object` CHECK is a MASKED backstop (every binding
     * on it sorts earlier and fails on a non-object first). The constraint
     * cannot be named, so what is proven instead is the property: a
     * non-object value is refused by SOME CHECK of this table.
     */
    nonObjectColumn?: string;
  },
): Promise<void> {
  if (!/^memory_[a-z_]+$/.test(spec.table)) {
    throw new Error(`check destroyer: unsafe table name ${spec.table}`);
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const source = await client.query(
      `SELECT to_jsonb(t) AS row FROM ${spec.table} AS t WHERE ${spec.where} LIMIT 2`,
      spec.params,
    );
    assert.equal(source.rowCount, 1, `${spec.table}: the source row must exist exactly once`);
    const row = source.rows[0].row as Json;
    delete row.id;
    const columns = (
      await client.query(
        `SELECT column_name FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1 AND column_name <> 'id'
          ORDER BY ordinal_position`,
        [spec.table],
      )
    ).rows.map((r: { column_name: string }) => r.column_name);
    const list = columns.join(", ");
    const insert = `INSERT INTO ${spec.table} (${list})
      SELECT ${list} FROM jsonb_populate_record(NULL::public.${spec.table}, $1::jsonb)`;
    await client.query(`ALTER TABLE ${spec.table} DISABLE TRIGGER USER`);

    const freshRow = applyOverrides(row, spec.fresh(row));
    await client.query("SAVEPOINT positive");
    await client.query(insert, [JSON.stringify(freshRow)]);
    await client.query("ROLLBACK TO SAVEPOINT positive");

    for (const testCase of spec.cases) {
      await client.query("SAVEPOINT violation");
      let refused: { code?: string; constraint?: string } | null = null;
      try {
        await client.query(insert, [JSON.stringify(applyOverrides(freshRow, testCase.violate(freshRow)))]);
      } catch (error) {
        refused = error as { code?: string; constraint?: string };
      }
      await client.query("ROLLBACK TO SAVEPOINT violation");
      assert.ok(refused !== null, `${testCase.constraint}: the violating row was ACCEPTED`);
      assert.equal(refused.code, "23514", `${testCase.constraint}: refused, but not by a CHECK: ${String(refused)}`);
      assert.equal(refused.constraint, testCase.constraint, `${testCase.constraint}: refused by a different CHECK`);
    }
    if (spec.nonObjectColumn !== undefined) {
      await client.query("SAVEPOINT non_object");
      let refused: { code?: string; constraint?: string } | null = null;
      try {
        await client.query(insert, [JSON.stringify({ ...freshRow, [spec.nonObjectColumn]: ["not", "an", "object"] })]);
      } catch (error) {
        refused = error as { code?: string; constraint?: string };
      }
      await client.query("ROLLBACK TO SAVEPOINT non_object");
      assert.ok(refused !== null, `${spec.table}: a non-object ${spec.nonObjectColumn} was ACCEPTED`);
      assert.equal(refused.code, "23514", `${spec.table}: non-object refused, but not by a CHECK`);
      assert.ok(String(refused.constraint).startsWith(`${spec.table}_`), `${spec.table}: refused by ${refused.constraint}`);
    }
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}
