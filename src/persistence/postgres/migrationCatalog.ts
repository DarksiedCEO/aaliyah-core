/**
 * THE LEDGER IS READ BACK AGAINST THE SCHEMA, NOT ONLY AGAINST THE SOURCE.
 *
 * Gate 7 of candidate-4 (D-03), executed: every check the migrator made
 * compared the ledger with the SOURCE. A row inserted for a migration that
 * never ran (L4), even carrying the true digest (L4b), made the runner report
 * success over a schema missing that migration's trigger and constraint.
 * Nothing compared the ledger with what the database actually holds.
 *
 * Each migration's catalog EFFECT is recorded in
 * `migrationEvidence.generated.ts`, derived by EXECUTION — every migration's
 * SQL applied in order on an empty database, the catalog snapshotted after
 * each, and the difference kept — never by reading the SQL. A test regenerates
 * it and fails on any drift.
 *
 * WHAT A SNAPSHOT RECORDS, AND WHAT IT DELIBERATELY DOES NOT
 *
 *   rel:<name>           relation kind (table, view, index, sequence)
 *   col:<table>.<col>    the column's type
 *   con:<table>.<name>   the constraint's kind (check, unique, fk, pk, trigger)
 *   trg:<table>.<name>   the trigger exists (non-internal only)
 *   fn:<name>(<args>)    sha256 of the function's source text, verbatim
 *
 * Only schema `public`. Not recorded: whether a trigger is ENABLED, a
 * function's `SET` configuration, ownership or grants. The suite's own tests
 * change those temporarily on a shared database while other files migrate it,
 * and they are held elsewhere (the privilege map, the search-path tests).
 * A disabled trigger is therefore NOT something this read-back refuses.
 * Every recorded field is one PostgreSQL stores as given, so a server upgrade
 * does not change it.
 */
import type { BoundedQuery } from "./pool";

export type CatalogSnapshot = ReadonlyMap<string, string>;

/** What one migration did to the catalog: keys it created or changed, and keys it removed. */
export type MigrationCatalogEvidence = {
  readonly sqlDigest: string;
  readonly set: Readonly<Record<string, string>>;
  readonly drop: ReadonlyArray<string>;
};

export const CATALOG_SNAPSHOT_SQL = `
  WITH rels AS (
    SELECT c.oid, c.relname, c.relkind
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'i', 'S', 'f')
  )
  SELECT key, fp FROM (
    SELECT 'rel:' || relname AS key, relkind::text AS fp FROM rels
    UNION ALL
    SELECT 'col:' || r.relname || '.' || a.attname, format_type(a.atttypid, a.atttypmod)
      FROM pg_attribute a JOIN rels r ON r.oid = a.attrelid
     WHERE r.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'con:' || r.relname || '.' || k.conname, k.contype::text
      FROM pg_constraint k JOIN rels r ON r.oid = k.conrelid
    UNION ALL
    SELECT 'trg:' || r.relname || '.' || t.tgname, 'trigger'
      FROM pg_trigger t JOIN rels r ON r.oid = t.tgrelid
     WHERE NOT t.tgisinternal
    UNION ALL
    SELECT 'fn:' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
           'sha256:' || encode(sha256(convert_to(p.prosrc, 'UTF8')), 'hex')
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
  ) s
  ORDER BY key`;

export async function readCatalog(bounded: BoundedQuery): Promise<CatalogSnapshot> {
  const rows = (await bounded(CATALOG_SNAPSHOT_SQL)).rows as Array<{ key: string; fp: string }>;
  return new Map(rows.map((r) => [r.key, r.fp]));
}

/**
 * What the catalog must hold for a ledger listing `applied`: every applied
 * migration's evidence folded in order, so a later migration's change or drop
 * supersedes an earlier one's. `owner` names the migration a key's expected
 * state came from, for the refusal message.
 */
export function expectedCatalog(
  order: ReadonlyArray<string>,
  applied: ReadonlySet<string>,
  evidence: Readonly<Record<string, MigrationCatalogEvidence>>,
): { expected: Map<string, string | null>; owner: Map<string, string> } {
  const expected = new Map<string, string | null>();
  const owner = new Map<string, string>();
  for (const id of order) {
    if (!applied.has(id)) continue;
    const entry = evidence[id];
    if (entry === undefined) continue;
    for (const [key, fp] of Object.entries(entry.set)) {
      expected.set(key, fp);
      owner.set(key, id);
    }
    for (const key of entry.drop) {
      expected.set(key, null);
      owner.set(key, id);
    }
  }
  return { expected, owner };
}

export type CatalogMismatch = {
  migration: string;
  key: string;
  expected: string | null;
  actual: string | null;
};

export function catalogMismatches(
  expected: ReadonlyMap<string, string | null>,
  owner: ReadonlyMap<string, string>,
  actual: CatalogSnapshot,
): CatalogMismatch[] {
  const out: CatalogMismatch[] = [];
  for (const [key, want] of expected) {
    const have = actual.get(key) ?? null;
    if (have !== want) out.push({ migration: owner.get(key) ?? "?", key, expected: want, actual: have });
  }
  return out;
}

/** A refusal message naming each migration whose recorded effect the schema does not hold. */
export function describeMismatches(mismatches: ReadonlyArray<CatalogMismatch>): string {
  const byMigration = new Map<string, CatalogMismatch[]>();
  for (const m of mismatches) {
    const list = byMigration.get(m.migration) ?? [];
    list.push(m);
    byMigration.set(m.migration, list);
  }
  return [...byMigration]
    .map(([migration, list]) => {
      const shown = list
        .slice(0, 3)
        .map((m) =>
          m.actual === null
            ? `${m.key} absent`
            : m.expected === null
              ? `${m.key} present (dropped by then)`
              : `${m.key} differs`,
        )
        .join(", ");
      return `${migration} [${shown}${list.length > 3 ? `, +${list.length - 3} more` : ""}]`;
    })
    .join("; ");
}
