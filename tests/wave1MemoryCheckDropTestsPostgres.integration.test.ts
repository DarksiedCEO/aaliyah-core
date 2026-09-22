import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import type { PoolClient } from "pg";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { lockSharedMemoryTables, type SharedTableLock } from "./support/sharedMemoryTables";

/**
 * R3.3 — THE 17 CHECK CONSTRAINTS NO TEST DETECTED (candidate-4 gate 7, D-09).
 *
 * Gate 7 dropped every CHECK constraint on `memory_%` one at a time against
 * the suite, then the 115 survivors against the whole suite, then all 17 that
 * still survived at once: 1088 of 1088 passed with all 17 absent. They fall in
 * two families that are NOT the same finding, and are closed differently:
 *
 *   B — 8 domain/shape constraints on the key-destruction ledger, each the
 *       SOLE enforcement of its invariant. Closed by a DROP-TEST each: a row
 *       violating that constraint and nothing else is refused, by name.
 *   A — 9 `jsonb_typeof(payload) = 'object'` type guards, MASKED: a
 *       non-object payload always fails a payload-BINDING check first, so no
 *       insert can reach them. Closed by an EXECUTED redundancy proof below,
 *       which is itself a detector for the masking: if a binding check is ever
 *       weakened so that a guard becomes the only refusal, the proof fails.
 *
 * Run against the SUITE'S database, inside transactions that are rolled back,
 * under the shared memory-table lock — because that is where gate 7 dropped
 * them. A test on a private database would not see a constraint dropped from
 * the shared one. User triggers are disabled inside each transaction so the
 * constraint is what refuses, not a trigger that runs first.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

let adminPool: Pool;
let sharedTableLock: SharedTableLock;

before(async () => {
  adminPool = new Pool({ connectionString: DB_URL, max: 2 });
  adminPool.on("error", () => undefined);
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
});

after(async () => {
  await sharedTableLock.release();
  await adminPool.end();
});

type Violation = { constraint: string; values: Record<string, unknown> };

/**
 * Insert `base` (the positive control: it must SUCCEED), then each violation
 * — `base` with some columns replaced — and require 23514 naming exactly that
 * constraint. One transaction, rolled back; savepoints between rows.
 */
async function dropTest(table: string, base: Record<string, unknown>, violations: Violation[]): Promise<void> {
  const client: PoolClient = await adminPool.connect();
  const insert = async (row: Record<string, unknown>) => {
    const columns = Object.keys(row);
    await client.query(
      `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${columns.map((_, i) => `$${i + 1}`).join(", ")})`,
      Object.values(row),
    );
  };
  try {
    await client.query("BEGIN");
    await client.query(`ALTER TABLE ${table} DISABLE TRIGGER USER`);
    await client.query("SAVEPOINT control");
    await insert(base); // POSITIVE CONTROL: the base row is valid, so each refusal below is its violation's.
    await client.query("ROLLBACK TO SAVEPOINT control");
    for (const violation of violations) {
      await client.query("SAVEPOINT violation");
      await assert.rejects(
        () => insert({ ...base, ...violation.values }),
        (error: { code?: string; constraint?: string }) => {
          assert.equal(error.code, "23514", `${violation.constraint}: not a CHECK violation: ${String(error)}`);
          assert.equal(error.constraint, violation.constraint, `the row was refused by the wrong constraint`);
          return true;
        },
        `${table}: a row violating ${violation.constraint} was ACCEPTED — the constraint is absent`,
      );
      await client.query("ROLLBACK TO SAVEPOINT violation");
    }
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

test("R3.3 family B: key-destruction OBLIGATIONS — state, reason and resolution are each refused by their own constraint", async () => {
  await dropTest(
    "memory_key_destruction_obligations",
    {
      tenant_id: "tenant-droptest",
      workspace_id: "workspace-droptest",
      subject_record_id: "record-droptest",
      alias_id: "alias-droptest",
      key_ref: "key-droptest",
      provider_id: "provider-droptest",
      binding_mutation_receipt_id: "mutation-droptest",
      erasure_tombstone_id: "tombstone-droptest",
      state: "KEY_DESTRUCTION_NOT_PROVEN",
      not_proven_reason: "PROVIDER_TIMEOUT",
      resolved_by: null,
      settled_by: null,
    },
    [
      // A resolved state no reader has a branch for, resolution otherwise well-formed.
      { constraint: "memory_key_destruction_obligations_state_domain", values: { state: "DESTROYED_PROBABLY", resolved_by: "PROVIDER" } },
      { constraint: "memory_key_destruction_obligations_reason_domain", values: { not_proven_reason: "BECAUSE" } },
      // Resolved without being resolved: the register credits this one's sibling with falsifying its own proof.
      { constraint: "memory_key_destruction_obligations_resolution_named", values: { resolved_by: "PROVIDER" } },
    ],
  );
});

test("R3.3 family B: key-destruction SETTLEMENTS — decision, states, digest and policy are each refused by their own constraint", async () => {
  await dropTest(
    "memory_key_destruction_settlements",
    {
      settlement_receipt_id: "settlement-droptest",
      tenant_id: "tenant-droptest",
      workspace_id: "workspace-droptest",
      subject_record_id: "record-droptest",
      alias_id: "alias-droptest",
      key_ref: "key-droptest",
      key_version: 1,
      provider_id: "provider-droptest",
      binding_mutation_receipt_id: "mutation-droptest",
      erasure_authorization_id: "authorization-droptest",
      erasure_tombstone_id: "tombstone-droptest",
      destruction_attempt_id: "attempt-droptest",
      evidence: JSON.stringify({
        kind: "provider_decommission_certificate",
        reference: "vault://decommission/2026-09-21/partition-1",
        referenceDigest: `sha256:${"b".repeat(64)}`,
        witnessedAt: "2026-09-21T00:00:00.000Z",
      }),
      evidence_digest: `sha256:${"0".repeat(64)}`,
      settlement_authority_id: "principal-authority",
      verifier_principal_id: "principal-verifier",
      decision: "PROVEN_DESTROYED",
      policy_version: "aaliyah.key-destruction-settlement/v1",
      nonce: "nonce-droptest",
      predecessor_state: "ERASURE_PENDING_SETTLEMENT",
      successor_state: "PROVEN_DESTROYED",
      decided_at: new Date(Date.now() - 60_000),
    },
    [
      { constraint: "memory_key_destruction_settlements_decision_domain", values: { decision: "PROBABLY_DESTROYED" } },
      { constraint: "memory_key_destruction_settlements_states_known", values: { predecessor_state: "SOMEWHERE" } },
      { constraint: "memory_key_destruction_settlements_states_known", values: { successor_state: "SOMEWHERE" } },
      // Free text where a digest belongs is a place for a subject's address to survive.
      { constraint: "memory_key_destruction_settlements_digest_shape", values: { evidence_digest: "alice@example.com" } },
      { constraint: "memory_key_destruction_settlements_policy_known", values: { policy_version: "aaliyah.key-destruction-settlement/v0" } },
    ],
  );
});

test("R3.3 family B: PII key AUDITS — an audited state outside the vocabulary is refused by its own constraint", async () => {
  await dropTest(
    "memory_pii_key_audits",
    { tenant_id: "tenant-droptest", workspace_id: "workspace-droptest", key_ref: "key-droptest", last_state: "destroyed" },
    [{ constraint: "memory_pii_key_audits_state_domain", values: { last_state: "probably-destroyed" } }],
  );
});

/**
 * FAMILY A — EXECUTED REDUNDANCY PROOF, NOT AN ARGUMENT.
 *
 * Gate 7 showed by execution that a non-object payload fails a BINDING check
 * before the type guard. That was one input on one table. This proves it for
 * every guard, every non-object JSON type, from the live catalog: for each
 * table, the payload column is set to a non-object value and every OTHER
 * CHECK on the table is evaluated against that row — and at least one must
 * evaluate to FALSE. Not NULL: a CHECK passes on NULL, so NULL would be a hole.
 * Every other column is NULL, which is the adversary's best case (a binding
 * check can only become NULL, never TRUE, with them NULL).
 */
const FAMILY_A: ReadonlyArray<[string, string, string]> = [
  ["memory_alias_bindings", "payload", "memory_alias_bindings_payload_object"],
  ["memory_authorization_receipts", "payload", "memory_authorization_receipts_payload_object"],
  ["memory_identity_edges", "payload", "memory_identity_edges_payload_object"],
  ["memory_legal_holds", "payload", "memory_legal_holds_payload_object"],
  ["memory_mutation_attempts", "payload", "memory_mutation_attempts_payload_object"],
  ["memory_mutation_receipts", "payload", "memory_mutation_receipts_payload_object"],
  ["memory_record_versions", "payload", "memory_record_versions_payload_object"],
  ["memory_tombstones", "payload", "memory_tombstones_payload_object"],
  ["memory_reconciliations", "evidence", "memory_reconciliations_evidence_object"],
];
const NON_OBJECTS = ['["not","an","object"]', '"a string"', "42", "true", "null"];

test("R3.3 family A: every payload type guard is MASKED — for every non-object JSON value another CHECK is FALSE (executed redundancy proof)", async () => {
  const unmasked: string[] = [];
  for (const [table, column, guard] of FAMILY_A) {
    const guardPresent = await adminPool.query(
      `SELECT count(*)::int AS n FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2`,
      [table, guard],
    );
    assert.equal(guardPresent.rows[0].n, 1, `fixture precondition: ${guard} exists on ${table}`);
    const others = (
      await adminPool.query(
        `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
          WHERE conrelid = $1::regclass AND contype = 'c' AND conname <> $2 ORDER BY conname`,
        [table, guard],
      )
    ).rows as Array<{ conname: string; def: string }>;
    for (const value of NON_OBJECTS) {
      let refusedBy: string | null = null;
      for (const { conname, def } of others) {
        const expression = def.replace(/^CHECK \(/, "(").replace(/\)( NOT VALID)?$/, ")");
        const verdict = await adminPool.query(
          `SELECT (${expression}) AS ok
             FROM (SELECT (jsonb_populate_record(NULL::${table}, jsonb_build_object($1::text, $2::jsonb))).*) AS candidate`,
          [column, value],
        );
        if (verdict.rows[0].ok === false) {
          refusedBy = conname;
          break;
        }
      }
      if (refusedBy === null) unmasked.push(`${table}.${column} = ${value}`);
    }
  }
  assert.deepEqual(
    unmasked,
    [],
    `a non-object value that NO other CHECK refuses — the type guard is the SOLE enforcement there and needs a drop-test of its own:\n${unmasked.join("\n")}`,
  );
});
