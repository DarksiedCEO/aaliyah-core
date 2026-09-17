import type { MemoryMutationReceipt } from "@aaliyah/contracts/v1";
import type { Pool } from "pg";

/**
 * AN ATTEMPT THAT MUTATED NOTHING IS WRITTEN HERE, NOT AS A MUTATION RECEIPT.
 *
 * Red team BREAK 1 against b3efc82: aborted and unresolved attempts were filed
 * as TERMINAL rows in `memory_mutation_receipts` under the caller's
 * `mutationReceiptId`, a namespace that table makes unique per phase. A later
 * real mutation reusing that id — the ordinary retry after a stale head, or an
 * id another principal squatted first — committed, read back, agreed, then
 * collided with the ABORTED row and was reported UNKNOWN; and the reconciler
 * skipped it forever, because the ABORTED row was a terminal sibling. The only
 * durable evidence said the mutation never happened.
 *
 * `memory_mutation_attempts` (migration 045) is append-only and deliberately
 * NOT unique on the receipt id: two failed attempts are two facts. Migration
 * 045 also refuses ABORTED_NO_MUTATION in `memory_mutation_receipts`, so no
 * writer can bring the collision back.
 *
 * Best effort by design, exactly as the terminal append it replaces was: an
 * attempt that could not be recorded loses audit detail, and the caller's
 * answer (a refusal) does not depend on it.
 */
export async function appendMutationAttempt(input: {
  pool: Pool;
  role: string | null;
  receipt: MemoryMutationReceipt;
  rejection: string;
}): Promise<void> {
  const { receipt } = input;
  if (receipt.outcome.status !== "ABORTED_NO_MUTATION") {
    throw new Error("memory attempts: only an aborted outcome is an attempt");
  }
  const client = await input.pool.connect();
  try {
    await client.query("BEGIN");
    if (input.role !== null) {
      if (!/^[a-z][a-z0-9_]{0,62}$/u.test(input.role)) {
        throw new Error("memory attempts: role is not a valid identifier");
      }
      await client.query(`SET LOCAL ROLE "${input.role}"`);
    }
    await client.query(
      `INSERT INTO memory_mutation_attempts
         (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
          authorization_id, action, target_record_id, rejection, abort_reason,
          attempted_at, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        receipt.scope.tenantId,
        receipt.scope.workspaceId,
        receipt.scope.principalId,
        receipt.scope.userId,
        receipt.mutationReceiptId,
        receipt.authorizationId,
        receipt.action,
        receipt.targetRecordId,
        input.rejection,
        receipt.outcome.abortReason,
        receipt.outcome.abortedAt,
        JSON.stringify(receipt),
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
