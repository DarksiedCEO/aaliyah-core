import assert from "node:assert/strict";
import test, { afterEach } from "node:test";

import {
  ensureIdempotentExecution,
  idempotencyStoreInternals,
  recordIdempotentFailure,
  recordIdempotentResult,
} from "../src/persistence/idempotencyStore";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

afterEach(() => {
  idempotencyStoreInternals.resetInMemory();
});

test("idempotency v2 replays stored result for the same request", async () => {
  const first = await ensureIdempotentExecution<{ success: boolean }>(
    "idem-1",
    { action: "send" },
    "write",
  );

  assert.equal(first.replay, false);

  await recordIdempotentResult("idem-1", { success: true });

  const replay = await ensureIdempotentExecution<{ success: boolean }>(
    "idem-1",
    { action: "send" },
    "write",
  );

  assert.equal(replay.replay, true);
  assert.deepEqual(replay.result, { success: true });
});

test("idempotency v2 rejects reused keys with different payloads", async () => {
  await ensureIdempotentExecution("idem-2", { action: "send" }, "write");

  await assert.rejects(
    () => ensureIdempotentExecution("idem-2", { action: "delete" }, "write"),
    /Idempotency key reuse with different payload/,
  );
});

test("idempotency v3 allows retry after recorded failure", async () => {
  await ensureIdempotentExecution("idem-3", { action: "send" }, "write");
  await recordIdempotentFailure("idem-3", "connector timeout");

  const retry = await ensureIdempotentExecution("idem-3", { action: "send" }, "write");

  assert.equal(retry.replay, false);
});
