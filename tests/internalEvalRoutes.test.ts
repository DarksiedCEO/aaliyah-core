import assert from "node:assert/strict";
import http from "node:http";
import test, { afterEach, mock } from "node:test";

import { createCoreApp } from "../src/http/createCoreApp";
import { internalEvalRouteInternals } from "../src/http/internalEvalRoutes";

let server: http.Server | undefined;

async function startServer(): Promise<string> {
  const app = createCoreApp();

  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });

  const activeServer = server;

  if (!activeServer) {
    throw new Error("Test server failed to start");
  }

  const address = activeServer.address();

  if (!address || typeof address === "string") {
    throw new Error("Unable to determine test server address");
  }

  return `http://127.0.0.1:${address.port}`;
}

afterEach(async () => {
  mock.restoreAll();

  delete process.env.AALIYAH_ENABLE_INTERNAL_EVAL;
  delete process.env.AALIYAH_EVAL_SECRET;

  if (server) {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }

  server = undefined;
});

test("internal eval route returns 404 when disabled", async () => {
  process.env.AALIYAH_ENABLE_INTERNAL_EVAL = "false";

  const baseUrl = await startServer();
  const response = await fetch(`${baseUrl}/internal/evals/run-task`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-eval-secret": "secret",
    },
    body: JSON.stringify({}),
  });

  assert.equal(response.status, 404);
});

test("internal eval route returns 403 with wrong secret", async () => {
  process.env.AALIYAH_ENABLE_INTERNAL_EVAL = "true";
  process.env.AALIYAH_EVAL_SECRET = "secret";

  const baseUrl = await startServer();
  const response = await fetch(`${baseUrl}/internal/evals/run-task`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-eval-secret": "wrong",
    },
    body: JSON.stringify({}),
  });

  assert.equal(response.status, 403);
});

test("internal eval route returns 200 with correct secret", async () => {
  process.env.AALIYAH_ENABLE_INTERNAL_EVAL = "true";
  process.env.AALIYAH_EVAL_SECRET = "secret";

  mock.method(internalEvalRouteInternals, "runTask", async () => ({
    success: true,
    message: "ok",
    plannerTelemetry: {
      plannerMode: "deterministic_fallback",
      plannerProvider: "openai",
    },
  }) as never);

  const baseUrl = await startServer();
  const response = await fetch(`${baseUrl}/internal/evals/run-task`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-eval-secret": "secret",
    },
    body: JSON.stringify({ taskId: "1" }),
  });

  assert.equal(response.status, 200);
});

test("core app refuses to start with eval enabled and no secret", () => {
  process.env.AALIYAH_ENABLE_INTERNAL_EVAL = "true";
  delete process.env.AALIYAH_EVAL_SECRET;

  assert.throws(
    () => createCoreApp(),
    /AALIYAH_EVAL_SECRET is required when internal eval routes are enabled/,
  );
});
