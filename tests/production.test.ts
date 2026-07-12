import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";

import {
  inspectProductionConfig,
  assertProductionConfig,
} from "../src/config/productionConfig";
import { createReadinessProbe } from "../src/http/readiness";
import { createCoreApp } from "../src/http/createCoreApp";

// ---- Production config validation ----

const GCP_OK = {
  NODE_ENV: "production",
  AALIYAH_DATABASE_URL: "postgres://x",
  AALIYAH_KMS_PROVIDER: "gcp",
  GCP_KMS_PROJECT_ID: "p",
  GCP_KMS_LOCATION: "l",
  GCP_KMS_KEY_RING: "r",
  GCP_KMS_CRYPTO_KEY: "k",
  GOOGLE_CLIENT_ID: "id",
  GOOGLE_CLIENT_SECRET: "secret",
  GOOGLE_OAUTH_REDIRECT_URI: "https://app/cb",
} as unknown as NodeJS.ProcessEnv;

test("production config: non-production never blocks boot", () => {
  const r = inspectProductionConfig({ NODE_ENV: "test" } as NodeJS.ProcessEnv);
  assert.equal(r.isProduction, false);
  assert.equal(r.errors.length, 0);
});

test("production config: missing durable state + local KMS fail closed", () => {
  const r = inspectProductionConfig({
    NODE_ENV: "production",
    AALIYAH_KMS_PROVIDER: "local",
  } as unknown as NodeJS.ProcessEnv);
  assert.ok(r.errors.some((e) => e.includes("AALIYAH_DATABASE_URL")));
  assert.ok(r.errors.some((e) => e.includes("AALIYAH_KMS_PROVIDER must be 'gcp'")));
  assert.throws(
    () => assertProductionConfig({ NODE_ENV: "production" } as NodeJS.ProcessEnv),
    /refusing to boot/,
  );
});

test("production config: gcp provider missing a key var is reported", () => {
  const env = { ...GCP_OK } as Record<string, string>;
  delete env.GCP_KMS_KEY_RING;
  const r = inspectProductionConfig(env as unknown as NodeJS.ProcessEnv);
  assert.ok(r.errors.some((e) => e.includes("GCP_KMS_KEY_RING")));
});

test("production config: fully configured passes with no errors", () => {
  const r = assertProductionConfig(GCP_OK);
  assert.equal(r.errors.length, 0);
  assert.equal(r.warnings.length, 0);
});

test("production config: missing Google OAuth is a warning, not a boot error", () => {
  const env = { ...GCP_OK } as Record<string, string>;
  delete env.GOOGLE_CLIENT_ID;
  const r = assertProductionConfig(env as unknown as NodeJS.ProcessEnv);
  assert.equal(r.errors.length, 0);
  assert.ok(r.warnings.some((w) => w.includes("Gmail connect is unconfigured")));
});

// ---- Readiness probe ----

test("readiness: trivially ready when no database is configured", async () => {
  const probe = createReadinessProbe({ databaseConfigured: false });
  assert.deepEqual(await probe(), { ready: true, checks: {} });
});

test("readiness: database ping ok -> ready", async () => {
  const pool = { query: async () => ({ rows: [{ "?column?": 1 }] }) } as never;
  const probe = createReadinessProbe({ databaseConfigured: true, pool });
  assert.deepEqual(await probe(), { ready: true, checks: { database: "ok" } });
});

test("readiness: database ping failure -> not ready", async () => {
  const pool = { query: async () => { throw new Error("ECONNREFUSED"); } } as never;
  const probe = createReadinessProbe({ databaseConfigured: true, pool });
  assert.deepEqual(await probe(), { ready: false, checks: { database: "unavailable" } });
});

// ---- Live /health + /ready wiring ----

async function withServer(
  ready: boolean,
  fn: (base: string) => Promise<void>,
): Promise<void> {
  const app = createCoreApp({
    readinessProbe: async () => ({ ready, checks: { database: ready ? "ok" : "unavailable" } }),
  });
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test("/health is 200 liveness regardless of dependencies", async () => {
  await withServer(false, async (base) => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  });
});

test("/ready is 200 when ready and 503 when a dependency is down", async () => {
  await withServer(true, async (base) => {
    const res = await fetch(`${base}/ready`);
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { status: string }).status, "ready");
  });
  await withServer(false, async (base) => {
    const res = await fetch(`${base}/ready`);
    assert.equal(res.status, 503);
    assert.equal(((await res.json()) as { status: string }).status, "not_ready");
  });
});
