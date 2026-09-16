import type { Server } from "node:http";

import { createCoreApp, mailStateFromEnv } from "./http/createCoreApp";
import { createReadinessProbe } from "./http/readiness";
import { assertProductionConfig } from "./config/productionConfig";
import { createMailDbPool } from "./persistence/postgres/pool";
import { runMailMigrations } from "./persistence/postgres/migrations";
import { createPostgresWave1MemoryService } from "./persistence/postgres/wave1IdentityGraphStore";

const port = Number(process.env.PORT ?? 3000);
const SHUTDOWN_GRACE_MS = Number(process.env.AALIYAH_SHUTDOWN_GRACE_MS ?? 10_000);

async function main(): Promise<void> {
  // Fail closed BEFORE opening a socket: in production, refuse to boot without
  // durable state + a real KMS provider (aggregated, up-front error).
  const config = assertProductionConfig();
  for (const warning of config.warnings) {
    process.stdout.write(`config warning: ${warning}\n`);
  }

  const databaseConfigured = Boolean(process.env.AALIYAH_DATABASE_URL);
  // A long-lived pool dedicated to readiness + migrations. Kept open for the
  // process lifetime so /ready can ping it; closed on shutdown.
  const pool = databaseConfigured ? createMailDbPool() : undefined;
  // A SECOND pool, and not a luxury: the trusted-memory store's post-commit
  // read-back has to run on a connection that is not the mutating one, and the
  // alias registry refuses to be constructed with a single pool for that exact
  // reason. Closed on shutdown alongside the first.
  const readPool = databaseConfigured ? createMailDbPool() : undefined;

  if (pool && readPool) {
    await runMailMigrations(pool);
    process.stdout.write("mail state: postgres (migrations applied)\n");

    // ---- TRUSTED MEMORY, REACHED AT BOOT ---------------------------------
    // Reconciliation is the one memory operation that belongs to the PROCESS
    // rather than to a request: an outcome left UNKNOWN by a crash has no
    // caller waiting on it, so nothing would ever resolve it if resolution
    // only happened inside a request. Running it here means a restart is what
    // settles what the crash left open.
    //
    // Fail-open DELIBERATELY, and only here: refusing to boot because an old
    // ambiguous outcome could not be settled would turn a historical unknown
    // into a total outage. The unknown stays durable and stays unknown, which
    // is exactly what it did before this ran.
    const memory = createPostgresWave1MemoryService(pool, readPool);
    try {
      const settled = await memory.reconcilePending();
      process.stdout.write(
        settled === 0
          ? "trusted memory: no unresolved mutations\n"
          : `trusted memory: reconciled ${settled} unresolved mutation(s)\n`,
      );
    } catch (error) {
      process.stderr.write(
        `trusted memory: reconciliation pass failed (${
          error instanceof Error ? error.message : String(error)
        }) — unresolved outcomes remain unresolved\n`,
      );
    }
  } else {
    process.stdout.write(
      "mail state: IN-MEMORY (dev only — set AALIYAH_DATABASE_URL for durable state)\n",
    );
  }

  const app = createCoreApp({
    mailState: mailStateFromEnv(),
    readinessProbe: createReadinessProbe({
      databaseConfigured,
      ...(pool ? { pool } : {}),
    }),
  });

  const server: Server = app.listen(port, () => {
    process.stdout.write(`Aaliyah core running on ${port}\n`);
  });

  // Graceful shutdown: stop accepting connections, drain in-flight requests,
  // then close the pool. Cloud Run sends SIGTERM before reclaiming an instance.
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write(`${signal} received — draining\n`);
    const force = setTimeout(() => {
      process.stderr.write("shutdown grace elapsed — forcing exit\n");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    force.unref();
    server.close(() => {
      void Promise.all([pool?.end(), readPool?.end()])
        .catch(() => {
          // best effort — we are exiting anyway
        })
        .finally(() => {
          clearTimeout(force);
          process.stdout.write("shutdown complete\n");
          process.exit(0);
        });
      if (!pool) {
        clearTimeout(force);
        process.stdout.write("shutdown complete\n");
        process.exit(0);
      }
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((error) => {
  process.stderr.write(
    `startup failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
