import type { Server } from "node:http";

import { createCoreApp, mailStateFromEnv } from "./http/createCoreApp";
import { createReadinessProbe } from "./http/readiness";
import { assertProductionConfig } from "./config/productionConfig";
import { createMailDbPool } from "./persistence/postgres/pool";
import { runMailMigrations } from "./persistence/postgres/migrations";

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

  if (pool) {
    await runMailMigrations(pool);
    process.stdout.write("mail state: postgres (migrations applied)\n");
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
      void pool
        ?.end()
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
