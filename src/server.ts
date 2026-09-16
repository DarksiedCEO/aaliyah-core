import type { Server } from "node:http";

import { createCoreApp, mailStateFromEnv } from "./http/createCoreApp";
import { createReadinessProbe } from "./http/readiness";
import { assertProductionConfig } from "./config/productionConfig";
import { createMailDbPool } from "./persistence/postgres/pool";
import { runMailMigrations } from "./persistence/postgres/migrations";
import { createPostgresWave1MemoryService } from "./persistence/postgres/wave1IdentityGraphStore";
import { CeoProfileSchema } from "./application/executive/ceoProfile";
import { AaliyahModelRouter } from "./model-router/AaliyahModelRouter";
import { AnthropicAdapter } from "./model-router/adapters/anthropicAdapter";
import { OpenAIAdapter } from "./model-router/adapters/openaiAdapter";
import type { ProviderAdapter } from "./model-router/types";
import type { ExecutiveRoutesDeps } from "./http/executiveRoutes";
import type { Wave1MemoryService } from "./application/memory/wave1MemoryService";

/**
 * THE EXECUTIVE ROUTE'S DEPENDENCIES, OR A REASON IT IS NOT MOUNTED.
 *
 * Returns null rather than a degraded stand-in. A route mounted without a model
 * provider would answer every message `degraded`, and a route mounted without a
 * CEO profile would draft in nobody's voice — both look like a working endpoint
 * to a caller, which is worse than a 404.
 *
 * NO CREDENTIALS ARE CREATED HERE. Providers are constructed only from keys the
 * deployment already holds; absent them, the route stays unmounted and says so.
 */
function executiveDeps(
  memory: Wave1MemoryService,
): Omit<ExecutiveRoutesDeps, "auth"> | { unmounted: string } {
  const raw = process.env.AALIYAH_CEO_PROFILE;
  if (!raw) return { unmounted: "AALIYAH_CEO_PROFILE is not set" };
  let profile;
  try {
    profile = CeoProfileSchema.parse(JSON.parse(raw));
  } catch (error) {
    return {
      unmounted: `AALIYAH_CEO_PROFILE is not a valid profile (${
        error instanceof Error ? error.message : String(error)
      })`,
    };
  }
  const adapters: ProviderAdapter[] = [];
  if (process.env.ANTHROPIC_API_KEY) adapters.push(new AnthropicAdapter());
  if (process.env.OPENAI_API_KEY) adapters.push(new OpenAIAdapter());
  if (adapters.length === 0) {
    return { unmounted: "no model provider credentials are configured" };
  }
  const router = new AaliyahModelRouter(adapters);
  return { memory, pipeline: { triageRouter: router, draftRouter: router, profile } };
}

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
  // Built below when a pool exists; the executive route needs it at app
  // construction, which happens after.
  let memoryService: Wave1MemoryService | null = null;
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
    memoryService = createPostgresWave1MemoryService(pool, readPool);
    const memory = memoryService;
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

  const executive = memoryService === null ? null : executiveDeps(memoryService);
  if (executive !== null && "unmounted" in executive) {
    process.stdout.write(
      `executive inbound route: NOT mounted — ${executive.unmounted}\n`,
    );
  } else if (executive !== null) {
    process.stdout.write("executive inbound route: mounted\n");
  }

  const app = createCoreApp({
    mailState: mailStateFromEnv(),
    ...(executive !== null && !("unmounted" in executive)
      ? { executive }
      : {}),
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
