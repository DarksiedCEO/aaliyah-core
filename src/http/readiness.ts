import type { Pool } from "pg";

/**
 * Readiness is distinct from liveness. `/health` (liveness) says the process is
 * up; `/ready` says it can actually serve — i.e. its durable dependencies are
 * reachable. Cloud Run routes traffic on readiness, so this must fail (503)
 * when Postgres is unreachable rather than accept requests it cannot serve.
 */
export type ReadinessResult = {
  ready: boolean;
  checks: Record<string, "ok" | "unavailable">;
};

export type ReadinessProbe = () => Promise<ReadinessResult>;

/**
 * Build a readiness probe. When a database is configured the probe pings it
 * (`SELECT 1`); a failed ping yields not-ready. When no database is configured
 * (dev/in-memory) the probe is trivially ready.
 */
export function createReadinessProbe(opts: {
  pool?: Pool;
  databaseConfigured: boolean;
}): ReadinessProbe {
  return async () => {
    const checks: Record<string, "ok" | "unavailable"> = {};
    if (opts.databaseConfigured) {
      try {
        await opts.pool!.query("SELECT 1");
        checks.database = "ok";
      } catch {
        checks.database = "unavailable";
      }
    }
    const ready = Object.values(checks).every((state) => state === "ok");
    return { ready, checks };
  };
}
