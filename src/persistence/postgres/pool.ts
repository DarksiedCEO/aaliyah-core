import { Pool } from "pg";

/**
 * Durable mail-state pool. Fails closed: without an explicit database URL
 * there is no silent fallback to anything in-memory — callers must decide,
 * visibly, which backend they run.
 */
export function createMailDbPool(env: NodeJS.ProcessEnv = process.env): Pool {
  const url = env.AALIYAH_DATABASE_URL;
  if (!url) {
    throw new Error("durable mail state not configured: AALIYAH_DATABASE_URL is required");
  }
  return new Pool({ connectionString: url, max: 10 });
}
