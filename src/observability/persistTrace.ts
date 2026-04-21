import { logger } from "./logger";

export async function persistTrace(trace: Record<string, unknown>): Promise<void> {
  const enriched = {
    timestamp: new Date().toISOString(),
    auditVersion: "v2",
    ...trace,
  };

  logger.info(enriched, "aaliyah.trace");

  // TODO: persist to DB (Postgres / Clickhouse / S3)
}
