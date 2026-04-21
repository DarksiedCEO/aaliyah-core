import { logger } from "./logger";

export function emitMetric(
  name: string,
  value: number,
  tags: Record<string, string>,
): void {
  logger.info({ metric: { name, value, tags } }, "aaliyah.metric");
}
