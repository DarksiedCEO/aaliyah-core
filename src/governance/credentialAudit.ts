import { logger } from "../observability/logger";

export function auditCredentialUse(
  tenantId: string,
  userId: string,
  provider: string,
): void {
  logger.info(
    { tenantId, userId, provider },
    "credential.used",
  );
}
