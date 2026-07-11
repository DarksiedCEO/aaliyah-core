/**
 * Up-front production configuration validation. In production the process must
 * refuse to boot half-configured rather than fail lazily on the first request —
 * so this aggregates every missing requirement into one clear error.
 *
 * Only durable-state + envelope-KMS config is boot-required here: those are the
 * surfaces that must never silently fall back (Postgres is the sole state store;
 * the local master key is dev-only). Google OAuth is feature-gated elsewhere
 * (googleCapability) and its absence degrades the mail connect flow to a clean
 * "not configured" rather than blocking boot, so it is reported as a warning.
 */

const GCP_KMS_REQUIRED = [
  "GCP_KMS_PROJECT_ID",
  "GCP_KMS_LOCATION",
  "GCP_KMS_KEY_RING",
  "GCP_KMS_CRYPTO_KEY",
] as const;

const GOOGLE_OAUTH_VARS = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
] as const;

export type ProductionConfigReport = {
  isProduction: boolean;
  errors: string[];
  warnings: string[];
};

function isProductionEnv(env: NodeJS.ProcessEnv): boolean {
  return env.NODE_ENV === "production" || env.AALIYAH_ENV === "production";
}

export function inspectProductionConfig(
  env: NodeJS.ProcessEnv = process.env,
): ProductionConfigReport {
  const isProduction = isProductionEnv(env);
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!isProduction) return { isProduction, errors, warnings };

  if (!env.AALIYAH_DATABASE_URL) {
    errors.push("AALIYAH_DATABASE_URL is required — Postgres is the sole durable state store");
  }

  const kms = env.AALIYAH_KMS_PROVIDER;
  if (kms !== "gcp") {
    errors.push(
      `AALIYAH_KMS_PROVIDER must be 'gcp' in production (got '${kms ?? "unset"}'; the local master key is dev-only)`,
    );
  } else {
    for (const key of GCP_KMS_REQUIRED) {
      if (!env[key]) errors.push(`${key} is required for the gcp KMS provider`);
    }
  }

  const missingGoogle = GOOGLE_OAUTH_VARS.filter((k) => !env[k]);
  if (missingGoogle.length > 0) {
    warnings.push(
      `Gmail connect is unconfigured (missing ${missingGoogle.join(", ")}) — connect routes will report provider_not_configured`,
    );
  }

  return { isProduction, errors, warnings };
}

/** Throw with the aggregated list if production config is invalid. No-op outside production. */
export function assertProductionConfig(env: NodeJS.ProcessEnv = process.env): ProductionConfigReport {
  const report = inspectProductionConfig(env);
  if (report.errors.length > 0) {
    throw new Error(
      `production configuration invalid — refusing to boot:\n - ${report.errors.join("\n - ")}`,
    );
  }
  return report;
}
