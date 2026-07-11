import { localMasterKms, type KmsKeyWrapper } from "../../crypto/envelopeEncryption";
import { gcpKmsFromEnv } from "../../crypto/gcpKms";
import type { MailStateBackend } from "../mailState";
import { createGoogleOAuthHttp } from "./googleOAuthHttp";
import type { GoogleConnectDeps } from "./googleConnect";

export type GoogleCapability =
  | { provider: "google"; available: true }
  | { provider: "google"; available: false; reasonCode: "provider_not_configured" };

const GOOGLE_REQUIRED = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
] as const;

const LOCAL_KMS_REQUIRED = ["MAIL_CREDENTIAL_ENCRYPTION_KEY", "MAIL_CREDENTIAL_KEY_VERSION"] as const;
const GCP_KMS_REQUIRED = [
  "GCP_KMS_PROJECT_ID",
  "GCP_KMS_LOCATION",
  "GCP_KMS_KEY_RING",
  "GCP_KMS_CRYPTO_KEY",
] as const;

/** AALIYAH_KMS_PROVIDER selects the envelope-encryption KMS backend. Defaults
 * to "local" — production must opt into "gcp" explicitly; an unrecognized
 * value fails closed rather than silently falling back to local. */
function kmsProvider(env: NodeJS.ProcessEnv): "local" | "gcp" | "unknown" {
  const raw = env.AALIYAH_KMS_PROVIDER;
  if (!raw || raw === "local") return "local";
  if (raw === "gcp") return "gcp";
  return "unknown";
}

function missing(env: NodeJS.ProcessEnv): string[] {
  const provider = kmsProvider(env);
  const kmsRequired =
    provider === "gcp" ? GCP_KMS_REQUIRED : provider === "local" ? LOCAL_KMS_REQUIRED : [];
  const gaps = [...GOOGLE_REQUIRED, ...kmsRequired].filter((k) => !env[k]);
  return provider === "unknown" ? [...gaps, "AALIYAH_KMS_PROVIDER (unknown value)"] : gaps;
}

/**
 * Internal capability state. The "Connect Google" button must not appear
 * functional when the backend is unconfigured — the client shows a plain
 * "temporarily unavailable" message from this reasonCode.
 */
export function googleCapability(env: NodeJS.ProcessEnv = process.env): GoogleCapability {
  return missing(env).length === 0
    ? { provider: "google", available: true }
    : { provider: "google", available: false, reasonCode: "provider_not_configured" };
}

export type GoogleRuntimeConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  kms: KmsKeyWrapper;
};

/**
 * Load validated runtime config. Throws (fail startup / disable cleanly) when
 * anything required is absent — never runs half-configured. AALIYAH_KMS_PROVIDER
 * selects local master key (dev/small-scale) or real GCP Cloud KMS
 * (production) — the wrapper changes, the stored envelope shape does not.
 */
export function loadGoogleConfig(env: NodeJS.ProcessEnv = process.env): GoogleRuntimeConfig {
  const gaps = missing(env);
  if (gaps.length > 0) {
    const provider = kmsProvider(env);
    const reason =
      provider === "unknown"
        ? `unknown AALIYAH_KMS_PROVIDER value "${env.AALIYAH_KMS_PROVIDER}"; missing: ${gaps.join(", ")}`
        : `missing: ${gaps.join(", ")}`;
    throw new Error(`Google mail is not configured; ${reason}`);
  }
  const kms: KmsKeyWrapper =
    kmsProvider(env) === "gcp"
      ? gcpKmsFromEnv(env)
      : localMasterKms({
          keyId: env.MAIL_CREDENTIAL_KEY_VERSION!,
          masterKey: Buffer.from(env.MAIL_CREDENTIAL_ENCRYPTION_KEY!, "base64"),
        });
  return {
    clientId: env.GOOGLE_CLIENT_ID!,
    clientSecret: env.GOOGLE_CLIENT_SECRET!,
    redirectUri: env.GOOGLE_OAUTH_REDIRECT_URI!,
    kms,
  };
}

/** Build fully-wired GoogleConnectDeps from config (real HTTP transport). */
export function buildGoogleConnectDeps(
  config: GoogleRuntimeConfig,
  state: MailStateBackend,
  extra?: Partial<GoogleConnectDeps>,
): GoogleConnectDeps {
  return {
    http: createGoogleOAuthHttp({ clientId: config.clientId, clientSecret: config.clientSecret }),
    kms: config.kms,
    state,
    clientId: config.clientId,
    ...extra,
  };
}
