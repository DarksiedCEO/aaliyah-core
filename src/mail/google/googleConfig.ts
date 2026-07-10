import { envKeyProvider, type KeyProvider } from "../../crypto/authenticatedEncryption";
import { createGoogleOAuthHttp } from "./googleOAuthHttp";
import type { GoogleConnectDeps } from "./googleConnect";

export type GoogleCapability =
  | { provider: "google"; available: true }
  | { provider: "google"; available: false; reasonCode: "provider_not_configured" };

const REQUIRED = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
  "MAIL_CREDENTIAL_ENCRYPTION_KEY",
  "MAIL_CREDENTIAL_KEY_VERSION",
] as const;

function missing(env: NodeJS.ProcessEnv): string[] {
  return REQUIRED.filter((k) => !env[k]);
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
  keyProvider: KeyProvider;
};

/**
 * Load validated runtime config. Throws (fail startup / disable cleanly) when
 * anything required is absent — never runs half-configured. The encryption key
 * is bridged into the versioned key provider used by the vault.
 */
export function loadGoogleConfig(env: NodeJS.ProcessEnv = process.env): GoogleRuntimeConfig {
  const gaps = missing(env);
  if (gaps.length > 0) {
    throw new Error(`Google mail is not configured; missing: ${gaps.join(", ")}`);
  }
  // Bridge MAIL_CREDENTIAL_* into the key-provider env contract.
  process.env.AALIYAH_MAIL_ENC_KEY_VERSION = env.MAIL_CREDENTIAL_KEY_VERSION;
  process.env[`AALIYAH_MAIL_ENC_KEY_${env.MAIL_CREDENTIAL_KEY_VERSION}`] =
    env.MAIL_CREDENTIAL_ENCRYPTION_KEY;
  return {
    clientId: env.GOOGLE_CLIENT_ID!,
    clientSecret: env.GOOGLE_CLIENT_SECRET!,
    redirectUri: env.GOOGLE_OAUTH_REDIRECT_URI!,
    keyProvider: envKeyProvider(),
  };
}

/** Build fully-wired GoogleConnectDeps from config (real HTTP transport). */
export function buildGoogleConnectDeps(
  config: GoogleRuntimeConfig,
  extra?: Partial<GoogleConnectDeps>,
): GoogleConnectDeps {
  return {
    http: createGoogleOAuthHttp({ clientId: config.clientId, clientSecret: config.clientSecret }),
    keyProvider: config.keyProvider,
    clientId: config.clientId,
    ...extra,
  };
}
