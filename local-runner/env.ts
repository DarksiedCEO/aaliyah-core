import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

/**
 * Local personal runner configuration.
 *
 * This is the ONLY new "config" surface for running Aaliyah against a single
 * real mailbox on this machine — free, no hosted infra. It reads the operator's
 * secrets from ~/.aaliyah-local (never from the repo, never printed) and shapes
 * them into the exact env the verified core already understands
 * (loadGoogleConfig / createMailDbPool / applicationStoreFromEnv). It does not
 * introduce a new credential path — it feeds the existing one.
 *
 * Safety posture: local KMS envelope encryption, a durable local Postgres, and
 * NODE_ENV left non-production. Nothing here can send mail — the send guarantee
 * lives in the frozen core.
 */

export const LOCAL_DIR = path.join(os.homedir(), ".aaliyah-local");

const GOOGLE_CLIENT_FILE = path.join(LOCAL_DIR, "google_client.json");
const MAIL_KEY_FILE = path.join(LOCAL_DIR, "mail_key.txt");
const ANTHROPIC_KEY_FILE = path.join(LOCAL_DIR, "anthropic_key.txt");

/** Where the non-secret connection pointer (id + email) is stored after connect. */
export const CONNECTION_FILE = path.join(LOCAL_DIR, "connection.json");

/**
 * Fixed single-operator identity. A real person owns exactly one local mailbox,
 * so the multi-tenant isolation keys collapse to one stable triple. The verified
 * core still enforces tenant scoping — we just always present the same scope.
 */
export const LOCAL_IDENTITY = {
  tenantId: "local",
  workspaceId: "local:default",
  userId: "owner",
} as const;

/** Loopback port for the OAuth callback. Fixed so the redirect URI is stable. */
export const LOOPBACK_PORT = 47017;
export const REDIRECT_URI = `http://127.0.0.1:${LOOPBACK_PORT}/oauth2/callback`;

export const DEFAULT_DATABASE_URL =
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

type InstalledClient = {
  installed?: { client_id?: string; client_secret?: string };
  web?: { client_id?: string; client_secret?: string };
};

function readGoogleClient(): { clientId: string; clientSecret: string } {
  if (!fs.existsSync(GOOGLE_CLIENT_FILE)) {
    throw new Error(
      `Google client file not found at ${GOOGLE_CLIENT_FILE}. ` +
        `Download the Desktop OAuth client JSON from Google Cloud and save it there.`,
    );
  }
  const parsed = JSON.parse(fs.readFileSync(GOOGLE_CLIENT_FILE, "utf8")) as InstalledClient;
  const inner = parsed.installed ?? parsed.web;
  if (!inner?.client_id || !inner.client_secret) {
    throw new Error(
      `Malformed ${GOOGLE_CLIENT_FILE}: expected an "installed" (Desktop) OAuth client with client_id and client_secret.`,
    );
  }
  return { clientId: inner.client_id, clientSecret: inner.client_secret };
}

/**
 * Load (or first-time generate) the 32-byte local master key used for envelope
 * encryption of the refresh token at rest. Persisted 0600 so only this user can
 * read it — this is the key that protects the mailbox grant on disk/in Postgres.
 */
function loadOrCreateMailKey(): string {
  if (fs.existsSync(MAIL_KEY_FILE)) {
    return fs.readFileSync(MAIL_KEY_FILE, "utf8").trim();
  }
  const key = crypto.randomBytes(32).toString("base64");
  fs.mkdirSync(LOCAL_DIR, { recursive: true });
  fs.writeFileSync(MAIL_KEY_FILE, key, { mode: 0o600 });
  fs.chmodSync(MAIL_KEY_FILE, 0o600);
  return key;
}

function loadOptionalAnthropicKey(): string | undefined {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  if (fs.existsSync(ANTHROPIC_KEY_FILE)) {
    const key = fs.readFileSync(ANTHROPIC_KEY_FILE, "utf8").trim();
    return key.length > 0 ? key : undefined;
  }
  return undefined;
}

export type LocalConfig = {
  databaseUrl: string;
  redirectUri: string;
  hasAnthropicKey: boolean;
};

/**
 * Populate process.env with exactly what the verified core reads, then return a
 * small non-secret summary for logging. Idempotent: safe to call once per CLI
 * command before touching any core module.
 */
export function loadLocalEnv(): LocalConfig {
  const { clientId, clientSecret } = readGoogleClient();
  const mailKey = loadOrCreateMailKey();
  const anthropicKey = loadOptionalAnthropicKey();

  process.env.GOOGLE_CLIENT_ID = clientId;
  process.env.GOOGLE_CLIENT_SECRET = clientSecret;
  process.env.GOOGLE_OAUTH_REDIRECT_URI = REDIRECT_URI;

  // Local envelope-encryption KMS (not GCP Cloud KMS): the wrapper differs, the
  // encrypted-at-rest shape does not.
  process.env.AALIYAH_KMS_PROVIDER = "local";
  process.env.MAIL_CREDENTIAL_ENCRYPTION_KEY = mailKey;
  process.env.MAIL_CREDENTIAL_KEY_VERSION = process.env.MAIL_CREDENTIAL_KEY_VERSION ?? "local-v1";

  // Durable state on the local docker Postgres; idempotency in-memory (single
  // process, one operator). NODE_ENV stays non-production on purpose.
  process.env.AALIYAH_DATABASE_URL = process.env.AALIYAH_DATABASE_URL ?? DEFAULT_DATABASE_URL;
  process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

  if (anthropicKey) process.env.ANTHROPIC_API_KEY = anthropicKey;

  return {
    databaseUrl: process.env.AALIYAH_DATABASE_URL,
    redirectUri: REDIRECT_URI,
    hasAnthropicKey: Boolean(anthropicKey),
  };
}

export type StoredConnection = {
  connectionId: string;
  email: string;
  tenantId: string;
  workspaceId: string;
  userId: string;
  connectedAt: string;
};

export function saveConnection(conn: StoredConnection): void {
  fs.mkdirSync(LOCAL_DIR, { recursive: true });
  fs.writeFileSync(CONNECTION_FILE, JSON.stringify(conn, null, 2), { mode: 0o600 });
}

export function readConnection(): StoredConnection | null {
  if (!fs.existsSync(CONNECTION_FILE)) return null;
  return JSON.parse(fs.readFileSync(CONNECTION_FILE, "utf8")) as StoredConnection;
}
