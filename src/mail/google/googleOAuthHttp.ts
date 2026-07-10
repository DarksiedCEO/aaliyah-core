import crypto from "node:crypto";
import { z } from "zod";

import { logger } from "../../observability/logger";
import type {
  GoogleMailboxProfile,
  GoogleOAuthHttp,
  GoogleTokenResponse,
} from "./googleConnect";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile";

// Validate every provider response at runtime — never trust a 200 blindly.
const TokenSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().optional(),
  expires_in: z.number(),
  scope: z.string().default(""),
});
const ProfileSchema = z.object({ emailAddress: z.string().email() });

/** Redact anything token-shaped before it can reach a log. */
function redact(text: string): string {
  return text
    .replace(/(access_token|refresh_token|code|client_secret)=([^&\s"]+)/gi, "$1=REDACTED")
    .replace(/"(access_token|refresh_token)":\s*"[^"]+"/gi, '"$1":"REDACTED"');
}

export class GoogleHttpError extends Error {
  readonly status: number;
  readonly correlationId: string;
  constructor(op: string, status: number, correlationId: string) {
    super(`google.${op} failed (${status}) [cid=${correlationId}]`);
    this.name = "GoogleHttpError";
    this.status = status;
    this.correlationId = correlationId;
  }
}

export type GoogleHttpOptions = {
  clientId: string;
  clientSecret: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number; // for SAFE (idempotent) ops only
};

/**
 * Concrete Google OAuth transport. Bounded retries apply ONLY to idempotent
 * operations (refresh, profile, revoke) — never to code exchange, which is
 * single-use. Timeouts, structured errors, response-schema validation, token
 * redaction, and correlation ids are built in; raw response bodies are never
 * logged.
 */
export function createGoogleOAuthHttp(opts: GoogleHttpOptions): GoogleOAuthHttp {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxRetries = opts.maxRetries ?? 2;

  async function request(
    op: string,
    url: string,
    init: RequestInit,
    { retry }: { retry: boolean },
  ): Promise<unknown> {
    const cid = crypto.randomUUID();
    const attempts = retry ? maxRetries + 1 : 1;
    let lastErr: unknown;

    for (let i = 0; i < attempts; i += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await doFetch(url, { ...init, signal: controller.signal });
        clearTimeout(timer);
        if (res.ok) return await res.json();
        // 5xx are transient for safe ops; 4xx are terminal.
        if (res.status >= 500 && retry && i < attempts - 1) {
          lastErr = new GoogleHttpError(op, res.status, cid);
          continue;
        }
        logger.warn({ op, status: res.status, cid }, "google.http.error");
        throw new GoogleHttpError(op, res.status, cid);
      } catch (error) {
        clearTimeout(timer);
        if (error instanceof GoogleHttpError) throw error;
        // network/timeout — retry only for safe ops
        lastErr = error;
        if (!retry || i >= attempts - 1) {
          logger.warn({ op, cid, reason: redact(String(error)) }, "google.http.network_error");
          throw new GoogleHttpError(op, 0, cid);
        }
      }
    }
    throw lastErr ?? new GoogleHttpError(op, 0, cid);
  }

  return {
    async exchangeAuthorizationCode(input): Promise<GoogleTokenResponse> {
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code: input.code,
        code_verifier: input.codeVerifier,
        redirect_uri: input.redirectUri,
        client_id: opts.clientId,
        client_secret: opts.clientSecret,
      });
      const raw = await request(
        "exchange",
        TOKEN_URL,
        { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
        { retry: false }, // single-use code — never retried
      );
      const parsed = TokenSchema.parse(raw);
      return {
        accessToken: parsed.access_token,
        ...(parsed.refresh_token ? { refreshToken: parsed.refresh_token } : {}),
        expiresIn: parsed.expires_in,
        scope: parsed.scope,
      };
    },

    async refreshAccessToken(refreshToken): Promise<GoogleTokenResponse> {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: opts.clientId,
        client_secret: opts.clientSecret,
      });
      const raw = await request(
        "refresh",
        TOKEN_URL,
        { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
        { retry: true },
      );
      const parsed = TokenSchema.parse(raw);
      return {
        accessToken: parsed.access_token,
        ...(parsed.refresh_token ? { refreshToken: parsed.refresh_token } : {}),
        expiresIn: parsed.expires_in,
        scope: parsed.scope,
      };
    },

    async fetchMailboxProfile(accessToken): Promise<GoogleMailboxProfile> {
      const raw = await request(
        "profile",
        PROFILE_URL,
        { method: "GET", headers: { Authorization: `Bearer ${accessToken}` } },
        { retry: true },
      );
      const parsed = ProfileSchema.parse(raw);
      return { email: parsed.emailAddress };
    },

    async revokeToken(token): Promise<void> {
      await request(
        "revoke",
        REVOKE_URL,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token }),
        },
        { retry: true },
      ).catch(() => {
        // revocation is best-effort — already-revoked tokens 400 and that's fine
      });
    },
  };
}
