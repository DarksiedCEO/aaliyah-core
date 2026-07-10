import crypto from "node:crypto";

import type { AuthStrength } from "@aaliyah/contracts/v1";

export type ResolvedSession = {
  sessionId: string;
  userId: string;
  authStrength: AuthStrength;
};

type SessionRecord = ResolvedSession & { revokedAt: string | null };

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type SessionStore = {
  issueSession(input: { userId: string; authStrength: AuthStrength }): {
    token: string;
    sessionId: string;
  };
  /** null on unknown, forged, or revoked tokens — never throws identity out. */
  resolveSession(token: string): ResolvedSession | null;
  revokeSession(sessionId: string): void;
  /** Test/inspection hook: the store's full serializable state (no raw tokens). */
  debugState(): unknown;
};

/**
 * In-memory session registry. The bearer token is returned once at issuance
 * and held only as a SHA-256 digest — the store can prove a token, but can
 * never leak one. Production replaces this with the durable session backend.
 */
export function createSessionStore(): SessionStore {
  const byTokenHash = new Map<string, SessionRecord>();
  const tokenHashBySessionId = new Map<string, string>();

  return {
    issueSession(input) {
      const token = b64url(crypto.randomBytes(32));
      const sessionId = `sess_${b64url(crypto.randomBytes(16))}`;
      byTokenHash.set(hashToken(token), {
        sessionId,
        userId: input.userId,
        authStrength: input.authStrength,
        revokedAt: null,
      });
      tokenHashBySessionId.set(sessionId, hashToken(token));
      return { token, sessionId };
    },

    resolveSession(token) {
      const record = byTokenHash.get(hashToken(token));
      if (!record || record.revokedAt) return null;
      const { revokedAt: _revokedAt, ...session } = record;
      return session;
    },

    revokeSession(sessionId) {
      const tokenHash = tokenHashBySessionId.get(sessionId);
      if (!tokenHash) return;
      const record = byTokenHash.get(tokenHash);
      if (record && !record.revokedAt) {
        byTokenHash.set(tokenHash, { ...record, revokedAt: new Date().toISOString() });
      }
    },

    debugState() {
      return {
        sessions: [...byTokenHash.entries()].map(([tokenHash, record]) => ({
          tokenHash,
          ...record,
        })),
      };
    },
  };
}
