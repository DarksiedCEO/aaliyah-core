import crypto from "node:crypto";

import express, { type Router } from "express";

import { logger } from "../observability/logger";
import type { AuthService } from "../auth/authService";
import { CSRF_COOKIE, SESSION_COOKIE } from "./mailRoutes";

/**
 * Identity routes. These authenticate the HUMAN operating Aaliyah — they
 * grant and revoke nothing over any mailbox. Gmail mailbox authorization is
 * a separate credential with a separate lifecycle (mail routes): logging out
 * here never disconnects a company inbox, and disconnecting an inbox never
 * deletes a login.
 */

function cookie(name: string, value: string, opts: { httpOnly: boolean; maxAgeMs: number }): string {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${Math.floor(opts.maxAgeMs / 1000)}`,
    ...(opts.httpOnly ? ["HttpOnly"] : []),
  ];
  return attrs.join("; ");
}

function clearedCookie(name: string): string {
  return `${name}=; Path=/; Secure; SameSite=Strict; Max-Age=0`;
}

export type AuthRoutesDeps = {
  auth: AuthService;
  /** Absent → login is cleanly unavailable (provider_not_configured). */
  googleLoginAvailable: boolean;
  sessionCookieMaxAgeMs?: number;
};

export function createAuthRouter(deps: AuthRoutesDeps): Router {
  const router = express.Router();
  const maxAgeMs = deps.sessionCookieMaxAgeMs ?? 12 * 60 * 60 * 1000;

  router.post("/api/auth/google/login", async (req, res) => {
    if (!deps.googleLoginAvailable) {
      res.status(503).json({ error: "provider_not_configured" });
      return;
    }
    const body = (req.body ?? {}) as { idToken?: unknown; tenantId?: unknown; nonce?: unknown };
    if (typeof body.idToken !== "string" || typeof body.tenantId !== "string") {
      res.status(400).json({ error: "id_token_and_tenant_required" });
      return;
    }
    try {
      const login = await deps.auth.loginWithGoogle({
        idToken: body.idToken,
        tenantId: body.tenantId,
        ...(typeof body.nonce === "string" ? { expectedNonce: body.nonce } : {}),
      });
      // Fresh server-generated session on every login (fixation-proof).
      // Session cookie is httpOnly; the CSRF cookie is deliberately not, for
      // the double-submit pattern.
      const csrfToken = crypto.randomBytes(24).toString("base64url");
      res.setHeader("set-cookie", [
        cookie(SESSION_COOKIE, login.token, { httpOnly: true, maxAgeMs }),
        cookie(CSRF_COOKIE, csrfToken, { httpOnly: false, maxAgeMs }),
      ]);
      res.json({ sessionId: login.sessionId, userId: login.userId, tenantId: login.tenantId, csrfToken });
    } catch (error) {
      // One generic refusal: no oracle for which check failed, nothing echoed.
      logger.warn(
        { reason: error instanceof Error ? error.name : "unknown" },
        "auth.google.login_refused",
      );
      res.status(401).json({ error: "login_refused" });
    }
  });

  router.post("/api/auth/logout", async (req, res) => {
    // Revoke whichever credential presented itself; clearing cookies alone
    // would leave a live durable session behind.
    const header = req.header("authorization");
    const bearer = header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : null;
    const cookieHeader = req.header("cookie") ?? "";
    const cookieToken = /(?:^|;\s*)aaliyah_session=([^;]+)/.exec(cookieHeader)?.[1];
    const token = bearer ?? (cookieToken ? decodeURIComponent(cookieToken) : null);
    if (token) await deps.auth.logout(token);
    res.setHeader("set-cookie", [clearedCookie(SESSION_COOKIE), clearedCookie(CSRF_COOKIE)]);
    res.json({ ok: true });
  });

  return router;
}
