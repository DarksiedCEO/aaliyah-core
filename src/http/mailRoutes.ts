import express, { type Router } from "express";

import type { Principal, SanitizedConnection } from "@aaliyah/contracts/v1";

import { logger } from "../observability/logger";
import type { TenantScope } from "../persistence/tenantScopedStore";
import type { MembershipDirectory } from "../auth/membershipDirectory";
import { authorizeMail, AuthorizationError } from "../auth/permissions";
import type { SessionStore } from "../auth/sessionStore";
import { GoogleMailAdapter } from "../mail/adapters/googleMailAdapter";
import { getConnection } from "../mail/connectionStore";
import {
  buildGoogleAuthorizationUrl,
  disconnectGoogle,
  handleGoogleCallback,
  refreshGoogleAccessToken,
  type GoogleConnectDeps,
} from "../mail/google/googleConnect";
import type { GoogleCapability } from "../mail/google/googleConfig";
import { recordMailAudit } from "../mail/security/mailAudit";

export type MailAuthDeps = {
  sessions: SessionStore;
  directory: MembershipDirectory;
};

export type MailRoutesDeps = {
  capability: GoogleCapability;
  redirectUri: string; // exact OAuth redirect URI (must match Google console)
  frontendInboxesUrl: string; // e.g. https://app.example/settings/inboxes
  connectDeps?: GoogleConnectDeps; // present only when configured
  auth: MailAuthDeps;
};

// ---- Server-verified principal resolution ----
//
// Identity comes ONLY from a bearer credential resolved against the session
// store (humans) or the service registry (workloads). x-aaliyah-* headers are
// never read: a header is a claim, not an identity.

export function authenticateRequest(
  req: express.Request,
  auth: MailAuthDeps,
): Principal | null {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  if (!token) return null;

  const session = auth.sessions.resolveSession(token);
  if (session) return auth.directory.principalForSession(session);
  return auth.directory.servicePrincipalForToken(token);
}

function actorFields(principal: Principal): {
  actorType: "user" | "service";
  actorUserId?: string;
  actorServiceId?: string;
} {
  return principal.actorType === "user"
    ? { actorType: "user", actorUserId: principal.userId }
    : { actorType: "service", actorServiceId: principal.serviceId };
}

/** Audit an authorization decision — allowed or denied — with the actor. */
function auditDecision(
  principal: Principal,
  workspaceId: string,
  action: string,
  decision: "allowed" | "denied",
  detail?: string,
): void {
  recordMailAudit({
    tenantId: principal.tenantId,
    workspaceId,
    ...actorFields(principal),
    action,
    detail: detail ?? decision,
  });
}

// ---- Handler functions (framework-independent, unit-testable) ----

export function startGoogleConnect(
  principal: Principal,
  workspaceId: string,
  deps: MailRoutesDeps,
):
  | { available: false; reasonCode: "provider_not_configured" }
  | { available: true; authorizationUrl: string } {
  authorizeMail(principal, "mail.connection.create", {
    tenantId: principal.tenantId,
    workspaceId,
  });
  if (principal.actorType !== "user") {
    // Defense in depth: create grants are refused for services at registration,
    // and OAuth state must bind to a human session.
    throw new AuthorizationError("permission_denied", "oauth connect requires a user session");
  }
  if (!deps.capability.available || !deps.connectDeps) {
    return { available: false, reasonCode: "provider_not_configured" };
  }
  const { url } = buildGoogleAuthorizationUrl(
    {
      tenantId: principal.tenantId,
      workspaceId,
      userId: principal.userId,
      sessionId: principal.sessionId,
      redirectUri: deps.redirectUri,
    },
    deps.connectDeps,
  );
  auditDecision(principal, workspaceId, "mail.connection.start_requested", "allowed");
  return { available: true, authorizationUrl: url };
}

/**
 * Process the callback and return ONLY a sanitized frontend redirect — never
 * codes, tokens, emails, or raw provider errors. Tenant and workspace come
 * exclusively from the session-bound OAuth state; nothing identity-bearing is
 * accepted from the callback query. A failure after state consumption must not
 * encourage replaying the same URL: the user is sent to a generic failure page
 * and must start a brand-new authorization.
 */
export async function handleGoogleCallbackRoute(
  input: { code?: string; state?: string; error?: string },
  principal: Principal | null,
  deps: MailRoutesDeps,
): Promise<{ redirectTo: string }> {
  const base = deps.frontendInboxesUrl;
  if (
    !principal ||
    principal.actorType !== "user" ||
    input.error ||
    !input.code ||
    !input.state ||
    !deps.connectDeps
  ) {
    return { redirectTo: `${base}?connection=failed` };
  }
  try {
    await handleGoogleCallback(
      {
        code: input.code,
        state: input.state,
        redirectUri: deps.redirectUri,
        expectedSessionId: principal.sessionId,
        expectedTenantId: principal.tenantId,
      },
      deps.connectDeps,
    );
    return { redirectTo: `${base}?connection=success` };
  } catch (error) {
    // Rollback already happened inside handleGoogleCallback. Log sanitized.
    logger.warn(
      { reason: error instanceof Error ? error.name : "unknown" },
      "mail.google.callback_failed",
    );
    return { redirectTo: `${base}?connection=failed` };
  }
}

function clientStatus(stored: string): SanitizedConnection["status"] {
  if (stored === "connected") return "connected";
  if (stored === "disconnected") return "disconnected";
  return "needs_attention";
}

export function getConnectionStatus(
  connectionId: string,
  workspaceId: string,
  principal: Principal,
): SanitizedConnection | null {
  authorizeMail(principal, "mail.connection.read", {
    tenantId: principal.tenantId,
    workspaceId,
  });
  const scope: TenantScope = { tenantId: principal.tenantId, workspaceId };
  const conn = getConnection(connectionId, scope);
  if (!conn) return null;
  auditDecision(principal, workspaceId, "mail.connection.read", "allowed", connectionId);
  return {
    connectionId: conn.connectionId,
    provider: "google",
    connectedEmail: conn.emailAddress,
    status: clientStatus(conn.status),
  };
}

/**
 * Controlled connection test: verify identity, read one message, create and
 * retrieve one uniquely-named draft. NEVER sends. Returns a sanitized summary.
 */
export async function testConnection(
  connectionId: string,
  workspaceId: string,
  principal: Principal,
  deps: MailRoutesDeps,
  now: () => number = () => Date.now(),
): Promise<{ profileOk: boolean; threadsListed: number; draftId: string; marker: string }> {
  authorizeMail(principal, "mail.connection.test", {
    tenantId: principal.tenantId,
    workspaceId,
  });
  if (!deps.connectDeps) throw new Error("google not configured");
  const scope: TenantScope = { tenantId: principal.tenantId, workspaceId };
  const conn = getConnection(connectionId, scope);
  if (!conn) throw new Error("connection not found");

  const accessToken = await refreshGoogleAccessToken(connectionId, scope, deps.connectDeps);
  const adapter = new GoogleMailAdapter({ resolveAccessToken: () => accessToken });

  const health = await adapter.verify(connectionId);
  const threads = await adapter.listThreads({ connectionId, limit: 1 });
  if (threads.length > 0) {
    await adapter.readThread({ connectionId, threadId: threads[0]!.threadId });
  }
  const marker = `AALIYAH_GOOGLE_SMOKE_${now()}`;
  const draft = await adapter.createDraft({
    connectionId,
    to: [{ email: conn.emailAddress }],
    subject: marker,
    body: "Aaliyah connection self-test — safe to delete.",
  });
  auditDecision(principal, workspaceId, "mail.connection.test_requested", "allowed", connectionId);
  return { profileOk: health.healthy, threadsListed: threads.length, draftId: draft.draftId, marker };
}

export async function disconnectConnection(
  connectionId: string,
  workspaceId: string,
  principal: Principal,
  deps: MailRoutesDeps,
): Promise<{ ok: boolean }> {
  authorizeMail(principal, "mail.connection.disconnect", {
    tenantId: principal.tenantId,
    workspaceId,
  });
  if (!deps.connectDeps) return { ok: false };
  const scope: TenantScope = { tenantId: principal.tenantId, workspaceId };
  const conn = getConnection(connectionId, scope);
  if (!conn) return { ok: false };
  await disconnectGoogle(connectionId, scope, deps.connectDeps);
  auditDecision(principal, workspaceId, "mail.connection.disconnect_requested", "allowed", connectionId);
  return { ok: true };
}

// ---- Express wiring (thin) ----

type AuthedHandler = (
  req: express.Request,
  res: express.Response,
  principal: Principal,
) => void | Promise<void>;

export function createMailRouter(deps: MailRoutesDeps): Router {
  const router = express.Router();

  /** 401 without a verified principal; 403 (audited) on authorization denial. */
  const authed = (handler: AuthedHandler) =>
    async (req: express.Request, res: express.Response): Promise<void> => {
      const principal = authenticateRequest(req, deps.auth);
      if (!principal) {
        res.status(401).json({ error: "unauthenticated" });
        return;
      }
      try {
        await handler(req, res, principal);
      } catch (error) {
        if (error instanceof AuthorizationError) {
          auditDecision(
            principal,
            workspaceParam(req) ?? "unspecified",
            "mail.authz.denied",
            "denied",
            error.code,
          );
          res.status(403).json({ error: error.code });
          return;
        }
        throw error;
      }
    };

  const workspaceParam = (req: express.Request): string | null => {
    const fromBody =
      typeof req.body === "object" && req.body !== null
        ? (req.body as Record<string, unknown>).workspaceId
        : undefined;
    const fromQuery = req.query.workspaceId;
    const value = typeof fromBody === "string" ? fromBody : fromQuery;
    return typeof value === "string" && value.length > 0 ? value : null;
  };

  router.post(
    "/api/mail/connections/google/start",
    authed((req, res, principal) => {
      const workspaceId = workspaceParam(req);
      if (!workspaceId) {
        res.status(400).json({ error: "workspace_required" });
        return;
      }
      const result = startGoogleConnect(principal, workspaceId, deps);
      res.status(result.available ? 200 : 503).json(result);
    }),
  );

  router.get("/api/mail/connections/google/callback", async (req, res) => {
    // The callback authenticates like every other route, but browser-redirect
    // ergonomics demand a redirect rather than a JSON 401 on failure.
    const principal = authenticateRequest(req, deps.auth);
    const cb = {
      ...(typeof req.query.code === "string" ? { code: req.query.code } : {}),
      ...(typeof req.query.state === "string" ? { state: req.query.state } : {}),
      ...(typeof req.query.error === "string" ? { error: req.query.error } : {}),
    };
    const { redirectTo } = await handleGoogleCallbackRoute(cb, principal, deps);
    return res.redirect(302, redirectTo);
  });

  router.get(
    "/api/mail/connections/:connectionId",
    authed((req, res, principal) => {
      const workspaceId = workspaceParam(req);
      if (!workspaceId) {
        res.status(400).json({ error: "workspace_required" });
        return;
      }
      const status = getConnectionStatus(String(req.params.connectionId), workspaceId, principal);
      if (status) res.json(status);
      else res.status(404).json({ error: "not_found" });
    }),
  );

  router.post(
    "/api/mail/connections/:connectionId/test",
    authed(async (req, res, principal) => {
      const workspaceId = workspaceParam(req);
      if (!workspaceId) {
        res.status(400).json({ error: "workspace_required" });
        return;
      }
      try {
        const result = await testConnection(String(req.params.connectionId), workspaceId, principal, deps);
        res.json(result);
      } catch (error) {
        if (error instanceof AuthorizationError) throw error; // 403 via authed()
        res.status(400).json({ error: "test_failed" });
      }
    }),
  );

  router.delete(
    "/api/mail/connections/:connectionId",
    authed(async (req, res, principal) => {
      const workspaceId = workspaceParam(req);
      if (!workspaceId) {
        res.status(400).json({ error: "workspace_required" });
        return;
      }
      const result = await disconnectConnection(
        String(req.params.connectionId),
        workspaceId,
        principal,
        deps,
      );
      res.status(result.ok ? 200 : 404).json(result);
    }),
  );

  return router;
}
