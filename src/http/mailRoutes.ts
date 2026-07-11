import express, { type Router } from "express";

import type { SanitizedConnection } from "@aaliyah/contracts/v1";

import { logger } from "../observability/logger";
import type { TenantScope } from "../persistence/tenantScopedStore";
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

export type MailRoutesDeps = {
  capability: GoogleCapability;
  redirectUri: string; // exact OAuth redirect URI (must match Google console)
  frontendInboxesUrl: string; // e.g. https://app.example/settings/inboxes
  connectDeps?: GoogleConnectDeps; // present only when configured
};

type Identity = { tenantId: string; workspaceId: string; userId: string };

// ---- Handler functions (framework-independent, unit-testable) ----

export function startGoogleConnect(
  identity: Identity,
  deps: MailRoutesDeps,
):
  | { available: false; reasonCode: "provider_not_configured" }
  | { available: true; authorizationUrl: string } {
  if (!deps.capability.available || !deps.connectDeps) {
    return { available: false, reasonCode: "provider_not_configured" };
  }
  const { url } = buildGoogleAuthorizationUrl(
    { ...identity, redirectUri: deps.redirectUri },
    deps.connectDeps,
  );
  return { available: true, authorizationUrl: url };
}

/**
 * Process the callback and return ONLY a sanitized frontend redirect — never
 * codes, tokens, emails, or raw provider errors. A failure after state
 * consumption must not encourage replaying the same URL: the user is sent to a
 * generic failure page and must start a brand-new authorization.
 */
export async function handleGoogleCallbackRoute(
  input: { code?: string; state?: string; error?: string },
  deps: MailRoutesDeps,
): Promise<{ redirectTo: string }> {
  const base = deps.frontendInboxesUrl;
  if (input.error || !input.code || !input.state || !deps.connectDeps) {
    return { redirectTo: `${base}?connection=failed` };
  }
  try {
    await handleGoogleCallback(
      { code: input.code, state: input.state, redirectUri: deps.redirectUri },
      deps.connectDeps,
    );
    return { redirectTo: `${base}?connection=success` };
  } catch (error) {
    // Rollback already happened inside handleGoogleCallback. Log sanitized.
    logger.warn({ reason: error instanceof Error ? error.name : "unknown" }, "mail.google.callback_failed");
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
  scope: TenantScope,
  identity: Identity,
): SanitizedConnection | null {
  const conn = getConnection(connectionId, scope);
  if (!conn || conn.userId !== identity.userId) return null;
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
  scope: TenantScope,
  identity: Identity,
  deps: MailRoutesDeps,
  now: () => number = () => Date.now(),
): Promise<{ profileOk: boolean; threadsListed: number; draftId: string; marker: string }> {
  if (!deps.connectDeps) throw new Error("google not configured");
  const conn = getConnection(connectionId, scope);
  if (!conn || conn.userId !== identity.userId) throw new Error("connection not found");

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
  return { profileOk: health.healthy, threadsListed: threads.length, draftId: draft.draftId, marker };
}

export async function disconnectConnection(
  connectionId: string,
  scope: TenantScope,
  identity: Identity,
  deps: MailRoutesDeps,
): Promise<{ ok: boolean }> {
  if (!deps.connectDeps) return { ok: false };
  const conn = getConnection(connectionId, scope);
  if (!conn || conn.userId !== identity.userId) return { ok: false };
  await disconnectGoogle(connectionId, scope, deps.connectDeps);
  return { ok: true };
}

// ---- Express wiring (thin) ----

// TEMPORARY identity seam: production MUST replace this with an authenticated
// session/JWT. Until the auth layer lands, identity is read from signed headers
// set by the API gateway.
function identityOf(req: express.Request): Identity | null {
  const tenantId = req.header("x-aaliyah-tenant");
  const workspaceId = req.header("x-aaliyah-workspace");
  const userId = req.header("x-aaliyah-user");
  if (!tenantId || !workspaceId || !userId) return null;
  return { tenantId, workspaceId, userId };
}

export function createMailRouter(deps: MailRoutesDeps): Router {
  const router = express.Router();

  router.post("/api/mail/connections/google/start", (req, res) => {
    const id = identityOf(req);
    if (!id) return res.status(401).json({ error: "unauthenticated" });
    const result = startGoogleConnect(id, deps);
    return res.status(result.available ? 200 : 503).json(result);
  });

  router.get("/api/mail/connections/google/callback", async (req, res) => {
    const cb = {
      ...(typeof req.query.code === "string" ? { code: req.query.code } : {}),
      ...(typeof req.query.state === "string" ? { state: req.query.state } : {}),
      ...(typeof req.query.error === "string" ? { error: req.query.error } : {}),
    };
    const { redirectTo } = await handleGoogleCallbackRoute(cb, deps);
    return res.redirect(302, redirectTo);
  });

  router.get("/api/mail/connections/:connectionId", (req, res) => {
    const id = identityOf(req);
    if (!id) return res.status(401).json({ error: "unauthenticated" });
    const status = getConnectionStatus(
      req.params.connectionId,
      { tenantId: id.tenantId, workspaceId: id.workspaceId },
      id,
    );
    return status ? res.json(status) : res.status(404).json({ error: "not_found" });
  });

  router.post("/api/mail/connections/:connectionId/test", async (req, res) => {
    const id = identityOf(req);
    if (!id) return res.status(401).json({ error: "unauthenticated" });
    try {
      const result = await testConnection(
        req.params.connectionId,
        { tenantId: id.tenantId, workspaceId: id.workspaceId },
        id,
        deps,
      );
      return res.json(result);
    } catch {
      return res.status(400).json({ error: "test_failed" });
    }
  });

  router.delete("/api/mail/connections/:connectionId", async (req, res) => {
    const id = identityOf(req);
    if (!id) return res.status(401).json({ error: "unauthenticated" });
    const result = await disconnectConnection(
      req.params.connectionId,
      { tenantId: id.tenantId, workspaceId: id.workspaceId },
      id,
      deps,
    );
    return res.status(result.ok ? 200 : 404).json(result);
  });

  return router;
}
