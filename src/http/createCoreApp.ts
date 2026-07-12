import express, { type Express } from "express";
import { internalEvalRoutes } from "./internalEvalRoutes";
import { createAuthRouter } from "./authRoutes";
import { createMailRouter, type MailAuthDeps, type MailRoutesDeps } from "./mailRoutes";
import { createAuthService, type AuthService } from "../auth/authService";
import { fetchGoogleJwks } from "../auth/googleIdentity";
import { createInMemoryIdentityState, type IdentityBackend } from "../auth/identityState";
import { createInMemoryMailState, type MailStateBackend } from "../mail/mailState";
import { createMailDbPool } from "../persistence/postgres/pool";
import { createPostgresIdentityState } from "../persistence/postgres/identityStateStore";
import { createPostgresMailState } from "../persistence/postgres/mailStateStore";
import {
  googleCapability,
  loadGoogleConfig,
  buildGoogleConnectDeps,
} from "../mail/google/googleConfig";
import { createCredentialLifecycle } from "../mail/google/credentialLifecycle";
import type { ReadinessProbe } from "./readiness";

/**
 * Build mail-route deps from the environment. When Google is unconfigured the
 * routes still mount, but `/start` returns a clean `provider_not_configured`
 * capability — the Connect button never appears functional against a
 * half-configured backend.
 */
function mailRoutesDeps(auth: MailAuthDeps, state: MailStateBackend): MailRoutesDeps {
  const capability = googleCapability();
  const frontendInboxesUrl =
    process.env.AALIYAH_FRONTEND_INBOXES_URL ?? "/settings/inboxes";
  if (!capability.available) {
    return { capability, redirectUri: "", frontendInboxesUrl, auth, state };
  }
  const config = loadGoogleConfig();
  const connectDeps = buildGoogleConnectDeps(config, state);
  return {
    capability,
    redirectUri: config.redirectUri,
    frontendInboxesUrl,
    connectDeps,
    // One lifecycle per process: its access-token cache and single-flight guard
    // are intentionally per-instance (see credentialLifecycle.ts).
    credentialLifecycle: createCredentialLifecycle({
      state,
      kms: connectDeps.kms,
      http: connectDeps.http,
    }),
    auth,
    state,
  };
}

/**
 * Select the mail-state backend: Postgres when AALIYAH_DATABASE_URL is set
 * (the caller — server.ts — must run migrations before serving traffic),
 * otherwise in-memory for dev/tests. In production the durable backend is
 * REQUIRED — startup fails closed rather than running approvals, credentials,
 * or audit on process memory.
 */
export function mailStateFromEnv(env: NodeJS.ProcessEnv = process.env): MailStateBackend {
  if (env.AALIYAH_DATABASE_URL) {
    return createPostgresMailState(createMailDbPool(env));
  }
  if (env.NODE_ENV === "production") {
    throw new Error(
      "durable mail state is required in production: set AALIYAH_DATABASE_URL (no in-memory fallback)",
    );
  }
  return createInMemoryMailState();
}

/**
 * Select the identity backend under the same rule: production cannot boot on
 * the in-memory identity twin — sessions, memberships, and revocations must
 * survive restarts and be shared across instances.
 */
export function identityStateFromEnv(env: NodeJS.ProcessEnv = process.env): IdentityBackend {
  if (env.AALIYAH_DATABASE_URL) {
    return createPostgresIdentityState(createMailDbPool(env));
  }
  if (env.NODE_ENV === "production") {
    throw new Error(
      "durable identity state is required in production: set AALIYAH_DATABASE_URL (no in-memory fallback)",
    );
  }
  return createInMemoryIdentityState();
}

export function createCoreApp(
  options: {
    mailAuth?: MailAuthDeps;
    mailState?: MailStateBackend;
    identityState?: IdentityBackend;
    authService?: AuthService;
    /** Readiness probe for /ready. Defaults to trivially-ready (dev); the
     * server wires a real Postgres ping in production. */
    readinessProbe?: ReadinessProbe;
  } = {},
): Express {
  if (
    process.env.AALIYAH_ENABLE_INTERNAL_EVAL === "true" &&
    !process.env.AALIYAH_EVAL_SECRET
  ) {
    throw new Error("AALIYAH_EVAL_SECRET is required when internal eval routes are enabled");
  }

  const app = express();

  const mailState = options.mailState ?? mailStateFromEnv();
  const identityState = options.identityState ?? identityStateFromEnv();

  // Google IDENTITY login (who is the human) is configured independently of
  // Gmail mailbox OAuth (which mailbox authorized Aaliyah) — separate
  // credentials, separate lifecycles, separate revocation.
  const googleLoginAvailable = Boolean(process.env.GOOGLE_CLIENT_ID);
  const authService =
    options.authService ??
    createAuthService(identityState, {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID ?? "unconfigured",
        jwks: fetchGoogleJwks(),
      },
    });

  // The ONLY principal source: the durable resolver. With an empty identity
  // backend every mail route fails closed with 401.
  const mailAuth = options.mailAuth ?? {
    principalForToken: authService.principalForToken,
  };

  app.use(express.json());
  app.use(internalEvalRoutes);
  app.use(createAuthRouter({ auth: authService, googleLoginAvailable }));
  app.use(createMailRouter(mailRoutesDeps(mailAuth, mailState)));

  // Liveness: the process is up and the event loop is responsive. Deliberately
  // dependency-free — a liveness failure means "restart me", not "back off".
  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  // Readiness: can we actually serve? Fails 503 when a durable dependency is
  // unreachable so the load balancer stops routing until it recovers.
  const readinessProbe: ReadinessProbe =
    options.readinessProbe ?? (async () => ({ ready: true, checks: {} }));
  app.get("/ready", async (_req, res) => {
    try {
      const result = await readinessProbe();
      res.status(result.ready ? 200 : 503).json({
        status: result.ready ? "ready" : "not_ready",
        checks: result.checks,
      });
    } catch {
      res.status(503).json({ status: "not_ready", checks: { probe: "unavailable" } });
    }
  });

  return app;
}
