import express, { type Express } from "express";
import { internalEvalRoutes } from "./internalEvalRoutes";
import { createMailRouter, type MailAuthDeps, type MailRoutesDeps } from "./mailRoutes";
import { createMembershipDirectory } from "../auth/membershipDirectory";
import { createSessionStore } from "../auth/sessionStore";
import { createInMemoryMailState, type MailStateBackend } from "../mail/mailState";
import { createMailDbPool } from "../persistence/postgres/pool";
import { createPostgresMailState } from "../persistence/postgres/mailStateStore";
import {
  googleCapability,
  loadGoogleConfig,
  buildGoogleConnectDeps,
} from "../mail/google/googleConfig";

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
  return {
    capability,
    redirectUri: config.redirectUri,
    frontendInboxesUrl,
    connectDeps: buildGoogleConnectDeps(config, state),
    auth,
    state,
  };
}

/**
 * Select the mail-state backend: Postgres when AALIYAH_DATABASE_URL is set
 * (the caller — server.ts — must run migrations before serving traffic),
 * otherwise in-memory for dev/tests. The choice is explicit and logged by
 * the caller; there is no silent production fallback to memory.
 */
export function mailStateFromEnv(env: NodeJS.ProcessEnv = process.env): MailStateBackend {
  if (env.AALIYAH_DATABASE_URL) {
    return createPostgresMailState(createMailDbPool(env));
  }
  return createInMemoryMailState();
}

export function createCoreApp(
  options: { mailAuth?: MailAuthDeps; mailState?: MailStateBackend } = {},
): Express {
  if (
    process.env.AALIYAH_ENABLE_INTERNAL_EVAL === "true" &&
    !process.env.AALIYAH_EVAL_SECRET
  ) {
    throw new Error("AALIYAH_EVAL_SECRET is required when internal eval routes are enabled");
  }

  const app = express();

  // Without an injected auth backend the directories are EMPTY: every mail
  // route fails closed with 401 — never an open header-trusting seam.
  const mailAuth = options.mailAuth ?? {
    sessions: createSessionStore(),
    directory: createMembershipDirectory(),
  };
  const mailState = options.mailState ?? mailStateFromEnv();

  app.use(express.json());
  app.use(internalEvalRoutes);
  app.use(createMailRouter(mailRoutesDeps(mailAuth, mailState)));

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  return app;
}
