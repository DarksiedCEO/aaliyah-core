import express, { type Express } from "express";
import { internalEvalRoutes } from "./internalEvalRoutes";
import { createMailRouter, type MailRoutesDeps } from "./mailRoutes";
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
function mailRoutesDeps(): MailRoutesDeps {
  const capability = googleCapability();
  const frontendInboxesUrl =
    process.env.AALIYAH_FRONTEND_INBOXES_URL ?? "/settings/inboxes";
  if (!capability.available) {
    return { capability, redirectUri: "", frontendInboxesUrl };
  }
  const config = loadGoogleConfig();
  return {
    capability,
    redirectUri: config.redirectUri,
    frontendInboxesUrl,
    connectDeps: buildGoogleConnectDeps(config),
  };
}

export function createCoreApp(): Express {
  if (
    process.env.AALIYAH_ENABLE_INTERNAL_EVAL === "true" &&
    !process.env.AALIYAH_EVAL_SECRET
  ) {
    throw new Error("AALIYAH_EVAL_SECRET is required when internal eval routes are enabled");
  }

  const app = express();

  app.use(express.json());
  app.use(internalEvalRoutes);
  app.use(createMailRouter(mailRoutesDeps()));

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  return app;
}
