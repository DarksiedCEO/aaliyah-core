import http from "node:http";
import crypto from "node:crypto";
import { exec } from "node:child_process";

import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresMailState } from "../src/persistence/postgres/mailStateStore";
import { loadGoogleConfig, buildGoogleConnectDeps } from "../src/mail/google/googleConfig";
import {
  buildGoogleAuthorizationUrl,
  handleGoogleCallback,
} from "../src/mail/google/googleConnect";

import {
  loadLocalEnv,
  saveConnection,
  LOCAL_IDENTITY,
  LOOPBACK_PORT,
  REDIRECT_URI,
} from "./env";

/**
 * `connect` — one-time loopback OAuth against the operator's own Gmail.
 *
 * This is a thin driver over the VERIFIED connect path: PKCE state, code
 * exchange, verified-identity fetch, envelope-encrypted refresh token, durable
 * persistence, and audit all happen inside handleGoogleCallback — unchanged. The
 * only local part is catching Google's redirect on 127.0.0.1 and recording a
 * non-secret pointer to the resulting connection.
 */

const SUCCESS_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>Aaliyah connected</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{text-align:center;max-width:420px;padding:2rem}h1{font-size:1.4rem}p{color:#9aa0a6}</style></head>
<body><div class="card"><h1>✅ Aaliyah is connected</h1><p>Your inbox is linked. You can close this tab and return to the terminal.</p></div></body></html>`;

function errorHtml(detail: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Aaliyah connect failed</title></head>
<body style="font-family:system-ui;padding:2rem"><h1>Connection failed</h1><p>${detail}</p>
<p>Return to the terminal and try again.</p></body></html>`;
}

function openBrowser(url: string): void {
  // Best effort — if it fails, the printed URL is the fallback.
  exec(`open "${url.replace(/"/g, "%22")}"`, () => undefined);
}

export async function runConnect(): Promise<void> {
  loadLocalEnv();

  const pool = createMailDbPool();
  await runMailMigrations(pool);
  const state = createPostgresMailState(pool);
  const config = loadGoogleConfig();
  const deps = buildGoogleConnectDeps(config, state);

  const sessionId = crypto.randomUUID();
  const { url } = await buildGoogleAuthorizationUrl(
    {
      tenantId: LOCAL_IDENTITY.tenantId,
      workspaceId: LOCAL_IDENTITY.workspaceId,
      userId: LOCAL_IDENTITY.userId,
      sessionId,
      redirectUri: REDIRECT_URI,
    },
    deps,
  );

  await new Promise<void>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const requestUrl = new URL(req.url ?? "/", `http://127.0.0.1:${LOOPBACK_PORT}`);
      if (requestUrl.pathname !== "/oauth2/callback") {
        res.writeHead(404).end();
        return;
      }

      const err = requestUrl.searchParams.get("error");
      const code = requestUrl.searchParams.get("code");
      const returnedState = requestUrl.searchParams.get("state");

      const finish = (statusCode: number, html: string, outcome: () => void) => {
        res.writeHead(statusCode, { "Content-Type": "text/html" }).end(html);
        // Close the socket server so the process can exit cleanly, then settle.
        server.close(() => outcome());
      };

      if (err || !code || !returnedState) {
        finish(400, errorHtml(err ?? "missing code/state"), () =>
          reject(new Error(`OAuth callback error: ${err ?? "missing code/state"}`)),
        );
        return;
      }

      handleGoogleCallback(
        { code, state: returnedState, redirectUri: REDIRECT_URI, expectedSessionId: sessionId },
        deps,
      )
        .then((conn) => {
          saveConnection({
            connectionId: conn.connectionId,
            email: conn.connectedEmail,
            tenantId: LOCAL_IDENTITY.tenantId,
            workspaceId: LOCAL_IDENTITY.workspaceId,
            userId: LOCAL_IDENTITY.userId,
            connectedAt: new Date().toISOString(),
          });
          // eslint-disable-next-line no-console
          console.log(`\n✅ Connected: ${conn.connectedEmail}`);
          finish(200, SUCCESS_HTML, () => resolve());
        })
        .catch((error: unknown) => {
          const detail = error instanceof Error ? error.message : "unknown error";
          finish(500, errorHtml(detail), () => reject(error instanceof Error ? error : new Error(detail)));
        });
    });

    server.on("error", reject);
    server.listen(LOOPBACK_PORT, "127.0.0.1", () => {
      // eslint-disable-next-line no-console
      console.log("Opening Google sign-in in your browser…");
      console.log("If it doesn't open, paste this URL:\n");
      console.log(url + "\n");
      openBrowser(url);
    });
  }).finally(() => pool.end());
}
