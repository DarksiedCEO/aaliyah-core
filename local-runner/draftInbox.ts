import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresMailState } from "../src/persistence/postgres/mailStateStore";
import { loadGoogleConfig } from "../src/mail/google/googleConfig";
import { createGoogleOAuthHttp } from "../src/mail/google/googleOAuthHttp";
import {
  createCredentialLifecycle,
  ReauthRequiredError,
  CredentialRevokedError,
} from "../src/mail/google/credentialLifecycle";
import { GoogleMailAdapter } from "../src/mail/adapters/googleMailAdapter";
import { analyzeInbound } from "../src/application/inbound/analyzeInbound";
import {
  deterministicDraftGenerator,
  type DraftGenerator,
} from "../src/application/inbound/generateInboundDraft";
import {
  runInboundDraft,
  inboundDraftInternals,
} from "../src/application/inbound/runInboundDraft";

import { readLatestInbound } from "./gmailReader";
import { createAnthropicDraftGenerator } from "./anthropicDraftGenerator";
import { loadLocalEnv, readConnection } from "./env";

/* eslint-disable no-console */

/**
 * `draft-inbox` — for each recent inbox thread, draft a reply and (unless
 * --dry-run) save it to Gmail for the operator to review. NEVER sends.
 *
 * Two modes:
 *  - dry-run (preview): reads the inbox (read-only) and shows what Aaliyah WOULD
 *    draft — no Gmail draft is created, nothing is persisted. Safe first pass.
 *  - live: routes each message through the verified runInboundDraft flow with a
 *    REAL access token and the REAL Gmail draft writer — the same path the local
 *    runtime certification exercised, which cannot send.
 */

export type DraftInboxOptions = { limit: number; query: string; dryRun: boolean };

function preview(body: string, maxLines = 8, maxChars = 500): string {
  const text = body.split(/\r?\n/).slice(0, maxLines).join("\n").trim();
  return text.length > maxChars ? `${text.slice(0, maxChars)}…` : text;
}

export async function runDraftInbox(opts: DraftInboxOptions): Promise<void> {
  const cfg = loadLocalEnv();

  const conn = readConnection();
  if (!conn) {
    throw new Error('No connected mailbox. Run "connect" first.');
  }

  const pool = createMailDbPool();
  await runMailMigrations(pool);
  const state = createPostgresMailState(pool);
  const config = loadGoogleConfig();
  const http = createGoogleOAuthHttp({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
  });
  const lifecycle = createCredentialLifecycle({ state, kms: config.kms, http });
  const scope = { tenantId: conn.tenantId, workspaceId: conn.workspaceId };

  // The generator used in BOTH modes — model-assisted when a key is present,
  // deterministic otherwise. Chosen once so preview and live drafts match.
  const generator: DraftGenerator = cfg.hasAnthropicKey
    ? createAnthropicDraftGenerator()
    : deterministicDraftGenerator;

  // Restore points for the live-path seams so we leave global state clean.
  const savedGenerator = inboundDraftInternals.generator;
  const savedResolve = inboundDraftInternals.resolveAccessToken;

  try {
    let accessToken: string;
    try {
      accessToken = await lifecycle.getFreshAccessToken(conn.connectionId, scope);
    } catch (error) {
      if (error instanceof ReauthRequiredError || error instanceof CredentialRevokedError) {
        throw new Error('Your Google authorization is no longer valid. Run "connect" again.');
      }
      throw error;
    }

    console.log(`Mailbox:        ${conn.email}`);
    console.log(`Mode:           ${opts.dryRun ? "DRY-RUN (preview only — nothing saved)" : "live (drafts saved to Gmail)"}`);
    console.log(`Draft quality:  ${cfg.hasAnthropicKey ? "model-assisted (Anthropic)" : "deterministic (no ANTHROPIC_API_KEY)"}`);
    console.log(`Scanning up to ${opts.limit} threads matching "${opts.query}"…\n`);

    const adapter = new GoogleMailAdapter({ resolveAccessToken: () => accessToken });
    const threads = await adapter.listThreads({
      connectionId: conn.connectionId,
      limit: opts.limit,
      query: opts.query,
    });

    // Live path only: hand the verified flow a real token and the chosen
    // generator. createDraft stays the real default; there is no send seam.
    if (!opts.dryRun) {
      inboundDraftInternals.resolveAccessToken = () => accessToken;
      inboundDraftInternals.generator = generator;
    }

    let drafted = 0;
    let skipped = 0;
    let failed = 0;

    for (const thread of threads) {
      const email = await readLatestInbound(accessToken, thread.threadId, conn.email);
      if (!email) {
        skipped += 1;
        console.log(`• (${thread.threadId.slice(0, 10)}) no inbound message to reply to — skipped`);
        continue;
      }

      try {
        if (opts.dryRun) {
          const analysis = analyzeInbound(email);
          if (!analysis.shouldDraft) {
            skipped += 1;
            console.log(`• Skipped (${analysis.reason}) — from ${email.fromEmail}`);
            continue;
          }
          const draft = await generator({ email, replyType: analysis.replyType });
          drafted += 1;
          console.log(`── WOULD DRAFT ──────────────────────────────`);
          console.log(`From:    ${email.fromEmail}`);
          console.log(`Subject: ${email.subject || "(no subject)"}`);
          console.log(`Reply (${draft.replyType}, confidence ${draft.confidence}):`);
          console.log(preview(draft.body).replace(/^/gm, "    "));
          console.log("");
          continue;
        }

        const result = await runInboundDraft({
          tenantId: conn.tenantId,
          workspaceId: conn.workspaceId,
          userId: conn.userId,
          email,
        });
        if (result.status === "awaiting_approval") {
          drafted += 1;
          console.log(`✅ Draft saved — from ${email.fromEmail} · "${email.subject || "(no subject)"}"`);
        } else {
          skipped += 1;
          console.log(`• Skipped (${result.reason ?? result.status}) — from ${email.fromEmail}`);
        }
      } catch (error) {
        failed += 1;
        const detail = error instanceof Error ? error.message : "unknown error";
        console.log(`⚠️  Failed on "${email.subject || "(no subject)"}": ${detail}`);
      }
    }

    if (opts.dryRun) {
      console.log(
        `\nDry-run complete. ${drafted} reply(ies) previewed, ${skipped} skipped, ${failed} failed. Nothing was created or sent.`,
      );
      console.log('Run without --dry-run to save the ones you want to Gmail Drafts.');
    } else {
      console.log(
        `\nDone. ${drafted} draft(s) saved to Gmail, ${skipped} skipped, ${failed} failed. Nothing was sent.`,
      );
      if (drafted > 0) {
        console.log("Review them in Gmail → Drafts. Edit and send the ones you like.");
      }
    }
  } finally {
    inboundDraftInternals.generator = savedGenerator;
    inboundDraftInternals.resolveAccessToken = savedResolve;
    await pool.end();
  }
}
