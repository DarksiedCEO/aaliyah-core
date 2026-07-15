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
import { runEaPipeline, type EaOutcome } from "../src/application/executive/eaPipeline";
import { resolveConfiguredModels } from "../src/application/executive/modelResolution";
import { createGmailDraft } from "../src/integrations/gmail/createDraft";

import { readLatestInbound } from "./gmailReader";
import { loadCeoProfile } from "./ceoProfileFile";
import { buildEaRouters } from "./eaRouters";
import { loadLocalEnv, readConnection } from "./env";

/* eslint-disable no-console */

/**
 * `draft-inbox` — for each recent inbox thread, run the Executive Assistant
 * pipeline (deterministic triage → authority policy → model-assisted draft)
 * and, when the pipeline authorizes it, save a reply draft to Gmail for the
 * operator to review. NEVER sends.
 *
 * Two modes:
 *  - dry-run (preview): reads the inbox (read-only) and shows what Aaliyah WOULD
 *    draft — no Gmail draft is created, nothing is persisted. Safe first pass.
 *  - live: the same pipeline decision, but a drafted reply is saved as a real
 *    Gmail draft via the verified createGmailDraft writer. There is no send seam.
 */

export type DraftInboxOptions = { limit: number; query: string; dryRun: boolean };

function previewBody(body: string, maxLines = 8): string {
  return body.split(/\r?\n/).slice(0, maxLines).join("\n").replace(/^/gm, "    ");
}

function buildRawReply(draft: NonNullable<EaOutcome["draft"]>, toEmail: string, inReplyTo: string): string {
  return [
    `To: ${toEmail}`,
    `Subject: ${draft.subject}`,
    `In-Reply-To: ${inReplyTo}`,
    `References: ${inReplyTo}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    draft.body,
  ].join("\r\n");
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
    console.log(`Draft quality:  ${cfg.hasAnthropicKey ? "model-assisted (Anthropic)" : "no ANTHROPIC_API_KEY — drafting stages will be review-only (degraded)"}`);
    console.log(`Scanning up to ${opts.limit} threads matching "${opts.query}"…\n`);

    const adapter = new GoogleMailAdapter({ resolveAccessToken: () => accessToken });
    const threads = await adapter.listThreads({
      connectionId: conn.connectionId,
      limit: opts.limit,
      query: opts.query,
    });

    const profile = loadCeoProfile(); // fail-closed on bad perms / missing
    const tiers = resolveConfiguredModels(process.env);
    const { triageRouter, draftRouter } = buildEaRouters(tiers);

    let drafted = 0;
    let skipped = 0;
    let escalated = 0;
    let review = 0;
    let failed = 0;

    for (const thread of threads) {
      const read = await readLatestInbound(accessToken, thread.threadId, conn.email);
      if (!read) {
        skipped += 1;
        console.log(`• (${thread.threadId.slice(0, 10)}) no inbound message to reply to — skipped`);
        continue;
      }
      const { email, signals } = read;

      let out: EaOutcome;
      try {
        out = await runEaPipeline({ triageRouter, draftRouter, profile }, { email, signals });
      } catch (error) {
        failed += 1;
        const detail = error instanceof Error ? error.message : "unknown error";
        console.log(`⚠️  Failed on "${email.subject || "(no subject)"}": ${detail}`);
        continue;
      }

      const head = `${out.category} · risk=${out.risk} · conf=${out.confidence.toFixed(2)} · ${out.action}`;

      if (out.action === "draft" && out.draft) {
        if (opts.dryRun) {
          drafted += 1;
          console.log(`── WOULD DRAFT ── ${head}${out.cautionMarker ? " · ⚠ CAUTION" : ""}`);
          console.log(`From:    ${email.fromEmail}`);
          console.log(`Subject: ${email.subject || "(no subject)"}`);
          console.log(previewBody(out.draft.body));
          console.log("");
        } else {
          const raw = buildRawReply(out.draft, email.fromEmail, email.messageId);
          await createGmailDraft(raw, accessToken);
          drafted += 1;
          console.log(`✅ Draft saved ── ${head}${out.cautionMarker ? " · ⚠ CAUTION" : ""} — from ${email.fromEmail}`);
        }
      } else if (out.action === "no_action") {
        skipped += 1;
        console.log(`• Skipped ── ${head} — from ${email.fromEmail}`);
      } else if (out.action === "escalate") {
        escalated += 1;
        console.log(`🚩 ESCALATE (review yourself, no draft) ── ${head} — from ${email.fromEmail} · ${out.reason}`);
      } else {
        review += 1;
        console.log(`👀 Review-only${out.degraded ? " (degraded)" : ""} ── ${head} — from ${email.fromEmail} · ${out.reason}`);
      }
    }

    if (opts.dryRun) {
      console.log(
        `\nDry-run complete. ${drafted} reply(ies) previewed, ${skipped} skipped, ${escalated} escalated, ${review} review-only, ${failed} failed. Nothing was created or sent.`,
      );
      console.log('Run without --dry-run to save the ones you want to Gmail Drafts.');
    } else {
      console.log(
        `\nDone. ${drafted} draft(s) saved to Gmail, ${skipped} skipped, ${escalated} escalated, ${review} review-only, ${failed} failed. Nothing was sent.`,
      );
      if (drafted > 0) {
        console.log("Review them in Gmail → Drafts. Edit and send the ones you like.");
      }
    }
  } finally {
    await pool.end();
  }
}
