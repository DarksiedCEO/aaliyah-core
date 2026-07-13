import Anthropic from "@anthropic-ai/sdk";
import type { InboundGeneratedDraft } from "@aaliyah/contracts/v1";

import type { DraftGenerator } from "../src/application/inbound/generateInboundDraft";

/**
 * Optional Anthropic-backed draft generator for the local runner.
 *
 * It plugs into the SAME DraftGenerator seam the deterministic default uses, so
 * the inbound flow, safety contract, and decision trace are unchanged — only the
 * words in the (still human-approved, never-sent) draft get better. Used only
 * when an API key is present; otherwise the runner keeps the deterministic
 * generator.
 *
 * Cost note: defaults to Haiku to protect a small credit balance; override with
 * AALIYAH_ANTHROPIC_MODEL for higher quality.
 */

const SYSTEM_PROMPT = [
  "You are drafting a reply email on behalf of the mailbox owner.",
  "Write only the body of the reply — no subject line, no 'Subject:' prefix, no surrounding quotes, no commentary.",
  "Be concise, warm, and professional. Match the sender's register.",
  "Do not invent facts, commitments, prices, dates, or availability. When specifics are unknown, keep the reply open (e.g. offer to follow up) rather than fabricating them.",
  "This draft will be reviewed and edited by a human before anything is ever sent.",
].join("\n");

function replySubject(subject: string): string {
  const trimmed = subject.trim();
  if (trimmed.length === 0) return "Re: your message";
  return /^\s*re:/i.test(trimmed) ? trimmed : `Re: ${trimmed}`;
}

export function createAnthropicDraftGenerator(options?: {
  buildClient?: () => Anthropic;
  model?: string;
}): DraftGenerator {
  const model = options?.model ?? process.env.AALIYAH_ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001";
  const buildClient =
    options?.buildClient ?? (() => new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));

  return async ({ email, replyType }): Promise<InboundGeneratedDraft> => {
    const client = buildClient();
    const userMessage = [
      `From: ${email.fromEmail}`,
      `Subject: ${email.subject || "(no subject)"}`,
      "",
      "Message:",
      email.body,
      "",
      "Draft a reply.",
    ].join("\n");

    const message = await client.messages.create({
      model,
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: userMessage }],
    });

    if (message.stop_reason === "refusal") {
      throw new Error("anthropic: draft request refused by safety policy");
    }

    const body = message.content
      .filter((block): block is Anthropic.TextBlock => block.type === "text")
      .map((block) => block.text)
      .join("")
      .trim();

    if (body.length === 0) {
      throw new Error("anthropic: empty draft body");
    }

    return {
      subject: replySubject(email.subject),
      body,
      replyType,
      // Human approval is unconditional for inbound drafts regardless; this is a
      // model-assisted first pass, not a high-autonomy signal.
      confidence: 55,
      generatorMode: `anthropic:${model}`,
    };
  };
}
