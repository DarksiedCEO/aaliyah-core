import type { StyleProfile } from "@aaliyah/contracts/v1";

import type { AaliyahModelRouter } from "../../model-router/AaliyahModelRouter";
import {
  styleDirectives,
  enforceForbiddenPhrases,
} from "../style/styleDirectives";
import type { DraftGenerator } from "./generateInboundDraft";

function replySubject(subject: string): string {
  const trimmed = subject.trim();
  if (trimmed.length === 0) {
    return "Re: your message";
  }
  return /^\s*re:/i.test(trimmed) ? trimmed : `Re: ${trimmed}`;
}

const SYSTEM_PROMPT = [
  "You are Aaliyah, drafting a reply to an inbound email on the user's behalf.",
  "Write only the reply body — no subject line, no preamble, no sign-off block beyond a simple closing.",
  "Be concise, professional, and do not invent commitments, prices, or facts not present in the message.",
].join(" ");

/**
 * Block 3 integration point: adapts the AaliyahModelRouter to the Block 2
 * DraftGenerator seam. Wiring this in is opt-in (set
 * `inboundDraftInternals.generator = routerDraftGenerator(router)`), so the
 * inbound flow itself is unchanged — exactly what the seam was built for.
 */
export function routerDraftGenerator(
  router: AaliyahModelRouter,
  options?: { style?: StyleProfile },
): DraftGenerator {
  const style = options?.style;
  const system = style
    ? `${SYSTEM_PROMPT} ${styleDirectives(style)}`
    : SYSTEM_PROMPT;

  return async ({ email, replyType }) => {
    const prompt = [
      `From: ${email.fromEmail}`,
      `Subject: ${email.subject}`,
      "",
      email.body,
      "",
      "Draft a reply to the message above.",
    ].join("\n");

    const result = await router.generate({ system, prompt, maxOutputTokens: 512 });

    const raw =
      result.text.trim().length > 0 ? result.text.trim() : "Thank you for your message.";
    const body = style ? enforceForbiddenPhrases(raw, style) : raw;

    return {
      subject: replySubject(email.subject),
      body,
      replyType,
      confidence: 60,
      generatorMode: `router:${result.provider}`,
    };
  };
}
