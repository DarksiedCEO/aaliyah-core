import { z } from "zod";

export const CEO_PROFILE_SCHEMA_VERSION = 1 as const;

export const CeoProfileSchema = z.object({
  schemaVersion: z.literal(CEO_PROFILE_SCHEMA_VERSION),
  name: z.string().min(1),
  title: z.string().min(1),
  companies: z.array(z.string().min(1)).min(1),
  priorities: z.array(z.string().min(1)).default([]),
  tone: z.string().min(1),
  greeting: z.string().min(1),
  signoff: z.string().min(1),
  neverPromise: z.array(z.string().min(1)).default([]),
  confidentialTopics: z.array(z.string().min(1)).default([]),
  vipContacts: z.array(z.string().min(1)).default([]),
  approvedFacts: z.array(z.string().min(1)).default([]),
});

export type CeoProfile = z.infer<typeof CeoProfileSchema>;

/** Compose the CEO context block injected into triage/draft system prompts.
 * Contains only profile-declared facts — never invents. */
export function buildCeoContext(profile: CeoProfile): string {
  const lines = [
    `You are the executive assistant to ${profile.name}, ${profile.title} of ${profile.companies.join(", ")}.`,
    `Current priorities: ${profile.priorities.join("; ") || "(none stated)"}.`,
    `Voice: ${profile.tone}. Open with "${profile.greeting}"; close with "${profile.signoff.replace(/\n/g, " ")}".`,
  ];
  if (profile.approvedFacts.length > 0) {
    lines.push(`Approved facts you may state: ${profile.approvedFacts.join("; ")}.`);
  }
  lines.push(
    `You must never promise, commit, or imply any of: ${profile.neverPromise.join(", ")}. ` +
      `Never disclose confidential topics: ${profile.confidentialTopics.join(", ") || "(none)"}. ` +
      `Never invent facts, prices, dates, or commitments. When specifics are unknown, keep the reply open.`,
  );
  return lines.join("\n");
}
