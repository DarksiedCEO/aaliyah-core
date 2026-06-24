import type { StyleProfile } from "@aaliyah/contracts/v1";

const LENGTH_HINT = {
  short: "Keep it short — 2-3 sentences.",
  medium: "Keep it reasonably brief — a short paragraph.",
  long: "A few short paragraphs are acceptable if needed.",
} as const;

const CTA_HINT = {
  none: "Do not add a call to action.",
  soft: "End with a soft, optional next step.",
  direct: "End with a clear, direct call to action.",
} as const;

/**
 * Render a style profile into a drafting directive appended to the generator's
 * system prompt. This shapes wording ONLY — it carries no decision authority.
 */
export function styleDirectives(profile: StyleProfile): string {
  const lines = [
    `Write in a ${profile.tone} tone (${profile.formality} formality).`,
    LENGTH_HINT[profile.lengthPreference],
    CTA_HINT[profile.ctaBehavior],
  ];
  if (profile.greeting) {
    lines.push(`Open with a greeting like "${profile.greeting}".`);
  }
  if (profile.signoff) {
    lines.push(`Close with a sign-off like "${profile.signoff}".`);
  }
  if (profile.forbiddenPhrases.length > 0) {
    lines.push(`Never use these phrases: ${profile.forbiddenPhrases.join("; ")}.`);
  }
  if (profile.customNotes) {
    lines.push(`Additional style notes: ${profile.customNotes}`);
  }
  return lines.join(" ");
}

/**
 * Deterministic safety net: strip any forbidden phrases that slipped through.
 */
export function enforceForbiddenPhrases(body: string, profile: StyleProfile): string {
  let result = body;
  for (const phrase of profile.forbiddenPhrases) {
    if (phrase.trim().length === 0) continue;
    result = result.split(phrase).join("");
  }
  return result.replace(/[ \t]{2,}/g, " ").trim();
}
