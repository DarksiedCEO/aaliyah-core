export type ModelTiers = { triage: string; draft: string };

export const DEFAULT_TIERS: ModelTiers = {
  triage: "claude-haiku-4-5-20251001",
  draft: "claude-sonnet-5",
};

export function resolveConfiguredModels(env: NodeJS.ProcessEnv): ModelTiers {
  return {
    triage: env.AALIYAH_TRIAGE_MODEL ?? DEFAULT_TIERS.triage,
    draft: env.AALIYAH_DRAFT_MODEL ?? DEFAULT_TIERS.draft,
  };
}

/** Verify the configured IDs exist for this account. Never substitutes — a
 * missing tier is reported so the caller fails that stage degraded. */
export async function verifyModels(
  configured: ModelTiers,
  listModels: () => Promise<string[]>,
): Promise<{ ok: boolean; missing: string[]; tiers: ModelTiers }> {
  const available = new Set(await listModels());
  const missing = [configured.triage, configured.draft].filter((m) => !available.has(m));
  return { ok: missing.length === 0, missing, tiers: configured };
}
