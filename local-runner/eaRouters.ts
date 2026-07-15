import Anthropic from "@anthropic-ai/sdk";
import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";
import { AnthropicAdapter } from "../src/model-router/adapters/anthropicAdapter";
import type { ModelTiers } from "../src/application/executive/modelResolution";

/**
 * Build the two routers the EA pipeline needs — a fast/cheap triage router and
 * a higher-quality drafting router. Anthropic-only for the pilot: each tier is
 * its own single-adapter router since the adapter's model is fixed at
 * construction time.
 */
export function buildEaRouters(tiers: ModelTiers): {
  triageRouter: AaliyahModelRouter;
  draftRouter: AaliyahModelRouter;
} {
  const triageRouter = new AaliyahModelRouter([new AnthropicAdapter({ model: tiers.triage })]);
  const draftRouter = new AaliyahModelRouter([new AnthropicAdapter({ model: tiers.draft })]);
  return { triageRouter, draftRouter };
}

/** List model ids available to this Anthropic account, for status/verification. */
export async function listAccountModels(): Promise<string[]> {
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const ids: string[] = [];
  for await (const m of client.models.list()) ids.push(m.id);
  return ids;
}
