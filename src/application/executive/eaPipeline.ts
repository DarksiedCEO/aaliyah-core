import type { InboundEmail, ModelRouterRequest, NormalizedModelResponse } from "@aaliyah/contracts/v1";
import type { CeoProfile } from "./ceoProfile";
import { stage0SystemFilter, classifyInbound, type MailSignals, type TriageCategory, type RiskLevel } from "./triage";
import { decideAuthority, type EaAction } from "./authorityPolicy";
import { generateExecutiveDraft, DraftDegradedError, type ExecutiveDraft } from "./executiveDraft";

type MinimalRouter = { generate(req: ModelRouterRequest): Promise<NormalizedModelResponse> };

export type EaDeps = { triageRouter: MinimalRouter; draftRouter: MinimalRouter; profile: CeoProfile };
export type EaInput = { email: InboundEmail; signals: MailSignals };

export type EaOutcome = {
  category: TriageCategory;
  risk: RiskLevel;
  confidence: number;
  action: EaAction;
  reason: string;
  degraded: boolean;
  cautionMarker: boolean;
  draft?: ExecutiveDraft;
};

export async function runEaPipeline(deps: EaDeps, input: EaInput): Promise<EaOutcome> {
  // Stage 0 — free deterministic filter.
  const stage0 = stage0SystemFilter(input.email, input.signals);
  const triage = stage0 ?? (await classifyInbound(deps.triageRouter, input.email));
  const degradedTriage = triage.degraded === true;

  // Stage 2 — deterministic authority.
  const decision = decideAuthority(triage);
  const base: EaOutcome = {
    category: triage.category,
    risk: triage.risk,
    confidence: triage.confidence,
    action: decision.action,
    reason: decision.reason,
    degraded: degradedTriage,
    cautionMarker: decision.cautionMarker,
  };
  if (degradedTriage) return { ...base, action: "review_only", reason: triage.reason };

  // Stage 3 — draft only when permitted.
  if (decision.draftable && (triage.category === "real_lead" || triage.category === "vendor_solicitation")) {
    try {
      const draft = await generateExecutiveDraft(deps.draftRouter, deps.profile, triage.category, input.email);
      return { ...base, action: "draft", draft };
    } catch (error) {
      if (error instanceof DraftDegradedError) {
        return { ...base, action: "review_only", degraded: true, reason: "drafting model unavailable — review-only" };
      }
      throw error;
    }
  }
  return base;
}
