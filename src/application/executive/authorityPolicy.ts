import type { TriageResult } from "./triage";

export type EaAction = "draft" | "no_action" | "escalate" | "review_only";
export type AuthorityDecision = {
  action: EaAction;
  draftable: boolean;
  cautionMarker: boolean;
  reason: string;
};

export const CONFIDENCE_FLOOR = 0.7;

/** Deterministic authority. Risk gates before category; low confidence and RED
 * can only subtract permission, never grant it. The model never decides the action. */
export function decideAuthority(t: TriageResult): AuthorityDecision {
  // 1. RED — hard stop.
  if (t.risk === "red") {
    return { action: "escalate", draftable: false, cautionMarker: false, reason: `red risk: ${t.reason}` };
  }
  // 2. Low confidence — treat as unknown.
  if (t.confidence < CONFIDENCE_FLOOR) {
    return { action: "review_only", draftable: false, cautionMarker: false, reason: `low confidence (${t.confidence})` };
  }
  // 3-4. Category policy (green, or yellow with caution).
  const caution = t.risk === "yellow";
  switch (t.category) {
    case "real_lead":
    case "vendor_solicitation":
      return { action: "draft", draftable: true, cautionMarker: caution, reason: t.reason };
    case "notification_system":
      return { action: "no_action", draftable: false, cautionMarker: false, reason: t.reason };
    case "sensitive_escalation":
      return { action: "escalate", draftable: false, cautionMarker: false, reason: t.reason };
    case "unknown":
    default:
      return { action: "review_only", draftable: false, cautionMarker: false, reason: t.reason };
  }
}
