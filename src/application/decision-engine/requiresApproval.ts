import type { RiskTier } from "@aaliyah/contracts/v1";

export function requiresApproval(
  riskTier: RiskTier,
  score: number,
  margin: number,
): boolean {
  if (riskTier === "A4_IRREVERSIBLE") {
    return true;
  }

  if (riskTier === "A2_WRITE_APPROVED") {
    return true;
  }

  if (riskTier === "A3_LOW_RISK_AUTO" && (score < 85 || margin < 10)) {
    return true;
  }

  return false;
}
