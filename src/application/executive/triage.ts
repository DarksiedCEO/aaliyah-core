import type { InboundEmail } from "@aaliyah/contracts/v1";

export type TriageCategory =
  | "real_lead"
  | "vendor_solicitation"
  | "notification_system"
  | "sensitive_escalation"
  | "unknown";

export type RiskLevel = "green" | "yellow" | "red";

export type TriageResult = {
  category: TriageCategory;
  risk: RiskLevel;
  reason: string;
  confidence: number; // 0..1
};

export type MailSignals = { listUnsubscribe: boolean; precedenceBulk: boolean };

const SYSTEM_SENDER = [
  /no-?reply@/i,
  /do-?not-?reply@/i,
  /mailer-daemon@/i,
  /postmaster@/i,
  /notifications?@/i,
  /@mail\.instagram\.com$/i,
];

const DIGEST_SIGNAL = /\b(digest|newsletter|weekly|your stories|recap|unsubscribe)\b/i;

/** High-confidence deterministic system filter. Returns a notification_system
 * result ONLY on strong signals; otherwise null (send to Stage 1). List-Unsubscribe
 * ALONE is never sufficient — legitimate correspondence carries bulk headers too. */
export function stage0SystemFilter(email: InboundEmail, signals: MailSignals): TriageResult | null {
  const from = email.fromEmail.toLowerCase();
  const knownSystem = SYSTEM_SENDER.some((re) => re.test(from));
  const bulk = signals.listUnsubscribe || signals.precedenceBulk;
  const digestish = DIGEST_SIGNAL.test(email.subject) || DIGEST_SIGNAL.test(from);

  if (knownSystem || (bulk && digestish)) {
    return {
      category: "notification_system",
      risk: "green",
      reason: knownSystem ? "known system/no-reply sender" : "bulk headers with digest/newsletter signal",
      confidence: 0.99,
    };
  }
  return null;
}
