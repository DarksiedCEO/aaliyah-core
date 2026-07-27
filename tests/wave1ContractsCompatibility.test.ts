import assert from "node:assert/strict";
import test from "node:test";

import {
  AALIYAH_EXECUTIVE_COMMUNICATIONS_CONTRACT_VERSION,
  AuditLifecycleEventSchema,
  ExecutiveQualityDraftSchema,
  ProviderCapabilitiesV2Schema,
  Wave1BindingSchema,
  verifyExecutiveQualityDraft,
  verifyLifecycleEvent,
} from "@aaliyah/contracts/v1";

test("Core resolves the exact public Wave 1 Contracts surface", () => {
  assert.equal(
    AALIYAH_EXECUTIVE_COMMUNICATIONS_CONTRACT_VERSION,
    "aaliyah.executive-communications/wave1",
  );
  for (const contract of [
    Wave1BindingSchema,
    AuditLifecycleEventSchema,
    ExecutiveQualityDraftSchema,
    ProviderCapabilitiesV2Schema,
  ]) {
    assert.equal(typeof contract.parse, "function");
  }
  assert.equal(typeof verifyExecutiveQualityDraft, "function");
  assert.equal(typeof verifyLifecycleEvent, "function");
});
