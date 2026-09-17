import type { CanonicalAliasIdentity, Wave1SubjectBoundEvidence } from "@aaliyah/contracts/v1";

import {
  aliasAssignmentCommitment,
  aliasAssignmentDigest,
} from "../../src/application/memory/wave1AliasRegistry";
import { createLocalTestPiiKeyProvider } from "../../src/crypto/memoryPiiKeys";

/**
 * ONE LOCAL TEST PII KEY PROVIDER PER TEST PROCESS.
 *
 * The issuer computing an alias authorization and the store verifying it must
 * share key material, exactly as a production issuer and store would share a
 * KMS. Each test FILE runs in its own process, so this is one provider per
 * file, never shared with a production path (it refuses NODE_ENV=production).
 */
export const TEST_PII_KEYS = createLocalTestPiiKeyProvider({
  rootKey: Buffer.alloc(32, 0x5a),
});

/** The authorization digest an issuer computes for an alias assignment. */
export async function testAliasAssignmentDigest(input: {
  record: unknown;
  alias: CanonicalAliasIdentity;
  evidence: Wave1SubjectBoundEvidence;
  scope: { tenantId: string; workspaceId: string };
}): Promise<string> {
  const aliasCommitment = await aliasAssignmentCommitment({
    piiKeys: TEST_PII_KEYS,
    scope: input.scope,
    alias: input.alias,
  });
  return aliasAssignmentDigest({
    record: input.record,
    aliasCommitment,
    evidence: input.evidence,
  });
}
