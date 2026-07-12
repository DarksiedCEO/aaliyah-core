import assert from "node:assert/strict";
import test from "node:test";

import { googleCapability, loadGoogleConfig } from "../src/mail/google/googleConfig";

const REDIRECT = "https://app.example/oauth/google/callback";
const GOOGLE_BASE = {
  GOOGLE_CLIENT_ID: "a",
  GOOGLE_CLIENT_SECRET: "b",
  GOOGLE_OAUTH_REDIRECT_URI: REDIRECT,
};
const LOCAL_KMS = {
  MAIL_CREDENTIAL_ENCRYPTION_KEY: Buffer.alloc(32).toString("base64"),
  MAIL_CREDENTIAL_KEY_VERSION: "v1",
};
const GCP_KMS = {
  GCP_KMS_PROJECT_ID: "aaliyah-prod",
  GCP_KMS_LOCATION: "us-central1",
  GCP_KMS_KEY_RING: "mail-credentials",
  GCP_KMS_CRYPTO_KEY: "refresh-token-key",
};

function env(vars: Record<string, string>): NodeJS.ProcessEnv {
  return vars as unknown as NodeJS.ProcessEnv;
}

test("default (unset AALIYAH_KMS_PROVIDER) uses the local master KMS and requires its vars", () => {
  const missingLocal = env({ ...GOOGLE_BASE });
  assert.equal(googleCapability(missingLocal).available, false);
  assert.throws(() => loadGoogleConfig(missingLocal), /not configured/);

  const complete = env({ ...GOOGLE_BASE, ...LOCAL_KMS });
  assert.equal(googleCapability(complete).available, true);
  const config = loadGoogleConfig(complete);
  assert.equal(config.kms.keyId, "v1");
});

test("AALIYAH_KMS_PROVIDER=local behaves identically to the default", () => {
  const complete = env({ ...GOOGLE_BASE, ...LOCAL_KMS, AALIYAH_KMS_PROVIDER: "local" });
  assert.equal(googleCapability(complete).available, true);
  assert.equal(loadGoogleConfig(complete).kms.keyId, "v1");
});

test("AALIYAH_KMS_PROVIDER=gcp requires GCP_KMS_* vars, not the local master vars", () => {
  const missingGcp = env({ ...GOOGLE_BASE, AALIYAH_KMS_PROVIDER: "gcp" });
  assert.equal(googleCapability(missingGcp).available, false);
  assert.throws(() => loadGoogleConfig(missingGcp), /not configured/);

  // Local master vars alone are NOT sufficient once gcp is selected.
  const onlyLocalVars = env({ ...GOOGLE_BASE, ...LOCAL_KMS, AALIYAH_KMS_PROVIDER: "gcp" });
  assert.equal(googleCapability(onlyLocalVars).available, false);

  const complete = env({ ...GOOGLE_BASE, ...GCP_KMS, AALIYAH_KMS_PROVIDER: "gcp" });
  assert.equal(googleCapability(complete).available, true);
  const config = loadGoogleConfig(complete);
  assert.equal(
    config.kms.keyId,
    "projects/aaliyah-prod/locations/us-central1/keyRings/mail-credentials/cryptoKeys/refresh-token-key",
  );
});

test("an unrecognized AALIYAH_KMS_PROVIDER value fails closed rather than silently defaulting", () => {
  const bogus = env({ ...GOOGLE_BASE, ...LOCAL_KMS, AALIYAH_KMS_PROVIDER: "azure" });
  assert.equal(googleCapability(bogus).available, false);
  assert.throws(() => loadGoogleConfig(bogus), /unknown AALIYAH_KMS_PROVIDER/);
});
