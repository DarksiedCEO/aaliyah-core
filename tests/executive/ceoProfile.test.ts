import assert from "node:assert/strict";
import test from "node:test";
import { CeoProfileSchema, buildCeoContext, CEO_PROFILE_SCHEMA_VERSION } from "../../src/application/executive/ceoProfile";

const VALID = {
  schemaVersion: 1,
  name: "Andre Love",
  title: "CEO",
  companies: ["Z Best Media"],
  priorities: ["leads", "clients", "partnerships", "protecting time"],
  tone: "direct, warm, concise",
  greeting: "Hi",
  signoff: "Best,\nAndre",
  neverPromise: ["pricing", "deadlines", "meetings", "contracts", "refunds", "legal positions"],
  confidentialTopics: ["internal finances"],
};

test("valid profile parses and exposes the current schema version", () => {
  const p = CeoProfileSchema.parse(VALID);
  assert.equal(p.schemaVersion, CEO_PROFILE_SCHEMA_VERSION);
  assert.equal(p.name, "Andre Love");
});

test("wrong schemaVersion is rejected", () => {
  assert.throws(() => CeoProfileSchema.parse({ ...VALID, schemaVersion: 99 }));
});

test("missing required field is rejected", () => {
  const { name, ...rest } = VALID;
  assert.throws(() => CeoProfileSchema.parse(rest));
});

test("buildCeoContext includes identity, priorities, and the never-promise list", () => {
  const ctx = buildCeoContext(CeoProfileSchema.parse(VALID));
  assert.match(ctx, /Andre Love/);
  assert.match(ctx, /Z Best Media/);
  assert.match(ctx, /protecting time/);
  assert.match(ctx, /never promise/i);
  assert.match(ctx, /pricing/);
});
