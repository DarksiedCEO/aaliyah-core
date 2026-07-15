import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadCeoProfileFrom } from "../../local-runner/ceoProfileFile";

const VALID = { schemaVersion: 1, name: "Andre Love", title: "CEO", companies: ["Z Best Media"], priorities: ["leads"], tone: "direct", greeting: "Hi", signoff: "Best", neverPromise: ["pricing"], confidentialTopics: [] };
function tmp(mode: number): string {
  const p = path.join(os.tmpdir(), `ceo-${process.pid}-${mode}.json`);
  fs.writeFileSync(p, JSON.stringify(VALID), { mode });
  fs.chmodSync(p, mode);
  return p;
}

test("loads a valid 0600 profile", () => {
  const p = tmp(0o600);
  const profile = loadCeoProfileFrom(p);
  assert.equal(profile.name, "Andre Love");
  fs.rmSync(p);
});

test("fails closed on group/world-readable file", () => {
  const p = tmp(0o644);
  assert.throws(() => loadCeoProfileFrom(p), /permission/i);
  fs.rmSync(p);
});

test("missing file throws a clear error", () => {
  assert.throws(() => loadCeoProfileFrom("/no/such/ceo.json"), /not found/i);
});
