import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const coreRoot = path.resolve(__dirname, "..");
const contractsRoot = path.resolve(coreRoot, "../aaliyah-contracts");
const targetArtifact = "dist/src/v1/postcondition-verification.js";

test("Contracts provenance rejects equally stale sibling and installed artifacts", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "contracts-provenance-"));
  const fixtureCore = path.join(root, "aaliyah-core");
  const fixtureContracts = path.join(root, "aaliyah-contracts");
  try {
    fs.mkdirSync(path.join(fixtureCore, "scripts"), { recursive: true });
    fs.copyFileSync(
      path.join(coreRoot, "scripts/contracts-provenance.sh"),
      path.join(fixtureCore, "scripts/contracts-provenance.sh"),
    );

    const clone = spawnSync(
      "git",
      ["clone", "--quiet", "--local", "--no-hardlinks", contractsRoot, fixtureContracts],
      { encoding: "utf8" },
    );
    assert.equal(clone.status, 0, `${clone.stdout}${clone.stderr}`);
    fs.cpSync(
      path.join(contractsRoot, "node_modules"),
      path.join(fixtureContracts, "node_modules"),
      { recursive: true },
    );
    fs.cpSync(
      path.join(contractsRoot, "dist"),
      path.join(fixtureContracts, "dist"),
      { recursive: true },
    );

    const installedContracts = path.join(
      fixtureCore,
      "node_modules/@aaliyah/contracts",
    );
    fs.mkdirSync(path.dirname(installedContracts), { recursive: true });
    fs.cpSync(
      path.join(coreRoot, "node_modules/@aaliyah/contracts"),
      installedContracts,
      { recursive: true, dereference: true },
    );
    fs.cpSync(
      path.join(coreRoot, "node_modules/zod"),
      path.join(fixtureCore, "node_modules/zod"),
      { recursive: true, dereference: true },
    );

    const mutation = "\n// stale-both mutation\n";
    fs.appendFileSync(path.join(fixtureContracts, targetArtifact), mutation);
    fs.appendFileSync(path.join(installedContracts, targetArtifact), mutation);

    const result = spawnSync(
      "bash",
      ["scripts/contracts-provenance.sh"],
      { cwd: fixtureCore, encoding: "utf8" },
    );
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(
      result.stderr,
      /installed Contracts artifacts do not match isolated exact-SHA build/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
