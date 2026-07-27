import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const coreRoot = path.resolve(__dirname, "..");
const contractsRoot = path.resolve(coreRoot, "../aaliyah-wave1-contracts");
const targetArtifact = "dist/src/v1/postcondition-verification.js";

test("Contracts provenance rejects stale artifacts and redirected package exports", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "contracts-provenance-"));
  const fixtureCore = path.join(root, "aaliyah-core");
  const fixtureContracts = path.join(root, "aaliyah-wave1-contracts");
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

    fs.copyFileSync(
      path.join(contractsRoot, targetArtifact),
      path.join(fixtureContracts, targetArtifact),
    );
    fs.copyFileSync(
      path.join(contractsRoot, targetArtifact),
      path.join(installedContracts, targetArtifact),
    );
    const manifestPath = path.join(installedContracts, "package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
      exports: Record<string, string>;
    };
    manifest.exports["./v1"] = "./redirected-v1.js";
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    fs.writeFileSync(
      path.join(installedContracts, "redirected-v1.js"),
      [
        "module.exports = {",
        '  POSTCONDITION_VERIFICATION_CONTRACT_VERSION: "aaliyah.postcondition-verification/v1",',
        '  EXECUTIVE_MESSAGING_CONTRACT_VERSION: "aaliyah.executive-messaging/v1",',
        '  AALIYAH_EXECUTIVE_COMMUNICATIONS_CONTRACT_VERSION: "aaliyah.executive-communications/wave1",',
        "};",
        "",
      ].join("\n"),
    );
    const redirected = spawnSync(
      "bash",
      ["scripts/contracts-provenance.sh"],
      { cwd: fixtureCore, encoding: "utf8" },
    );
    assert.notEqual(
      redirected.status,
      0,
      `${redirected.stdout}${redirected.stderr}`,
    );
    assert.match(
      redirected.stderr,
      /installed Contracts package manifest does not match exact SHA/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
