import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "..");
const manifestName = ".aegis-frozen.sha256";

function createFixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-frozen-test-"));
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true });
  fs.copyFileSync(
    path.join(repositoryRoot, "scripts", "aegis-frozen.sh"),
    path.join(root, "scripts", "aegis-frozen.sh"),
  );
  fs.copyFileSync(
    path.join(repositoryRoot, manifestName),
    path.join(root, manifestName),
  );

  const manifest = fs.readFileSync(path.join(root, manifestName), "utf8");
  const canonicalLines: string[] = [];
  for (const line of manifest.trim().split("\n")) {
    const frozenPath = line.split(/\s+/)[1];
    assert.ok(frozenPath, "manifest entry must contain a path");
    const target = path.join(root, frozenPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(repositoryRoot, frozenPath), target);
    const digest = createHash("sha256")
      .update(fs.readFileSync(target))
      .digest("hex");
    canonicalLines.push(`${digest}  ${frozenPath}`);
  }
  fs.writeFileSync(
    path.join(root, manifestName),
    `${canonicalLines.join("\n")}\n`,
  );
  assert.equal(
    spawnSync("git", ["init", "-q"], { cwd: root }).status,
    0,
  );
  assert.equal(
    spawnSync("git", ["add", "."], { cwd: root }).status,
    0,
  );
  return root;
}

function verify(root: string) {
  return spawnSync("bash", ["scripts/aegis-frozen.sh", "verify"], {
    cwd: root,
    encoding: "utf8",
  });
}

test("canonical frozen manifest verifies", () => {
  const root = createFixture();
  try {
    const result = verify(root);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("frozen verification rejects reordered entries", () => {
  const root = createFixture();
  try {
    const manifestPath = path.join(root, manifestName);
    const lines = fs.readFileSync(manifestPath, "utf8").trim().split("\n");
    fs.writeFileSync(manifestPath, `${lines.reverse().join("\n")}\n`);
    assert.notEqual(verify(root).status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("frozen verification rejects duplicate entries", () => {
  const root = createFixture();
  try {
    const manifestPath = path.join(root, manifestName);
    const manifest = fs.readFileSync(manifestPath, "utf8");
    fs.writeFileSync(manifestPath, `${manifest}${manifest.split("\n")[0]}\n`);
    assert.notEqual(verify(root).status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("frozen verification rejects malformed entries", () => {
  const root = createFixture();
  try {
    const manifestPath = path.join(root, manifestName);
    fs.writeFileSync(manifestPath, "not-a-sha src/services/executeIdempotent.ts\n");
    assert.notEqual(verify(root).status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("frozen verification rejects changed content", () => {
  const root = createFixture();
  try {
    fs.appendFileSync(
      path.join(root, "src/services/executeIdempotent.ts"),
      "\ncontent mutation\n",
    );
    assert.notEqual(verify(root).status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
