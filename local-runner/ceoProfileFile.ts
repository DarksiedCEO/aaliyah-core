import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CeoProfileSchema, type CeoProfile } from "../src/application/executive/ceoProfile";

export const CEO_PROFILE_PATH = path.join(os.homedir(), ".aaliyah-local", "ceo-profile.json");

export function loadCeoProfileFrom(filePath: string): CeoProfile {
  if (!fs.existsSync(filePath)) {
    throw new Error(`CEO profile not found at ${filePath}. Run "init-profile" to create one.`);
  }
  const mode = fs.statSync(filePath).mode & 0o777;
  // Fail closed: any group/world bit set is rejected.
  if (mode & 0o077) {
    throw new Error(`CEO profile ${filePath} has insecure permission ${mode.toString(8)}; must be 600. Run: chmod 600 ${filePath}`);
  }
  return CeoProfileSchema.parse(JSON.parse(fs.readFileSync(filePath, "utf8")));
}

export function loadCeoProfile(): CeoProfile {
  return loadCeoProfileFrom(CEO_PROFILE_PATH);
}
