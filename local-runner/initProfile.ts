import fs from "node:fs";
import path from "node:path";
import { CEO_PROFILE_PATH } from "./ceoProfileFile";
import { CEO_PROFILE_SCHEMA_VERSION } from "../src/application/executive/ceoProfile";

/* eslint-disable no-console */
const TEMPLATE = {
  schemaVersion: CEO_PROFILE_SCHEMA_VERSION,
  name: "Andre Love",
  title: "CEO",
  companies: ["Z Best Media"],
  priorities: ["leads", "clients", "partnerships", "protecting time"],
  tone: "direct, warm, concise",
  greeting: "Hi",
  signoff: "Best,\nAndre",
  neverPromise: ["pricing", "deadlines", "meetings", "contracts", "refunds", "legal positions"],
  confidentialTopics: ["internal finances", "unreleased plans"],
  vipContacts: [],
  approvedFacts: [],
};

export function runInitProfile(): void {
  if (fs.existsSync(CEO_PROFILE_PATH)) {
    console.log(`CEO profile already exists at ${CEO_PROFILE_PATH} — leaving it untouched.`);
    return;
  }
  fs.mkdirSync(path.dirname(CEO_PROFILE_PATH), { recursive: true });
  fs.writeFileSync(CEO_PROFILE_PATH, JSON.stringify(TEMPLATE, null, 2), { mode: 0o600 });
  fs.chmodSync(CEO_PROFILE_PATH, 0o600);
  console.log(`✅ Wrote CEO profile template to ${CEO_PROFILE_PATH} (chmod 600).`);
  console.log("Edit it to sharpen tone, priorities, and the never-promise list, then run draft-inbox.");
}
