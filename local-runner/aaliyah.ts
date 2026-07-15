import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { resolveConfiguredModels, verifyModels } from "../src/application/executive/modelResolution";

import { loadLocalEnv, readConnection } from "./env";
import { runConnect } from "./connect";
import { runDraftInbox } from "./draftInbox";
import { runInitProfile } from "./initProfile";
import { listAccountModels } from "./eaRouters";

/* eslint-disable no-console */

/**
 * Aaliyah local personal runner — a tiny CLI to test Aaliyah against one real
 * mailbox on this machine, with no hosted infrastructure. It orchestrates the
 * verified core; it never adds a way to send mail.
 *
 *   connect        Link your Gmail (one-time browser approval)
 *   draft-inbox    Draft replies for recent inbox mail (saved to Gmail, never sent)
 *   status         Show connection + local environment health
 */

function parseFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

async function runStatus(): Promise<void> {
  const cfg = loadLocalEnv();
  console.log("Aaliyah local runner — status\n");
  console.log(`Database URL:    ${cfg.databaseUrl}`);
  console.log(`Redirect URI:    ${cfg.redirectUri}`);
  console.log(`Anthropic key:   ${cfg.hasAnthropicKey ? "present (model-assisted drafts)" : "absent (deterministic drafts)"}`);

  if (cfg.hasAnthropicKey) {
    const tiers = resolveConfiguredModels(process.env);
    try {
      const v = await verifyModels(tiers, listAccountModels);
      console.log(
        v.ok
          ? `Models:          triage=${tiers.triage}, draft=${tiers.draft} — verified ✅`
          : `Models:          MISSING ${v.missing.join(", ")} — those stages will fail degraded ❌`,
      );
    } catch (error) {
      console.log(`Models:          could not verify (${error instanceof Error ? error.message : "unknown"})`);
    }
  } else {
    console.log("Models:          no Anthropic key — EA drafting will be review-only (degraded)");
  }

  const pool = createMailDbPool();
  try {
    await runMailMigrations(pool);
    await pool.query("SELECT 1");
    console.log("Postgres:        reachable, migrations applied ✅");
  } catch (error) {
    console.log(`Postgres:        UNREACHABLE ❌ — ${error instanceof Error ? error.message : "unknown"}`);
    console.log("                 Start it with: docker start aaliyah-b4-pg");
  } finally {
    await pool.end();
  }

  const conn = readConnection();
  console.log(
    conn
      ? `Connected inbox:  ${conn.email} (since ${conn.connectedAt})`
      : 'Connected inbox:  none — run "connect" first',
  );
}

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;

  switch (command) {
    case "connect":
      await runConnect();
      break;
    case "draft-inbox": {
      const limit = Number(parseFlag(rest, "limit") ?? "8");
      // Default excludes Promotions/Social so the first real pass targets actual
      // correspondence, not marketing mail.
      const query = parseFlag(rest, "query") ?? "in:inbox -category:promotions -category:social";
      const dryRun = rest.includes("--dry-run");
      await runDraftInbox({
        limit: Number.isFinite(limit) && limit > 0 ? limit : 8,
        query,
        dryRun,
      });
      break;
    }
    case "status":
      await runStatus();
      break;
    case "init-profile":
      runInitProfile();
      break;
    default:
      console.log(
        [
          "Aaliyah local runner",
          "",
          "Usage:",
          "  connect                                      Link your Gmail (one-time browser approval)",
          "  draft-inbox [--limit N] [--query Q] [--dry-run]   Draft replies for recent inbox mail (never sends)",
          "                                               --dry-run previews only; creates nothing",
          "  init-profile                                 Create the editable CEO profile (chmod 600)",
          "  status                                       Show connection + environment health",
        ].join("\n"),
      );
      process.exitCode = command ? 1 : 0;
  }
}

main().then(
  () => {
    // Some transports keep the event loop alive briefly; exit deterministically.
    process.exit(process.exitCode ?? 0);
  },
  (error: unknown) => {
    console.error(`\n${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  },
);
