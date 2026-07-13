import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";

import { loadLocalEnv, readConnection } from "./env";
import { runConnect } from "./connect";
import { runDraftInbox } from "./draftInbox";

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
    default:
      console.log(
        [
          "Aaliyah local runner",
          "",
          "Usage:",
          "  connect                                      Link your Gmail (one-time browser approval)",
          "  draft-inbox [--limit N] [--query Q] [--dry-run]   Draft replies for recent inbox mail (never sends)",
          "                                               --dry-run previews only; creates nothing",
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
