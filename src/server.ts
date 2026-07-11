import { createCoreApp, mailStateFromEnv } from "./http/createCoreApp";
import { createMailDbPool } from "./persistence/postgres/pool";
import { runMailMigrations } from "./persistence/postgres/migrations";

const port = Number(process.env.PORT ?? 3000);

async function main(): Promise<void> {
  // Durable mail state: run migrations before serving any traffic. Without
  // AALIYAH_DATABASE_URL the app runs on in-memory state — dev only, and the
  // choice is printed so it can never pass silently as production.
  if (process.env.AALIYAH_DATABASE_URL) {
    const pool = createMailDbPool();
    await runMailMigrations(pool);
    await pool.end();
    process.stdout.write("mail state: postgres (migrations applied)\n");
  } else {
    process.stdout.write("mail state: IN-MEMORY (dev only — set AALIYAH_DATABASE_URL for durable state)\n");
  }

  const app = createCoreApp({ mailState: mailStateFromEnv() });
  app.listen(port, () => {
    process.stdout.write(`Aaliyah core running on ${port}\n`);
  });
}

main().catch((error) => {
  process.stderr.write(`startup failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
