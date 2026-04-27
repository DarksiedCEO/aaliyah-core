import {
  runFollowupExecution,
  type FollowupDecisionResolverInput,
  type FollowupDecisionResolverResult,
} from "../src/application/execution/runFollowupExecution";

async function loadFortressResolver() {
  try {
    return (await import(
      "../../aaliyah-workflows/dist/src/adapters/runFortressFollowupDecision.js"
    )) as unknown as {
      runFortressFollowupDecision: (
        input: FollowupDecisionResolverInput,
      ) => Promise<FollowupDecisionResolverResult>;
    };
  } catch (error) {
    throw new Error(
      `Unable to load fortress follow-up adapter from aaliyah-workflows dist. Build workflows first. ${String(error)}`,
    );
  }
}

async function main(): Promise<void> {
  const threadId = process.argv[2];
  const accessToken = process.env.GMAIL_ACCESS_TOKEN;
  const tenantId = process.env.AALIYAH_TENANT_ID ?? "default";
  const userId = process.env.AALIYAH_USER_ID ?? "gmail-manual-approval";

  if (!threadId) {
    console.error(
      "Usage: node --require ts-node/register scripts/runFollowupExecution.ts <threadId> [messageId]",
    );
    process.exit(1);
  }

  const resolvedThreadId = threadId;
  const resolvedMessageId = process.argv[3] ?? resolvedThreadId;

  if (!accessToken) {
    console.error("Missing GMAIL_ACCESS_TOKEN");
    process.exit(1);
  }

  const { runFortressFollowupDecision } = await loadFortressResolver();

  const result = await runFollowupExecution(
    {
      threadId: resolvedThreadId,
      messageId: resolvedMessageId,
      tenantId,
    },
    {
      accessToken,
      userId,
      resolveFollowupDecision: runFortressFollowupDecision,
    },
  );

  console.log("RESULT:", JSON.stringify(result, null, 2));
}

void main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
