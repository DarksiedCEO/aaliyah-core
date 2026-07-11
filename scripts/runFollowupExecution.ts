import {
  runFollowupExecution,
  type FollowupDecisionResolverInput,
  type FollowupDecisionResolverResult,
} from "../src/application/execution/runFollowupExecution";

type FollowupDecisionResolver = (
  input: FollowupDecisionResolverInput,
) => Promise<FollowupDecisionResolverResult>;

/**
 * Load the concrete follow-up decision adapter the operator points at via
 * AALIYAH_FOLLOWUP_ADAPTER_MODULE (an absolute path or package specifier to a
 * module exporting `runFortressFollowupDecision`).
 *
 * aaliyah-core owns the resolver INTERFACE (FollowupDecisionResolverInput /
 * Result) and never names, imports, or builds against any particular adapter
 * implementation — so this script introduces no dependency on aaliyah-workflows
 * (or any sibling repo). The dependency is inverted: the adapter conforms to
 * core's interface, injected at run time.
 */
async function loadFollowupDecisionResolver(): Promise<FollowupDecisionResolver> {
  const modulePath = process.env.AALIYAH_FOLLOWUP_ADAPTER_MODULE;
  if (!modulePath) {
    throw new Error(
      "Set AALIYAH_FOLLOWUP_ADAPTER_MODULE to a module (absolute path or package specifier) exporting runFortressFollowupDecision",
    );
  }
  const mod = (await import(modulePath)) as {
    runFortressFollowupDecision?: FollowupDecisionResolver;
  };
  if (typeof mod.runFortressFollowupDecision !== "function") {
    throw new Error(
      `Adapter module '${modulePath}' does not export a runFortressFollowupDecision function`,
    );
  }
  return mod.runFortressFollowupDecision;
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

  const resolveFollowupDecision = await loadFollowupDecisionResolver();

  const result = await runFollowupExecution(
    {
      threadId: resolvedThreadId,
      messageId: resolvedMessageId,
      tenantId,
    },
    {
      accessToken,
      userId,
      resolveFollowupDecision,
    },
  );

  console.log("RESULT:", JSON.stringify(result, null, 2));
}

void main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
