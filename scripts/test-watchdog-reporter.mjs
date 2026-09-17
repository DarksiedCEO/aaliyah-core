/**
 * Machine-readable event stream for scripts/test-watchdog.mjs.
 *
 * One JSON object per line, flushed as each event arrives, so the watchdog can
 * read a partial stream from a run it had to kill. The human-readable `spec`
 * reporter runs alongside this one; neither is the verdict. The verdict is the
 * watchdog's, computed from these events and from the process's exit.
 */
export default async function* watchdogReporter(source) {
  for await (const event of source) {
    const data = event.data ?? {};
    switch (event.type) {
      case "test:pass":
      case "test:fail":
      case "test:complete": {
        const error = data.details?.error;
        yield `${JSON.stringify({
          type: event.type,
          name: data.name,
          file: data.file ?? null,
          nesting: data.nesting,
          skip: data.skip !== undefined && data.skip !== false,
          todo: data.todo !== undefined && data.todo !== false,
          passed: data.details?.passed ?? null,
          failureType: error?.failureType ?? null,
          message:
            typeof error?.message === "string"
              ? error.message.slice(0, 500)
              : typeof error?.cause?.message === "string"
                ? error.cause.message.slice(0, 500)
                : null,
          code: error?.cause?.code ?? error?.code ?? null,
        })}\n`;
        break;
      }
      case "test:enqueue":
        // Every test the runner queued. A file that exits mid-run (even with
        // status 0) leaves queued tests with no outcome — a fake success the
        // summary counts alone do not show.
        yield `${JSON.stringify({
          type: event.type,
          name: data.name,
          file: data.file ?? null,
          nesting: data.nesting,
        })}\n`;
        break;
      case "test:summary":
        yield `${JSON.stringify({
          type: event.type,
          file: data.file ?? null,
          counts: data.counts ?? null,
          success: data.success ?? null,
        })}\n`;
        break;
      default:
        break;
    }
  }
}
