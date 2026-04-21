import { emitMetric } from "../../observability/metrics";

function classifyConnectorFailure(error: unknown): string {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();

  if (message.includes("timeout")) {
    return "timeout";
  }

  if (message.includes("malformed")) {
    return "malformed_response";
  }

  if (message.includes("credential expired")) {
    return "expired_credential";
  }

  if (message.includes("missing credential")) {
    return "missing_credential";
  }

  if (message.includes("tenant boundary")) {
    return "tenant_mismatch";
  }

  return "provider_error";
}

export function wrapConnectorFailure(
  connector: string,
  error: unknown,
): never {
  const reason = classifyConnectorFailure(error);

  emitMetric("connector_failure", 1, {
    connector,
    reason,
  });

  throw error;
}

export function emitConnectorEmptyResult(connector: string): void {
  emitMetric("connector_empty_results", 1, { connector });
}
