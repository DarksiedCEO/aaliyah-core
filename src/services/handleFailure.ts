export function handleFailure(error: Error): "fail" | "retry" | "escalate" {
  if (/credential/i.test(error.message)) {
    return "fail";
  }

  if (/timeout/i.test(error.message)) {
    return "retry";
  }

  if (/malformed|invalid source|low-quality source/i.test(error.message)) {
    return "escalate";
  }

  if (/empty|no evidence|no evidence sources available/i.test(error.message)) {
    return "retry";
  }

  if (/contradiction/i.test(error.message)) {
    return "fail";
  }

  return "escalate";
}
