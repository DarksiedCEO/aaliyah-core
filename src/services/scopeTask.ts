import type { TaskEnvelope } from "@aaliyah/contracts/v1";

export type TaskScope = {
  taskId: string;
  tenantId: string;
  userId: string;
  taskType: TaskEnvelope["taskType"];
  riskTier: TaskEnvelope["riskTier"];
  requestedOutcome: string;
  requiredSources: string[];
  constraints: string[];
};

export async function scopeTask(task: TaskEnvelope): Promise<TaskScope> {
  return {
    taskId: task.taskId,
    tenantId: task.tenantId,
    userId: task.userId,
    taskType: task.taskType,
    riskTier: task.riskTier,
    requestedOutcome: task.requestedOutcome,
    requiredSources: task.requiredSources,
    constraints: task.constraints,
  };
}
