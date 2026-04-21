import express from "express";
import type { Router } from "express";

import { runAaliyahTask } from "../application/decision-engine/runAaliyahTask";

export const internalEvalRoutes: Router = express.Router();
export const internalEvalRouteInternals = {
  runTask: runAaliyahTask,
};

internalEvalRoutes.post("/internal/evals/run-task", async (req, res) => {
  const enabled = process.env.AALIYAH_ENABLE_INTERNAL_EVAL === "true";
  const secret = process.env.AALIYAH_EVAL_SECRET;

  if (!enabled) {
    return res.status(404).end();
  }

  if (!secret || req.headers["x-eval-secret"] !== secret) {
    return res.status(403).end();
  }

  try {
    const result = await internalEvalRouteInternals.runTask(req.body);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({
      error: "eval failure",
    });
  }
});
