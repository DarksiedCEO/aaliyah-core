import express, { type Express } from "express";
import { internalEvalRoutes } from "./internalEvalRoutes";

export function createCoreApp(): Express {
  if (
    process.env.AALIYAH_ENABLE_INTERNAL_EVAL === "true" &&
    !process.env.AALIYAH_EVAL_SECRET
  ) {
    throw new Error("AALIYAH_EVAL_SECRET is required when internal eval routes are enabled");
  }

  const app = express();

  app.use(express.json());
  app.use(internalEvalRoutes);

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  return app;
}
