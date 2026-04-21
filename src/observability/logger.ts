import pino from "pino";

export const logger = pino({
  name: "aaliyah-core",
  level: process.env.LOG_LEVEL ?? "info",
  base: null,
});
