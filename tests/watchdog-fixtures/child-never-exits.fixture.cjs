const { test } = require("node:test");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
test("waits on a child process that never exits", async () => {
  const child = spawn("sleep", ["3600"], { stdio: "ignore" });
  fs.writeFileSync(process.env.WATCHDOG_FIXTURE_PID_FILE, String(child.pid));
  await new Promise((resolve) => child.on("exit", resolve));
});
