#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distCli = path.join(rootDir, "dist", "cli.mjs");
const srcCli = path.join(rootDir, "src", "cli.ts");

function failClosedStartup(msg) {
  if (process.argv[2] === "hook") {
    const sub = process.argv[3];
    const hIdx = process.argv.indexOf("--harness");
    const harness = hIdx >= 0 ? process.argv[hIdx + 1] : "claude";
    const errMsg = `Veristack hook failed closed on startup error: ${msg}`;
    if (sub === "pre-edit") {
      console.error(errMsg);
      if (harness !== "codex") {
        console.log(JSON.stringify({ permission: "deny", hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: errMsg }, user_message: errMsg, agent_message: errMsg }));
      }
      process.exit(2);
    }
    if (sub === "stop") {
      console.log(JSON.stringify({ decision: "block", reason: errMsg }));
      process.exit(0);
    }
  }
  console.error(msg);
  process.exit(1);
}

if (fs.existsSync(srcCli)) {
  const res = spawnSync("bun", [srcCli, ...process.argv.slice(2)], { stdio: "inherit" });
  if (res.error) {
    failClosedStartup(`tracked src/cli.ts requires bun (${res.error.message}); refusing unverified dist/cli.mjs`);
  }
  process.exit(res.status ?? 1);
}

try {
  await import(pathToFileURL(distCli).href);
} catch (err) {
  failClosedStartup(err instanceof Error ? err.message : String(err));
}
