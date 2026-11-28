#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const localBin = path.resolve("node_modules/.bin/featlock");
const cmd = fs.existsSync(localBin) ? localBin : "bunx";
const args = fs.existsSync(localBin) ? ["check", "."] : ["featlock", "check", "."];
const res = spawnSync(cmd, args, { encoding: "utf8" });
if (res.error || res.status !== 0) {
  process.stderr.write(res.stdout || "");
  process.stderr.write(res.stderr || "");
  if (res.error) process.stderr.write(String(res.error.message || res.error) + "\n");
  process.stderr.write("\nFEATLOCK GUARD: Feature/invariant integrity check failed. Do NOT silently delete features or invariants.\n");
  process.exit(2);
}
