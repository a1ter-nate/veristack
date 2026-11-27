import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { auditRunnerConfigs, controlPlanePlugin } from "@veristack/plugin-control-plane";

test("control-plane plugin defines valid Veristack plugin and registers into rungs", () => {
  assert.equal(isVeristackPlugin(controlPlanePlugin), true);
  assert.equal(controlPlanePlugin.id, "veristack.plugin.control-plane");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [controlPlanePlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.rungs().length >= 1);
});

test("auditRunnerConfigs allows Bun monorepo workspace node_modules/.bin symlinks into root node_modules/.bun store", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bun-nm-"));
  try {
    const storeBin = path.join(dir, "node_modules", ".bun", "typescript@5.9.3", "node_modules", "typescript", "bin");
    const wsBin = path.join(dir, "packages", "app", "node_modules", ".bin");
    fs.mkdirSync(storeBin, { recursive: true });
    fs.mkdirSync(wsBin, { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "mono", workspaces: ["packages/*"] }));
    fs.writeFileSync(path.join(dir, "packages", "app", "package.json"), JSON.stringify({ name: "@mono/app" }));
    fs.writeFileSync(path.join(storeBin, "tsc"), "#!/usr/bin/env node\n");
    fs.symlinkSync(path.join(storeBin, "tsc"), path.join(wsBin, "tsc"));
    assert.equal(auditRunnerConfigs(dir), null);

    fs.unlinkSync(path.join(wsBin, "tsc"));
    fs.writeFileSync(path.join(dir, "evil-tsc.js"), "#!/usr/bin/env node\n");
    fs.symlinkSync(path.join(dir, "evil-tsc.js"), path.join(wsBin, "tsc"));
    assert.ok(auditRunnerConfigs(dir)?.includes("resolves outside node_modules"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
