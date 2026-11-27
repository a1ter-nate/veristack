import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { canaryPlugin } from "@veristack/plugin-canary";

test("canary plugin defines valid Veristack plugin and registers into rungs", () => {
  assert.equal(isVeristackPlugin(canaryPlugin), true);
  assert.equal(canaryPlugin.id, "veristack.plugin.canary");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [canaryPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.rungs().length >= 1);
});
