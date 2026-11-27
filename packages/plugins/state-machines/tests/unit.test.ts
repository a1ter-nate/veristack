import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { stateMachinesPlugin } from "@veristack/plugin-state-machines";

test("state-machines plugin defines valid Veristack plugin and registers into analyzers", () => {
  assert.equal(isVeristackPlugin(stateMachinesPlugin), true);
  assert.equal(stateMachinesPlugin.id, "veristack.plugin.state-machines");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [stateMachinesPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});
