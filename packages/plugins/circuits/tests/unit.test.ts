import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { circuitsPlugin } from "@veristack/plugin-circuits";

test("circuits plugin defines valid Veristack plugin and registers into circuits", () => {
  assert.equal(isVeristackPlugin(circuitsPlugin), true);
  assert.equal(circuitsPlugin.id, "veristack.plugin.circuits");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [circuitsPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.circuits().length >= 1);
});
