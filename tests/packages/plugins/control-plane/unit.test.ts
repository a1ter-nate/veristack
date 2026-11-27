import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { controlPlanePlugin } from "@veristack/plugin-control-plane";

test("control-plane plugin defines valid Veristack plugin and registers into rungs", () => {
  assert.equal(isVeristackPlugin(controlPlanePlugin), true);
  assert.equal(controlPlanePlugin.id, "veristack.plugin.control-plane");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [controlPlanePlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.rungs().length >= 1);
});
