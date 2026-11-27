import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { lawsFormalPlugin } from "@veristack/plugin-laws-formal";

test("laws-formal plugin defines valid Veristack plugin and registers into commands", () => {
  assert.equal(isVeristackPlugin(lawsFormalPlugin), true);
  assert.equal(lawsFormalPlugin.id, "veristack.plugin.laws-formal");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [lawsFormalPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.commands().length >= 1);
});
