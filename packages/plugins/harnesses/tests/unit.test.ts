import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { harnessesPlugin } from "@veristack/plugin-harnesses";

test("harnesses plugin defines valid Veristack plugin and registers into harnesses", () => {
  assert.equal(isVeristackPlugin(harnessesPlugin), true);
  assert.equal(harnessesPlugin.id, "veristack.plugin.harnesses");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [harnessesPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.harnesses().length >= 1);
});
