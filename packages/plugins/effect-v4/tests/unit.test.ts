import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { effectV4Plugin } from "@veristack/plugin-effect-v4";

test("effect-v4 plugin defines valid Veristack plugin and registers into analyzers", () => {
  assert.equal(isVeristackPlugin(effectV4Plugin), true);
  assert.equal(effectV4Plugin.id, "veristack.plugin.effect-v4");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [effectV4Plugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});
