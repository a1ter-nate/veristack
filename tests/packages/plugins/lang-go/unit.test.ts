import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { langGoPlugin } from "@veristack/plugin-lang-go";

test("lang-go plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langGoPlugin), true);
  assert.equal(langGoPlugin.id, "veristack.plugin.lang-go");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langGoPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});
