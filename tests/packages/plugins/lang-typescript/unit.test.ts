import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { langTypescriptPlugin } from "@veristack/plugin-lang-typescript";

test("lang-typescript plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langTypescriptPlugin), true);
  assert.equal(langTypescriptPlugin.id, "veristack.plugin.lang-typescript");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langTypescriptPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});
