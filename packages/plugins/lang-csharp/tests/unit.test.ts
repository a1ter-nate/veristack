import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { langCsharpPlugin } from "@veristack/plugin-lang-csharp";

test("lang-csharp plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langCsharpPlugin), true);
  assert.equal(langCsharpPlugin.id, "veristack.plugin.lang-csharp");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langCsharpPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});
