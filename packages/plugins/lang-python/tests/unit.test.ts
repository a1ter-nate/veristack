import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { langPythonPlugin } from "@veristack/plugin-lang-python";

test("lang-python plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langPythonPlugin), true);
  assert.equal(langPythonPlugin.id, "veristack.plugin.lang-python");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langPythonPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});
