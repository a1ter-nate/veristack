import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { langRustPlugin } from "@veristack/plugin-lang-rust";

test("lang-rust plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langRustPlugin), true);
  assert.equal(langRustPlugin.id, "veristack.plugin.lang-rust");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langRustPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});
