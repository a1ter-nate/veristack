import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { ciAuditorPlugin } from "@veristack/plugin-ci-auditor";

test("ci-auditor plugin defines valid Veristack plugin and registers into signals", () => {
  assert.equal(isVeristackPlugin(ciAuditorPlugin), true);
  assert.equal(ciAuditorPlugin.id, "veristack.plugin.ci-auditor");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [ciAuditorPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.signals().length >= 1);
});
