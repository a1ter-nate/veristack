import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { agentDocsPlugin } from "@veristack/plugin-agent-docs";

test("agent-docs plugin defines valid Veristack plugin and registers into analyzers", () => {
  assert.equal(isVeristackPlugin(agentDocsPlugin), true);
  assert.equal(agentDocsPlugin.id, "veristack.plugin.agent-docs");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [agentDocsPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});
