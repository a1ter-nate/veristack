import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { reviewBriefPlugin } from "@veristack/plugin-review-brief";

test("review-brief plugin defines valid Veristack plugin and registers into commands", () => {
  assert.equal(isVeristackPlugin(reviewBriefPlugin), true);
  assert.equal(reviewBriefPlugin.id, "veristack.plugin.review-brief");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [reviewBriefPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.commands().length >= 1);
});
