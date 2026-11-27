import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { createPluginHostSync } from "@veristack/core";
import { canaryPlugin } from "@veristack/plugin-canary";

class ActivatePluginCmd implements fc.Command<{ active: boolean }, { count: () => number }> {
  check(): boolean { return true; }
  run(model: { active: boolean }, real: { count: () => number }): void {
    model.active = true;
    assert.ok(real.count() >= 1);
  }
}

test("canary plugin host activation and disposal maintain clean registry contract", async () => {
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [canaryPlugin] });
  fc.assert(
    fc.property(fc.commands([fc.constant(new ActivatePluginCmd())], { maxCommands: 4 }), (cmds) => {
      fc.modelRun(
        () => ({ model: { active: false }, real: { count: () => host.registries.rungs().length } }),
        cmds,
      );
    }),
    { numRuns: 10 },
  );
  await host.dispose();
  assert.equal(host.registries.rungs().length, 0);
});
