import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { createPluginHostSync } from "@veristack/core";
import { langRustPlugin } from "@veristack/plugin-lang-rust";

class ActivatePluginCmd implements fc.Command<{ active: boolean }, { count: () => number }> {
  check(): boolean { return true; }
  run(model: { active: boolean }, real: { count: () => number }): void {
    model.active = true;
    assert.ok(real.count() >= 1);
  }
}

test("lang-rust plugin host activation and disposal maintain clean registry contract", async () => {
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langRustPlugin] });
  fc.assert(
    fc.property(fc.commands([fc.constant(new ActivatePluginCmd())], { maxCommands: 4 }), (cmds) => {
      fc.modelRun(
        () => ({ model: { active: false }, real: { count: () => host.registries.languages().length } }),
        cmds,
      );
    }),
    { numRuns: 10 },
  );
  await host.dispose();
  assert.equal(host.registries.languages().length, 0);
});
