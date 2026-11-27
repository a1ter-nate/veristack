import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { definePlugin, isVeristackPlugin, maskCode } from "@veristack/plugin";

class DefinePluginCommand implements fc.Command<{ ids: string[] }, Set<string>> {
  constructor(readonly id: string) {}
  check(): boolean { return true; }
  run(model: { ids: string[] }, real: Set<string>): void {
    const def = definePlugin({ id: this.id, setup() {} });
    assert.equal(isVeristackPlugin(def), true);
    model.ids.push(def.id);
    real.add(def.id);
    assert.equal(real.size, new Set(model.ids).size);
  }
}

test("SDK plugin branding and lexical masking preserve invariants under MBT commands", () => {
  fc.assert(
    fc.property(
      fc.commands([fc.stringMatching(/^[a-z]{3,8}\.[a-z]{3,8}$/).map((id) => new DefinePluginCommand(id))], { maxCommands: 8 }),
      (cmds) => {
        const s = () => ({ model: { ids: [] as string[] }, real: new Set<string>() });
        fc.modelRun(s, cmds);
      },
    ),
    { numRuns: 25 },
  );
  const masked = maskCode("const x = 1;", "typescript");
  assert.equal(masked.length, "const x = 1;".length);
});
