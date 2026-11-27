import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { createState, type StateInstance, type StateRegistration } from "@veristack/core";

interface StateModel { items: string[] }
interface StateReal {
  state: StateInstance<string[], { add: (v: string) => void }>;
  regs: Array<{ val: string; reg: StateRegistration }>;
}

class AddTransformCmd implements fc.Command<StateModel, StateReal> {
  constructor(readonly val: string) {}
  check(): boolean { return true; }
  run(model: StateModel, real: StateReal): void {
    const prevSnap = real.state.get();
    const prevCopy = [...prevSnap];
    const reg = real.state.transform((ed) => ed.add(this.val));
    model.items.push(this.val);
    real.regs.push({ val: this.val, reg });
    assert.deepEqual(prevSnap, prevCopy);
    assert.deepEqual(real.state.get(), model.items);
  }
}

class DisposeFirstCmd implements fc.Command<StateModel, StateReal> {
  check(model: Readonly<StateModel>): boolean { return model.items.length > 0; }
  run(model: StateModel, real: StateReal): void {
    const first = real.regs.shift();
    model.items.shift();
    first?.reg.dispose();
    assert.deepEqual(real.state.get(), model.items);
  }
}

test("Replayable State satisfies snapshot immutability and disposal replay MBT model", () => {
  fc.assert(
    fc.property(
      fc.commands(
        [
          fc.stringMatching(/^[a-z]{2,6}$/).map((v) => new AddTransformCmd(v)),
          fc.constant(new DisposeFirstCmd()),
        ],
        { maxCommands: 12 },
      ),
      (cmds) => {
        const setup = () => ({
          model: { items: [] as string[] },
          real: {
            state: createState<string[], { add: (v: string) => void }>({
              name: "core.mbt.state",
              initial: () => [],
              editor: (draft) => ({ add: (v) => { draft.push(v); } }),
            }),
            regs: [] as Array<{ val: string; reg: StateRegistration }>,
          },
        });
        fc.modelRun(setup, cmds);
      },
    ),
    { numRuns: 30 },
  );
});
