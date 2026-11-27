import assert from "node:assert/strict";
import { test } from "node:test";
import { buildRatchetBaseline, createPluginHostSync, createState } from "@veristack/core";

test("State.create tracks revision and createPluginHostSync activates all 18 built-in plugins", () => {
  const st = createState<number[], { push: (n: number) => void }>({
    name: "core.unit.nums",
    initial: () => [],
    editor: (draft) => ({ push: (n) => { draft.push(n); } }),
  });
  assert.equal(st.revision(), 0);
  const reg = st.transform((ed) => ed.push(42));
  assert.deepEqual(st.get(), [42]);
  assert.equal(st.revision(), 1);
  reg.dispose();
  assert.deepEqual(st.get(), []);

  const host = createPluginHostSync({ includeBuiltins: true });
  const entries = host.list();
  assert.equal(entries.length, 18);
  assert.equal(entries.every((e) => e.status === "active"), true);
});

test("buildRatchetBaseline includes dependenciesCount only when a numeric count is supplied", () => {
  const withDeps = buildRatchetBaseline([], undefined, 3);
  assert.equal(withDeps.dependenciesCount, 3);
  const withoutDeps = buildRatchetBaseline([]);
  assert.equal("dependenciesCount" in withoutDeps, false);
});
