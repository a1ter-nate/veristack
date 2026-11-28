import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkCrossSurfaceParity, checkMetamorphicRelation, circuitsPlugin, createCorpusSeedStore } from "@veristack/plugin-circuits";

test("circuits plugin defines valid Veristack plugin and registers into circuits", () => {
  assert.equal(isVeristackPlugin(circuitsPlugin), true);
  assert.equal(circuitsPlugin.id, "veristack.plugin.circuits");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [circuitsPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.circuits().length >= 1);
});

test("metamorphic relation check, cross-surface parity, and PBT corpus seed store work cleanly", () => {
  const perm = checkMetamorphicRelation({
    relation: "permutation",
    inputs: [[3, 1, 2], [9, 4, 7]],
    transform: (xs) => [...xs].reverse(),
    evaluate: (xs) => xs.reduce((a, b) => a + b, 0),
    assertRelation: (a, b) => a === b,
  });
  assert.equal(perm.passed, true);

  const parity = checkCrossSurfaceParity(["alpha", "beta"], {
    http: (x) => x.toUpperCase(),
    cli: (x) => x.toUpperCase(),
    mcp: (x) => x.toUpperCase(),
  });
  assert.equal(parity.passed, true);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-seeds-"));
  try {
    const store = createCorpusSeedStore(path.join(dir, "pbt-seeds.json"));
    const saved = store.record({ property: "sort-idempotent", seed: 42, minimizedInput: [2, 1] });
    assert.equal(saved.length, 1);
    assert.equal(store.load()[0]?.seed, 42);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
