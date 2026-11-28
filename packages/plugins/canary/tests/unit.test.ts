import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createPluginHostSync, discoverRepo } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { canaryPlugin, isAridMutationLine, runAllDeclaredRungsAsync, runOrderDependenceGate, synthesizeLawMutants } from "@veristack/plugin-canary";

test("canary plugin defines valid Veristack plugin and registers into rungs", () => {
  assert.equal(isVeristackPlugin(canaryPlugin), true);
  assert.equal(canaryPlugin.id, "veristack.plugin.canary");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [canaryPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.rungs().length >= 1);
});

test("runAllDeclaredRungsAsync omits failureOutputs on pass and populates them on failure", async () => {
  const dir = mkdtempSync(join(tmpdir(), "vstack-canary-unit-"));
  try {
    mkdirSync(join(dir, ".verification"), { recursive: true });
    writeFileSync(join(dir, "pass.test.ts"), "import { test } from 'node:test'; import assert from 'node:assert/strict'; test('ok', () => { assert.equal(1, 1); });\n");
    writeFileSync(join(dir, "fail.test.ts"), "import { test } from 'node:test'; import assert from 'node:assert/strict'; test('boom', () => { assert.equal(1, 2); });\n");
    writeFileSync(
      join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        version: 1,
        archetype: "library",
        rungs: {
          R2: { command: "bun test pass.test.ts" },
          R3: { command: "bun test fail.test.ts" },
        },
      }),
    );
    const repo = discoverRepo(dir);
    const okRes = await runAllDeclaredRungsAsync(repo, "R2", "test-key");
    assert.equal(okRes.passed, true);
    assert.equal("failureOutputs" in okRes, false);

    const failRes = await runAllDeclaredRungsAsync(repo, "R3", "test-key");
    assert.equal(failRes.passed, false);
    assert.equal("failureOutputs" in failRes, true);
    assert.ok((failRes.failureOutputs?.R3 ?? "").length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("arid-node filter, law-targeted mutant synthesis, and order-dependence shuffle gate work deterministically", () => {
  assert.equal(isAridMutationLine('console.log("debug", x);'), true);
  assert.equal(isAridMutationLine("if (balance >= amount) return true;"), false);

  const dir = mkdtempSync(join(tmpdir(), "vstack-od-gate-"));
  try {
    mkdirSync(join(dir, ".verification", "laws"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "rule.ts"), "export function ok(n: number): boolean { return n >= 1; }\n");
    writeFileSync(join(dir, ".verification", "laws", "core.laws.json"), JSON.stringify({ laws: [{ id: "law.pos", coveredFiles: ["src/rule.ts"] }] }));
    const lawMutants = synthesizeLawMutants(dir);
    assert.equal(lawMutants.length, 1);
    assert.equal(lawMutants[0]?.lawId, "law.pos");

    writeFileSync(join(dir, "a.test.ts"), "import { test } from 'node:test'; import assert from 'node:assert/strict'; test('a', () => { assert.equal(1 + 1, 2); });\n");
    writeFileSync(join(dir, "b.test.ts"), "import { test } from 'node:test'; import assert from 'node:assert/strict'; test('b', () => { assert.equal(2 + 2, 4); });\n");
    const od = runOrderDependenceGate({ repoRoot: dir, testCmd: "bun test a.test.ts b.test.ts", orders: 3 });
    assert.equal(od.passed, true);
    assert.equal(od.ordersTested, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
