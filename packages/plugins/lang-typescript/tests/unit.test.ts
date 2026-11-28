import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createPluginHostSync, discoverRepo } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { analyzeT3TestGuards, analyzeTypestateProtocols, langTypescriptPlugin } from "@veristack/plugin-lang-typescript";

test("lang-typescript plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langTypescriptPlugin), true);
  assert.equal(langTypescriptPlugin.id, "veristack.plugin.lang-typescript");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langTypescriptPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});

test("test-no-test-in-loop ignores RegExp.prototype.test inside loops while catching bare test() registration", () => {
  const cleanCode = [
    'import { test, expect } from "bun:test";',
    'test("regex inside loop", () => {',
    '  const items = ["a1", "b2"];',
    '  for (const item of items) {',
    '    expect(/^[a-z]\\d$/.test(item)).toBe(true);',
    '    expect(new RegExp("\\\\d").test(item)).toBe(true);',
    '  }',
    '});',
  ].join("\n");
  const cleanFindings = analyzeT3TestGuards({
    rel: "tests/regex-loop.test.ts",
    abs: "/tmp/tests/regex-loop.test.ts",
    language: "typescript",
    isTest: true,
    isWorkflow: false,
    lines: 8,
    content: cleanCode,
  });
  assert.equal(cleanFindings.some((f) => f.rule === "test-no-test-in-loop"), false);

  const badCode = [
    'import { test, expect } from "bun:test";',
    'for (const item of ["a", "b"]) {',
    '  test(item, () => { expect(item.length).toBe(1); });',
    '}',
  ].join("\n");
  const badFindings = analyzeT3TestGuards({
    rel: "tests/bad-loop.test.ts",
    abs: "/tmp/tests/bad-loop.test.ts",
    language: "typescript",
    isTest: true,
    isWorkflow: false,
    lines: 4,
    content: badCode,
  });
  assert.equal(badFindings.some((f) => f.rule === "test-no-test-in-loop"), true);
});

test("Strom & Yemini declarative typestate protocols enforce valid transition order and termination", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-typestate-"));
  try {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "protocols.json"),
      JSON.stringify({
        schemaVersion: 1,
        protocols: [{
          id: "tx-protocol",
          constructors: ["openTx"],
          initial: "Unverified",
          terminal: ["Committed"],
          transitions: { Unverified: { verify: "Verified" }, Verified: { commit: "Committed" } },
        }],
      }),
    );
    fs.writeFileSync(
      path.join(dir, "src", "bad.ts"),
      "export function bad(): void { const tx = openTx(); tx.commit(); }\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "good.ts"),
      "export function good(): void { const tx = openTx(); tx.verify(); tx.commit(); }\n",
    );
    const findings = analyzeTypestateProtocols(discoverRepo(dir));
    assert.equal(findings.some((f) => f.file === "src/bad.ts" && f.rule === "typestate-invalid-transition"), true);
    assert.equal(findings.some((f) => f.file === "src/bad.ts" && f.rule === "typestate-unterminated-protocol"), true);
    assert.equal(findings.some((f) => f.file === "src/good.ts"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
