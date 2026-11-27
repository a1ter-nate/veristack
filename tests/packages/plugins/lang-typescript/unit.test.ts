import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { analyzeT3TestGuards, langTypescriptPlugin } from "@veristack/plugin-lang-typescript";

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
