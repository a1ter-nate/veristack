import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { analyzeTigerControlFlow, tigerstylePlugin } from "@veristack/plugin-tigerstyle";

test("tigerstyle plugin defines valid Veristack plugin and registers analyzers", () => {
  assert.equal(isVeristackPlugin(tigerstylePlugin), true);
  assert.equal(tigerstylePlugin.id, "veristack.plugin.tigerstyle");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [tigerstylePlugin] });
  assert.equal(host.list()[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});

test("tiger-function-length ignores multi-line template literal payloads while still flagging long executable functions", () => {
  const htmlLines = Array.from({ length: 180 }, (_, idx) => `    <div data-row="${idx}">Row ${idx}</div>`).join("\n");
  const templateRenderer = `export function renderStudioPage(title: string): string {\n  return \`<!doctype html>\n  <html><body><h1>\${title}</h1>\n${htmlLines}\n  </body></html>\`;\n}\n`;
  const templateFindings = analyzeTigerControlFlow({
    rel: "src/studio.ts",
    abs: "/tmp/src/studio.ts",
    language: "typescript",
    isTest: false,
    isWorkflow: false,
    lines: 186,
    content: templateRenderer,
  });
  assert.equal(templateFindings.some((f) => f.rule === "tiger-function-length"), false);

  const realStmts = Array.from({ length: 85 }, (_, idx) => `  total += input + ${idx};`).join("\n");
  const longCodeFn = `export function computeHeavy(input: number): number {\n  let total = 0;\n${realStmts}\n  return total;\n}\n`;
  const realFindings = analyzeTigerControlFlow({
    rel: "src/heavy.ts",
    abs: "/tmp/src/heavy.ts",
    language: "typescript",
    isTest: false,
    isWorkflow: false,
    lines: 90,
    content: longCodeFn,
  });
  assert.equal(realFindings.some((f) => f.rule === "tiger-function-length"), true);
});
