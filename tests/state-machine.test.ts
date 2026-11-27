import assert from "node:assert/strict";
import test from "node:test";
import explicitSmPlugin from "../lint/oxlint-explicit-state-machine.mjs";
import type { ScannedFile } from "@veristack/core";
import { lintImplicitStateMachinesInFile } from "@veristack/plugin-state-machines";

function fakeTsFile(rel: string, content: string): ScannedFile {
  return {
    rel,
    abs: `/virtual/${rel}`,
    language: "typescript",
    isTest: false,
    isWorkflow: false,
    content,
    lines: content.split(/\r?\n/).length,
  };
}

test("flags boolean-flag lifecycle soup (red) and passes explicit discriminated union (green)", () => {
  const bad = [
    "export class Watchdog {",
    "  isRunning = false;",
    "  isArmed = false;",
    "  isDraining = false;",
    "  wasReverted = false;",
    "}",
  ].join("\n");
  const badHits = lintImplicitStateMachinesInFile(fakeTsFile("src/watchdog.ts", bad));
  assert.deepEqual(
    badHits.map((h) => h.rule),
    ["implicit-sm-boolean-soup"],
  );

  const good = [
    "export type WatchdogState =",
    '  | { readonly kind: "idle" }',
    '  | { readonly kind: "armed"; readonly armedAt: number }',
    '  | { readonly kind: "draining"; readonly startedAt: number }',
    '  | { readonly kind: "reverted"; readonly reason: string };',
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeTsFile("src/watchdog.ts", good)), []);
});

test("flags optional-field state bag (red) and passes per-variant discriminated union (green)", () => {
  const bad = [
    "export interface RunRecord {",
    '  status: "running" | "stopped" | "failed";',
    "  error?: string;",
    "  finishedAt?: number;",
    "  verdict?: string;",
    "}",
  ].join("\n");
  const badHits = lintImplicitStateMachinesInFile(fakeTsFile("src/run.ts", bad));
  assert.deepEqual(
    badHits.map((h) => h.rule),
    ["implicit-sm-optional-bag"],
  );

  const good = [
    "export type RunRecord =",
    '  | { readonly status: "running"; readonly startedAt: number }',
    '  | { readonly status: "stopped"; readonly finishedAt: number; readonly verdict: string }',
    '  | { readonly status: "failed"; readonly finishedAt: number; readonly error: string };',
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeTsFile("src/run.ts", good)), []);
});

test("flags scattered direct state mutations (red) and passes centralized transition function (green)", () => {
  const bad = [
    "export class JobRunner {",
    '  status = "idle";',
    "  start() {",
    '    this.status = "running";',
    "  }",
    "  stop() {",
    '    this.status = "stopped";',
    "  }",
    "}",
  ].join("\n");
  const badHits = lintImplicitStateMachinesInFile(fakeTsFile("src/runner.ts", bad));
  assert.deepEqual(
    badHits.map((h) => h.rule),
    ["implicit-sm-scattered-mutation"],
  );

  const good = [
    "export class JobRunner {",
    '  status = "idle";',
    "  constructor() {",
    '    this.status = "idle";',
    "  }",
    "  transition(next: string) {",
    "    this.status = next;",
    "  }",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeTsFile("src/runner.ts", good)), []);
});

test("flags non-exhaustive state switch (red) and passes switch with never exhaustiveness guard (green)", () => {
  const bad = [
    "export function label(run: { status: 'idle' | 'running' }) {",
    "  switch (run.status) {",
    "    case 'idle': return 'Idle';",
    "    case 'running': return 'Running';",
    "  }",
    "}",
  ].join("\n");
  const badHits = lintImplicitStateMachinesInFile(fakeTsFile("src/label.ts", bad));
  assert.deepEqual(
    badHits.map((h) => h.rule),
    ["implicit-sm-non-exhaustive-switch"],
  );

  const good = [
    "export function label(run: { status: 'idle' | 'running' }) {",
    "  switch (run.status) {",
    "    case 'idle': return 'Idle';",
    "    case 'running': return 'Running';",
    "    default: {",
    "      const _exhaustive: never = run.status;",
    "      throw new Error(String(_exhaustive));",
    "    }",
    "  }",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeTsFile("src/label.ts", good)), []);
});

test("false-positive guards: ignores plain config DTOs, feature flags, optional mode configs, and non-state switches", () => {
  const cleanConfig = [
    "export interface BuildConfig {",
    "  enableCache: boolean;",
    "  verbose: boolean;",
    "  dryRun: boolean;",
    "  strict: boolean;",
    "  hasFormatter: boolean;",
    "  hasLinter: boolean;",
    "  mode?: 'fast' | 'full';",
    "  outDir?: string;",
    "  concurrency?: number;",
    "}",
    "export interface RunnerOptions {",
    "  mode: 'local' | 'ci';",
    "  endpoint?: string;",
    "  timeoutMs?: number;",
    "}",
    "export function routeCmd(cmd: string) {",
    "  switch (cmd) {",
    "    case 'scan': return 1;",
    "    default: return 0;",
    "  }",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeTsFile("src/config.ts", cleanConfig)), []);
});

test("Oxlint plugin reports all 4 AST patterns via create(context) visitor", () => {
  const reports: string[] = [];
  const rule = explicitSmPlugin.rules["no-implicit-state-machine"];
  const visitor = rule.create({
    report(descriptor: { messageId: string }) {
      reports.push(descriptor.messageId);
    },
  });

  visitor.TSInterfaceDeclaration({
    type: "TSInterfaceDeclaration",
    id: { type: "Identifier", name: "BadSoup" },
    body: {
      body: [
        { type: "TSPropertySignature", key: { type: "Identifier", name: "isRunning" }, optional: false, typeAnnotation: { type: "TSTypeAnnotation", typeAnnotation: { type: "TSBooleanKeyword" } } },
        { type: "TSPropertySignature", key: { type: "Identifier", name: "isArmed" }, optional: false, typeAnnotation: { type: "TSTypeAnnotation", typeAnnotation: { type: "TSBooleanKeyword" } } },
        { type: "TSPropertySignature", key: { type: "Identifier", name: "isDraining" }, optional: false, typeAnnotation: { type: "TSTypeAnnotation", typeAnnotation: { type: "TSBooleanKeyword" } } },
        {
          type: "TSPropertySignature",
          key: { type: "Identifier", name: "status" },
          optional: false,
          typeAnnotation: {
            type: "TSTypeAnnotation",
            typeAnnotation: {
              type: "TSUnionType",
              types: [
                { type: "TSLiteralType", literal: { value: "running" } },
                { type: "TSLiteralType", literal: { value: "failed" } },
              ],
            },
          },
        },
        { type: "TSPropertySignature", key: { type: "Identifier", name: "error" }, optional: true },
        { type: "TSPropertySignature", key: { type: "Identifier", name: "finishedAt" }, optional: true },
      ],
    },
  });

  const fnA = { type: "FunctionDeclaration", id: { type: "Identifier", name: "start" } };
  visitor.FunctionDeclaration(fnA);
  visitor.AssignmentExpression({
    type: "AssignmentExpression",
    operator: "=",
    left: { type: "MemberExpression", computed: false, property: { type: "Identifier", name: "status" } },
  });
  visitor["FunctionDeclaration:exit"]();

  const fnB = { type: "FunctionDeclaration", id: { type: "Identifier", name: "stop" } };
  visitor.FunctionDeclaration(fnB);
  visitor.AssignmentExpression({
    type: "AssignmentExpression",
    operator: "=",
    left: { type: "MemberExpression", computed: false, property: { type: "Identifier", name: "status" } },
  });
  visitor["FunctionDeclaration:exit"]();

  visitor.SwitchStatement({
    type: "SwitchStatement",
    discriminant: { type: "MemberExpression", computed: false, property: { type: "Identifier", name: "status" } },
    cases: [{ test: { type: "Literal", value: "running" } }],
  });

  visitor["Program:exit"]();

  assert.deepEqual(reports.sort(), [
    "booleanSoup",
    "nonExhaustiveSwitch",
    "optionalBag",
    "scatteredMutation",
  ]);
});
