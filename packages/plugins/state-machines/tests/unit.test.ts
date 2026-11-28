import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { lintStatechartCompletenessAndCrashFolding, stateMachinesPlugin } from "@veristack/plugin-state-machines";

test("state-machines plugin defines valid Veristack plugin and registers into analyzers", () => {
  assert.equal(isVeristackPlugin(stateMachinesPlugin), true);
  assert.equal(stateMachinesPlugin.id, "veristack.plugin.state-machines");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [stateMachinesPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});

test("Harel statechart completeness and uncomplect crash-folding catch broken charts and pass clean charts", () => {
  const badChart = [
    "export const machine = {",
    '  initial: "idle",',
    "  states: {",
    "    idle: {",
    "      entry: 'startTimer',",
    "      invoke: { src: 'pay', onDone: 'settled', onError: { target: 'settled' } },",
    "      on: { GO: [{ guard: 'ok', target: 'running' }, { guard: 'ok', target: 'settled' }] },",
    "    },",
    "    running: { on: { CANCEL: 'settled' } },",
    "    review: { on: { CANCEL: 'settled' } },",
    "    settled: { type: 'final' },",
    "    orphan: { on: { PING: 'idle' } },",
    "  },",
    "};",
  ].join("\n");
  const bad = lintStatechartCompletenessAndCrashFolding({
    rel: "src/chart.ts", abs: "/tmp/src/chart.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 14, content: badChart,
  });
  const badRules = new Set(bad.map((f) => f.rule));
  assert.equal(badRules.has("sm-crash-folded-to-terminal"), true);
  assert.equal(badRules.has("statechart-unreachable-state"), true);
  assert.equal(badRules.has("statechart-overlapping-guards"), true);
  assert.equal(badRules.has("statechart-missing-exit-cleanup"), true);

  const cleanChart = [
    "export const clean = {",
    '  initial: "idle",',
    "  states: {",
    "    idle: { entry: 'startTimer', exit: 'stopTimer', invoke: { src: 'pay', onDone: 'settled', onError: { target: 'errored' } }, on: { GO: 'settled' } },",
    "    errored: { on: { RETRY: 'idle' } },",
    "    settled: { type: 'final' },",
    "  },",
    "};",
  ].join("\n");
  const clean = lintStatechartCompletenessAndCrashFolding({
    rel: "src/clean-chart.ts", abs: "/tmp/src/clean-chart.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 8, content: cleanChart,
  });
  assert.equal(clean.length, 0);
});
