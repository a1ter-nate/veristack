import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { analyzeEffectV4Rules, effectV4Plugin } from "@veristack/plugin-effect-v4";

test("effect-v4 plugin defines valid Veristack plugin and registers into analyzers", () => {
  assert.equal(isVeristackPlugin(effectV4Plugin), true);
  assert.equal(effectV4Plugin.id, "veristack.plugin.effect-v4");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [effectV4Plugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.analyzers().length >= 1);
});

test("uncomplect Effect v4 fences catch defect-folded-to-terminal and pass-through Layer wrappers", () => {
  const badSrc = [
    'import { Effect, Layer } from "effect";',
    'export const badFold = Effect.catchAll(Effect.void, () => Effect.succeed("settled"));',
    "export const badLayer = Layer.succeed(ClockSvc, { now: (x) => rawClock.now(x) });",
  ].join("\n");
  const findings = analyzeEffectV4Rules({
    rel: "src/eff.ts", abs: "/tmp/src/eff.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 3, content: badSrc,
  });
  const rules = new Set(findings.map((f) => f.rule));
  assert.equal(rules.has("effect-defect-folded-to-terminal"), true);
  assert.equal(rules.has("effect-passthrough-service-wrapper"), true);

  const cleanSrc = [
    'import { Effect } from "effect";',
    'export const ok = Effect.catchTag(Effect.void, "Timeout", () => Effect.succeed("pending"));',
  ].join("\n");
  const cleanFindings = analyzeEffectV4Rules({
    rel: "src/ok.ts", abs: "/tmp/src/ok.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 2, content: cleanSrc,
  });
  assert.equal(cleanFindings.length, 0);
});
