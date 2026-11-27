import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import veristackLintPlugin from "../../lint/index.mjs";
import { scanRepo } from "@veristack/core";

test("Bend 2 universal laws enforce monotonic terminals, saturating math, zero-cap clamping, codec symmetry, and unwind across TS, C#, Rust, Python, and Go", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bend-laws-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });

    fs.writeFileSync(
      path.join(tmp, "src", "orders.ts"),
      [
        "export type OrderState = 'Pending' | 'Shipped' | 'Cancelled';",
        "export function transition(s: OrderState): OrderState {",
        "  switch (s) {",
        "    case 'Shipped': return 'Pending';",
        "    case 'Pending': return 'Shipped';",
        "    case 'Cancelled': return 'Cancelled';",
        "  }",
        "}",
        "export function debit(balance: number, amount: number): number {",
        "  balance -= amount;",
        "  return balance;",
        "}",
        "export function page(cap?: number): number {",
        "  const effective = cap || 25;",
        "  return effective;",
        "}",
        "export function encodeStatus(s: OrderState): number {",
        "  switch (s) { case 'Pending': return 0; case 'Shipped': return 1; case 'Cancelled': return 2; }",
        "}",
        "export function decodeStatus(code: number): OrderState {",
        "  switch (code) { case 0: return 'Pending'; case 1: return 'Shipped'; default: return 'Pending'; }",
        "}",
      ].join("\n") + "\n",
    );

    fs.writeFileSync(
      path.join(tmp, "src", "order_rs.rs"),
      [
        "pub enum Order { Pending, Shipped, Cancelled }",
        "pub fn cancel(o: Order) -> Order {",
        "  match o {",
        "    Order::Shipped => Order::Pending,",
        "    Order::Pending => Order::Cancelled,",
        "    Order::Cancelled => Order::Cancelled,",
        "  }",
        "}",
      ].join("\n") + "\n",
    );

    fs.writeFileSync(
      path.join(tmp, "src", "locker.go"),
      [
        "package locker",
        "import (\"sync\"; \"time\")",
        "func Work(mu *sync.Mutex, start int64) int64 {",
        "  mu.Lock()",
        "  elapsed := time.Now().UnixMilli() - start",
        "  mu.Unlock()",
        "  return elapsed",
        "}",
        "func ResetForTesting() {}",
      ].join("\n") + "\n",
    );

    fs.writeFileSync(
      path.join(tmp, "src", "quota.py"),
      [
        "def resolve_quota(cap: int | None) -> int:",
        "    effective = cap or 50",
        "    return effective",
      ].join("\n") + "\n",
    );

    const report = scanRepo(tmp);
    const rulesByFile = new Map<string, Set<string>>();
    for (const f of report.findings) {
      const set = rulesByFile.get(f.file) ?? new Set<string>();
      set.add(f.rule);
      rulesByFile.set(f.file, set);
    }

    assert.ok(rulesByFile.get("src/orders.ts")?.has("law-monotonic-terminal-state"));
    assert.ok(rulesByFile.get("src/orders.ts")?.has("law-saturating-underflow"));
    assert.ok(rulesByFile.get("src/orders.ts")?.has("law-zero-cap-clamp"));
    assert.ok(rulesByFile.get("src/orders.ts")?.has("law-codec-roundtrip-asymmetry"));
    assert.ok(rulesByFile.get("src/order_rs.rs")?.has("law-monotonic-terminal-state"));
    assert.ok(rulesByFile.get("src/locker.go")?.has("law-unwind-unpaired"));
    assert.ok(rulesByFile.get("src/locker.go")?.has("cdc-wall-clock-duration"));
    assert.ok(rulesByFile.get("src/locker.go")?.has("no-test-only-production-seam"));
    assert.ok(rulesByFile.get("src/quota.py")?.has("law-zero-cap-clamp"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("clean Bend-law-compliant code across TS, Go, and Python produces zero law findings", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bend-clean-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "src", "safe.ts"),
      [
        "export type OrderState = 'Pending' | 'Shipped' | 'Cancelled';",
        "export function debit(balance: number, amount: number): number {",
        "  return Math.max(0, balance - amount);",
        "}",
        "export function page(cap?: number): number {",
        "  return cap ?? 25;",
        "}",
        "export function encodeStatus(s: OrderState): number {",
        "  switch (s) { case 'Pending': return 0; case 'Shipped': return 1; case 'Cancelled': return 2; }",
        "}",
        "export function decodeStatus(code: number): OrderState {",
        "  switch (code) { case 0: return 'Pending'; case 1: return 'Shipped'; case 2: return 'Cancelled'; default: throw new Error('bad'); }",
        "}",
      ].join("\n") + "\n",
    );
    fs.writeFileSync(
      path.join(tmp, "src", "safe.go"),
      [
        "package locker",
        "import (\"sync\"; \"time\")",
        "func Work(mu *sync.Mutex, start time.Time) time.Duration {",
        "  mu.Lock()",
        "  defer mu.Unlock()",
        "  return time.Since(start)",
        "}",
      ].join("\n") + "\n",
    );

    const report = scanRepo(tmp);
    const lawRules = report.findings.filter((f) => f.rule.startsWith("law-") || f.rule === "cdc-wall-clock-duration");
    assert.deepEqual(lawRules, []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("universal anti-slop, internal/ boundary, landmines test rules, and unified Oxlint plugin catch violations cleanly", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-antislop-univ-"));
  try {
    fs.mkdirSync(path.join(tmp, "src", "billing", "internal"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "src", "orders"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "tests"), { recursive: true });

    fs.writeFileSync(path.join(tmp, "src", "billing", "internal", "ledger.ts"), "export const secret = 1;\n");
    fs.writeFileSync(
      path.join(tmp, "src", "orders", "service.ts"),
      [
        'import { secret } from "../billing/internal/ledger.ts";',
        "export type OpaqueBag = unknown;",
        "export function bad(x: Object, bag: Record<string, any>, fn: Function) {",
        "  return Reflect.apply(fn, x, [bag, secret]);",
        "}",
      ].join("\n") + "\n",
    );
    fs.writeFileSync(
      path.join(tmp, "src", "bag.go"),
      "package bag\nfunc Parse(m map[string]any) int { return len(m) }\n",
    );
    fs.writeFileSync(
      path.join(tmp, "tests", "bad.test.ts"),
      [
        'import { bad } from "../src/orders/service.ts";',
        "const sharedSignal = AbortSignal.timeout(500);",
        "server.listen();",
        "test('flaky', async () => {",
        "  const mod = await import('../src/orders/service.ts');",
        "  while (Date.now() < 9999999999) { break; }",
        "  expect(mod.bad({}, {}, () => 1)).toBe(1);",
        "  void sharedSignal;",
        "});",
      ].join("\n") + "\n",
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("no-cross-feature-internal-import"));
    assert.ok(rules.has("no-reflect-dynamic-invoke"));
    assert.ok(rules.has("no-unknown-type-alias"));
    assert.ok(rules.has("no-unsafe-dictionary-type"));
    assert.ok(rules.has("no-object-type-escape"));
    assert.ok(rules.has("no-unsignaled-poll"));
    assert.ok(rules.has("no-shared-abort-signal"));
    assert.ok(rules.has("no-cold-import-in-test"));
    assert.ok(rules.has("strict-msw"));

    assert.equal(veristackLintPlugin.meta.name, "veristack");
    assert.ok(veristackLintPlugin.rules["no-comments"]);
    assert.ok(veristackLintPlugin.rules["no-implicit-state-machine"]);
    assert.ok(veristackLintPlugin.rules["no-reflect-dynamic-invoke"]);
    assert.ok(veristackLintPlugin.rules["no-unknown-type-alias"]);
    assert.ok(veristackLintPlugin.rules["no-unsafe-dictionary-type"]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
